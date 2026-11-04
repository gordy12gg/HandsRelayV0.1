#!/usr/bin/env python3
"""P2 route tests for the session app (hands_linux.create_app).

Run:  PYTHONPATH=/tmp/p1test:. python3 test_p2_routes.py
or:   python3 -m pytest hands/linux/test_p2_routes.py

Covers the P2 surface with fake backends (no D-Bus, no compositor):
window list shape + /proc process resolution, focus by KWin UUID (and
the upstream title fallback), monitors shape, clipboard get/set with
the read-logging assertion, the /type paste path through the real
clipboard seam, the file-drop state machine, /process from real /proc,
keep-awake engagement, and 423 gating of every new gated route while
the guardian is stopped. The pure pieces of windows_kwin (payload
mapping, script building) and keepawake (manager, systemd fallback)
are unit-tested here too.
"""

import base64
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PIL import Image  # noqa: E402

import hands_linux  # noqa: E402
import keepawake as keepawake_mod  # noqa: E402
import windows_kwin  # noqa: E402
from clipboard_wl import WlClipboard  # noqa: E402

SECRET = "test-secret-p2"
H = {"X-Secret": SECRET}

WIN1_ID = "{11111111-2222-3333-4444-555555555555}"
WIN2_ID = "{66666666-7777-4888-8999-000000000000}"


class StubGuardian:
    def __init__(self):
        self.stopped = False
        self.idle = 9999.0
        self.acts = []

    def state(self):
        return {"ok": True, "stopped": self.stopped,
                "reason": "test" if self.stopped else None, "since": 0.0}

    def activity(self):
        return {"ok": True, "idle_seconds": self.idle}

    def act(self, kind, steps):
        if self.stopped:
            return {"ok": False, "error_code": "emergency_stop"}
        self.acts.append((kind, steps))
        return {"ok": True}

    def stop(self, source):
        self.stopped = True
        return {"ok": True, "stopped": True}


class StubCapture:
    def monitor_rects(self):
        return [
            {"name": "DP-3", "x": 0, "y": 0, "w": 2560, "h": 1440},
            {"name": "HDMI-A-1", "x": 2560, "y": 0, "w": 1920, "h": 1080},
        ]

    def grab(self, rect=None, monitor_name=None):
        return Image.new("RGB", (16, 9), (0, 255, 0))


class FakeWindows:
    def __init__(self):
        self.activated = []
        self.activate_result = True
        self.windows = [
            {"id": WIN1_ID, "title": "Kate — notes.txt", "pid": os.getpid(),
             "bounds": {"x": 100, "y": 100, "w": 800, "h": 600},
             "visible": True, "focused": True},
            {"id": WIN2_ID, "title": "Terminal", "pid": None,
             "bounds": {"x": 2600, "y": 100, "w": 800, "h": 600},
             "visible": False, "focused": False},
        ]

    def list_windows(self):
        return list(self.windows)

    def activate(self, window_id):
        self.activated.append(window_id)
        return self.activate_result


class FakeClipboard:
    def __init__(self, text=""):
        self.text = text
        self.fail_set = False
        self.fail_get = False

    def get_text(self):
        if self.fail_get:
            raise OSError("wl-paste exploded")
        return self.text

    def set_text(self, text):
        if self.fail_set:
            raise OSError("wl-copy exploded")
        self.text = text


class FakeInhibitor:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def inhibit(self):
        self.calls.append("inhibit")
        if self.fail:
            raise RuntimeError("backend down")

    def uninhibit(self):
        self.calls.append("uninhibit")


def make_client(guardian=None, **kwargs):
    g = guardian if guardian is not None else StubGuardian()
    kwargs.setdefault("secret", SECRET)
    app = hands_linux.create_app(g, StubCapture(), **kwargs)
    app.testing = True
    return app.test_client(), g


# ---- windows ---------------------------------------------------------------


def test_windows_shape():
    fw = FakeWindows()
    c, _g = make_client(windows_backend=fw)
    r = c.get("/windows", headers=H)
    assert r.status_code == 200, r.get_data(as_text=True)
    wins = r.get_json()["windows"]
    assert len(wins) == 2
    w1, w2 = wins
    assert w1["id"] == WIN1_ID and w1["title"] == "Kate — notes.txt"
    assert w1["pid"] == os.getpid()
    with open("/proc/self/comm") as fh:
        assert w1["process"] == fh.read().strip()  # resolved via /proc
    assert w1["bounds"] == {"x": 100, "y": 100, "w": 800, "h": 600}
    assert w1["monitor"] == 0 and w1["visible"] is True
    assert w1["focused"] is True
    assert w2["monitor"] == 1 and w2["process"] is None
    assert w2["visible"] is False and w2["focused"] is False


def test_windows_unsupported_without_backend():
    c, _g = make_client()
    body = c.get("/windows", headers=H).get_json()
    assert body == {"ok": True, "windows": [], "supported": False}
    assert c.get("/window_titles", headers=H).get_json() == {
        "ok": True, "titles": []}


def test_windows_backend_failure_502():
    class ExplodingWindows:
        def list_windows(self):
            raise RuntimeError("dbus is gone")

        def activate(self, window_id):
            raise RuntimeError("dbus is gone")

    c, _g = make_client(windows_backend=ExplodingWindows())
    r = c.get("/windows", headers=H)
    assert r.status_code == 502
    assert "window list failed" in r.get_json()["error"]
    r = c.post("/focus", headers=H, json={"id": WIN1_ID})
    assert r.status_code == 502


def test_window_titles():
    c, _g = make_client(windows_backend=FakeWindows())
    body = c.get("/window_titles", headers=H).get_json()
    assert body == {"ok": True, "titles": ["Kate — notes.txt", "Terminal"]}


def test_focus_by_uuid():
    fw = FakeWindows()
    c, _g = make_client(windows_backend=fw)
    r = c.post("/focus", headers=H, json={"id": WIN2_ID})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert fw.activated == [WIN2_ID]
    assert r.get_json()["window"]["id"] == WIN2_ID


def test_focus_unknown_uuid_404():
    c, _g = make_client(windows_backend=FakeWindows())
    r = c.post("/focus", headers=H, json={"id": "{nope}"})
    assert r.status_code == 404
    assert "no window matching" in r.get_json()["error"]


def test_focus_activation_refused_409():
    fw = FakeWindows()
    fw.activate_result = False
    c, _g = make_client(windows_backend=fw)
    r = c.post("/focus", headers=H, json={"id": WIN1_ID})
    assert r.status_code == 409
    assert r.get_json()["window"]["id"] == WIN1_ID


def test_focus_title_fallback_and_validation():
    fw = FakeWindows()
    c, _g = make_client(windows_backend=fw)
    r = c.post("/focus", headers=H, json={"title": "terminal"})
    assert r.status_code == 200
    assert fw.activated == [WIN2_ID]
    r = c.post("/focus", headers=H, json={})
    assert r.status_code == 400


# ---- monitors ----------------------------------------------------------------


def test_monitors_shape():
    c, _g = make_client()
    r = c.get("/monitors", headers=H)
    body = r.get_json()
    assert body["ok"] is True and body["count"] == 2
    m1, m2 = body["monitors"]
    assert m1 == {"x": 0, "y": 0, "w": 2560, "h": 1440,
                  "primary": True, "name": "DP-3"}
    assert m2["primary"] is False and m2["x"] == 2560


# ---- clipboard ---------------------------------------------------------------


def test_clipboard_get_set_and_read_logging():
    clip = FakeClipboard()
    c, _g = make_client(clipboard_backend=clip)
    logs = []
    orig_log = hands_linux._log
    hands_linux._log = logs.append
    try:
        r = c.post("/clipboard/set", headers=H, json={"text": "hello clip"})
        assert r.status_code == 200 and clip.text == "hello clip"
        r = c.get("/clipboard/get", headers=H)
        assert r.status_code == 200
        assert r.get_json() == {"ok": True, "text": "hello clip"}
    finally:
        hands_linux._log = orig_log
    assert any("clipboard read via relay" in line for line in logs), logs
    r = c.post("/clipboard/set", headers=H, json={"text": 5})
    assert r.status_code == 400


def test_clipboard_backend_failure_502():
    clip = FakeClipboard()
    clip.fail_get = True
    c, _g = make_client(clipboard_backend=clip)
    r = c.get("/clipboard/get", headers=H)
    assert r.status_code == 502
    assert "clipboard read failed" in r.get_json()["error"]


def test_clipboard_unavailable_501():
    c, _g = make_client()  # no clipboard backend injected
    assert c.get("/clipboard/get", headers=H).status_code == 501
    r = c.post("/clipboard/set", headers=H, json={"text": "x"})
    assert r.status_code == 501


def test_wl_clipboard_backend_with_fake_run():
    calls = []

    class Proc:
        def __init__(self, rc, out=b"", err=b""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    state = {"get": Proc(0, "pasted text".encode())}

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == "wl-paste":
            return state["get"]
        return Proc(0)

    backend = WlClipboard(run=fake_run)
    assert backend.get_text() == "pasted text"
    state["get"] = Proc(1)  # no selection
    assert backend.get_text() == ""
    backend.set_text("new text")
    argv, kwargs = calls[-1]
    assert argv == ["wl-copy"] and kwargs["input"] == b"new text"

    def failing_run(argv, **kwargs):
        return Proc(2, err=b"boom")

    try:
        WlClipboard(run=failing_run).set_text("x")
        raise AssertionError("set_text should have raised")
    except OSError as exc:
        assert "wl-copy failed" in str(exc)


def test_monitor_rects_strips_ansi():
    """On-box 2026-11-04: kscreen-doctor colourises its output even
    when piped (SGR sequences around labels), which silently parsed
    to zero monitors. monitor_rects must strip ANSI codes first."""
    import capture as capture_mod

    colorized = (
        "\x1b[01;32mOutput: \x1b[0;0m1 DP-3 039392cf-b232-48ff-b3cd-a6e22420ace0\n"
        "\t\x1b[01;32menabled\x1b[0;0m\n"
        "\t\x1b[01;32mconnected\x1b[0;0m\n"
        "\t\x1b[01;34mModes: \x1b[0;0m 1:2560x1440@59.94*\n"
        "\tGeometry: 0,0 2560x1440\n"
        "\tScale: 1\n"
    )

    class Proc:
        returncode = 0
        stdout = colorized
        stderr = ""

    real_run = capture_mod.subprocess.run
    capture_mod.subprocess.run = lambda *a, **k: Proc()
    try:
        rects = capture_mod.monitor_rects()
    finally:
        capture_mod.subprocess.run = real_run
    assert rects == [{"name": "DP-3", "x": 0, "y": 0, "w": 2560, "h": 1440}], rects


def test_clipboard_set_timeout_readback():
    """On-box 2026-11-04: wl-copy's parent can linger past the timeout
    while the forked holder has already taken the selection. set_text
    must verify by read-back instead of reporting a false failure —
    and must still raise when the text did not land."""
    import subprocess as sp

    class Proc:
        def __init__(self, rc, out=b"", err=b""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def hanging_run(argv, **kwargs):
        if argv[0] == "wl-paste":
            return Proc(0, "landed".encode())
        raise sp.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 2))

    WlClipboard(run=hanging_run).set_text("landed")  # must not raise

    def hanging_run_mismatch(argv, **kwargs):
        if argv[0] == "wl-paste":
            return Proc(0, "something else".encode())
        raise sp.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 2))

    try:
        WlClipboard(run=hanging_run_mismatch).set_text("landed")
        raise AssertionError("set_text should have raised")
    except OSError as exc:
        assert "did not take" in str(exc)


# ---- /type paste path ----------------------------------------------------------


def test_type_paste_path_restores_clipboard():
    clip = FakeClipboard(text="previous contents")
    c, g = make_client(clipboard_backend=clip)
    r = c.post("/type", headers=H, json={"text": "hello", "method": "paste"})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["method_used"] == "paste"
    assert body["delays_planned"] == 0 and body["planned_seconds"] == 0
    # Ctrl+V went through the guardian as one keys act — the clipboard
    # itself injected nothing.
    assert len(g.acts) == 1
    kind, steps = g.acts[0]
    assert kind == "keys"
    assert steps == [
        {"t": "keydown", "key": "ctrl"},
        {"t": "keydown", "key": "v"},
        {"t": "keyup", "key": "v"},
        {"t": "keyup", "key": "ctrl"},
    ]
    # The owner's clipboard was saved and restored around the paste.
    assert clip.text == "previous contents"


def test_type_auto_pastes_long_text_only():
    clip = FakeClipboard()
    c, g = make_client(clipboard_backend=clip)
    r = c.post("/type", headers=H, json={"text": "x" * 121})
    assert r.get_json()["method_used"] == "paste"
    g.acts.clear()
    r = c.post("/type", headers=H, json={"text": "short"})
    assert r.get_json()["method_used"] == "keys"
    assert any(s.get("t") == "type" for _k, steps in g.acts for s in steps)


def test_type_paste_failure_falls_back_to_keys():
    clip = FakeClipboard()
    clip.fail_set = True
    c, g = make_client(clipboard_backend=clip)
    r = c.post("/type", headers=H, json={"text": "hi", "method": "paste"})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["method_used"] == "keys"
    assert "paste requested but unavailable" in body["note"]
    assert any(s.get("t") == "type" for _k, steps in g.acts for s in steps)


# ---- file-drop -------------------------------------------------------------------


def test_filedrop_happy_path_and_abort():
    payload = b"hello filedrop world"
    digest = hashlib.sha256(payload).hexdigest()
    with tempfile.TemporaryDirectory() as tmp:
        c, _g = make_client(filedrop_dirs=[tmp])
        r = c.post("/filedrop/begin", headers=H, json={
            "folder": tmp, "filename": "drop.txt",
            "size": len(payload), "sha256": digest})
        assert r.status_code == 200, r.get_data(as_text=True)
        body = r.get_json()
        assert body["chunk_max"] == 524288
        uid = body["upload_id"]

        r = c.post("/filedrop/chunk", headers=H, json={
            "upload_id": uid, "offset": 0,
            "data_b64": base64.b64encode(payload[:8]).decode()})
        assert r.get_json() == {"ok": True, "received": 8, "offset": 8}
        # Wrong offset is a 409 with the expected offset echoed.
        r = c.post("/filedrop/chunk", headers=H, json={
            "upload_id": uid, "offset": 0,
            "data_b64": base64.b64encode(payload[8:]).decode()})
        assert r.status_code == 409
        assert r.get_json()["expected_offset"] == 8
        r = c.post("/filedrop/chunk", headers=H, json={
            "upload_id": uid, "offset": 8,
            "data_b64": base64.b64encode(payload[8:]).decode()})
        assert r.get_json()["received"] == len(payload)

        r = c.post("/filedrop/commit", headers=H, json={"upload_id": uid})
        assert r.status_code == 200, r.get_data(as_text=True)
        body = r.get_json()
        assert body["path"] == os.path.join(tmp, "drop.txt")
        assert body["size"] == len(payload) and body["sha256"] == digest
        with open(body["path"], "rb") as fh:
            assert fh.read() == payload

        # Abort: begin a second upload, abort it, commit must 404.
        r = c.post("/filedrop/begin", headers=H, json={
            "folder": tmp, "filename": "gone.txt",
            "size": len(payload), "sha256": digest})
        uid2 = r.get_json()["upload_id"]
        r = c.post("/filedrop/abort", headers=H, json={"upload_id": uid2})
        assert r.status_code == 200 and r.get_json() == {"ok": True}
        r = c.post("/filedrop/commit", headers=H, json={"upload_id": uid2})
        assert r.status_code == 404
        assert not os.path.exists(os.path.join(tmp, "gone.txt"))


def test_filedrop_validation_and_unconfigured():
    payload = b"abc"
    digest = hashlib.sha256(payload).hexdigest()
    with tempfile.TemporaryDirectory() as tmp:
        c, _g = make_client(filedrop_dirs=[tmp])
        r = c.post("/filedrop/begin", headers=H, json={
            "folder": "/etc", "filename": "x.txt",
            "size": 3, "sha256": digest})
        assert r.status_code == 403  # not in the allowlist
        r = c.post("/filedrop/begin", headers=H, json={
            "folder": tmp, "filename": "../evil.txt",
            "size": 3, "sha256": digest})
        assert r.status_code == 400  # not a bare name
        r = c.post("/filedrop/begin", headers=H, json={
            "folder": tmp, "filename": "x.txt",
            "size": 3, "sha256": "zz"})
        assert r.status_code == 400  # bad sha
    c2, _g2 = make_client()  # nothing configured anywhere
    r = c2.post("/filedrop/begin", headers=H, json={
        "folder": "/tmp", "filename": "x.txt", "size": 3, "sha256": digest})
    assert r.status_code == 501


# ---- /process ---------------------------------------------------------------------


def test_process_self_and_bogus():
    c, _g = make_client()
    r = c.get(f"/process/{os.getpid()}", headers=H)
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True and body["pid"] == os.getpid()
    assert body["running"] is True
    with open("/proc/self/comm") as fh:
        assert body["name"] == fh.read().strip()
    assert isinstance(body["cmdline"], list) and body["cmdline"]
    assert ":" in body["instance"]  # boot_id:starttime
    assert body["state"] in ("R", "S", "D", "T", "t", "W", "X", "Z")

    r = c.get("/process/16777215", headers=H)  # beyond pid_max: never exists
    body = r.get_json()
    assert body["running"] is False and body["instance"] is None
    assert body["name"] is None and body["cmdline"] == []


# ---- keep-awake ---------------------------------------------------------------------


def test_keep_awake_engages_and_reports_state():
    inhibitor = FakeInhibitor()
    ka = keepawake_mod.KeepAwake(inhibitor)
    c, _g = make_client(keep_awake=ka, keep_awake_enabled=True)
    assert inhibitor.calls == ["inhibit"]
    body = c.get("/state", headers=H).get_json()
    assert body["keep_awake"] is True
    ka.stop()
    assert inhibitor.calls == ["inhibit", "uninhibit"]


def test_keep_awake_fallback_chain():
    primary = FakeInhibitor(fail=True)
    fallback = FakeInhibitor()
    ka = keepawake_mod.KeepAwake(primary, fallback=fallback)
    assert ka.start() is True and ka.active is True
    assert fallback.calls == ["inhibit"]
    assert ka.start() is True  # idempotent
    assert fallback.calls == ["inhibit"]
    ka.stop()
    assert fallback.calls == ["inhibit", "uninhibit"]


def test_systemd_inhibit_backend():
    spawned = []

    class FakeProc:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

    def fake_popen(argv, **kwargs):
        proc = FakeProc()
        spawned.append((argv, proc))
        return proc

    backend = keepawake_mod.SystemdInhibit(popen=fake_popen)
    backend.inhibit()
    argv, proc = spawned[0]
    assert argv[0] == "systemd-inhibit" and "--what=idle:sleep" in argv
    backend.uninhibit()
    assert proc.terminated is True


# ---- windows_kwin pure pieces -------------------------------------------------------


def test_kwin_payload_mapping():
    payload = json.dumps([
        {"id": "{a}", "title": "One", "pid": 4242, "x": 0, "y": 0,
         "w": 100, "h": 100, "minimized": False,
         "on_current_desktop": True, "active": True},
        {"id": "{b}", "title": "Two", "pid": 0, "x": 0, "y": 0,
         "w": 50, "h": 50, "minimized": True,
         "on_current_desktop": True, "active": False},
        {"id": "{c}", "title": "Three", "pid": 7, "x": 0, "y": 0,
         "w": 50, "h": 50, "minimized": False,
         "on_current_desktop": False, "active": False},
    ])
    wins = windows_kwin.windows_from_payload(payload)
    assert wins[0]["visible"] is True and wins[0]["focused"] is True
    assert wins[0]["pid"] == 4242
    assert wins[1]["visible"] is False and wins[1]["pid"] is None
    assert wins[2]["visible"] is False  # other desktop


def test_kwin_script_building():
    script = windows_kwin.build_script(
        "var wins = [];", "org.gordy.handsrelay.bridgeabc123",
        "deadbeefcafe", "JSON.stringify(wins)")
    assert '"org.gordy.handsrelay.bridgeabc123"' in script
    assert '"deadbeefcafe"' in script
    assert '"Deliver"' in script and "callDBus(" in script
    assert windows_kwin.BRIDGE_PATH in script


# ---- 423 gating ------------------------------------------------------------------------


def test_new_routes_423_while_stopped():
    g = StubGuardian()
    g.stopped = True
    c, _g = make_client(
        guardian=g,
        windows_backend=FakeWindows(),
        clipboard_backend=FakeClipboard(),
        filedrop_dirs=["/tmp"],
    )
    checks = [
        c.get("/windows", headers=H),
        c.get("/window_titles", headers=H),
        c.get("/monitors", headers=H),
        c.get("/clipboard/get", headers=H),
        c.get(f"/process/{os.getpid()}", headers=H),
        c.post("/focus", headers=H, json={"id": WIN1_ID}),
        c.post("/clipboard/set", headers=H, json={"text": "x"}),
        c.post("/filedrop/begin", headers=H, json={}),
        c.post("/filedrop/chunk", headers=H, json={}),
        c.post("/filedrop/commit", headers=H, json={}),
        c.post("/filedrop/abort", headers=H, json={}),
    ]
    for r in checks:
        assert r.status_code == 423, r.status_code
        assert r.get_json()["error_code"] == "emergency_stop"
    # The exemptions still answer while stopped.
    assert c.get("/state", headers=H).status_code == 200


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"{len(fns)} P2 route tests passed")
