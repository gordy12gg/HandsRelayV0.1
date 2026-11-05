"""P1 safety-semantics tests: the guardian latch is the product.

Run:  python3 -m pytest hands/linux/test_p1_safety.py
or:   python3 hands/linux/test_p1_safety.py   (plain-assert runner)

These tests pin the emergency-stop contract from DESIGN-P1.md:
  * a fresh guardian starts STOPPED (fail-safe),
  * acts are refused while stopped, with error_code emergency_stop,
  * resume from a session UID is refused; only a root peer may resume,
  * stop runs the release sweep and reports exactly what was held,
  * an unpaired keydown is swept at act end,
  * an unauthorized peer UID is refused at the gate.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import guardian as guardian_mod  # noqa: E402

SESSION_UID = 1000
STRANGER_UID = 1001


def make_guardian(tmp, overrides=None):
    cfg_dict = {
        "session_uid": SESSION_UID,
        "actuator": "fake",
        "state_dir": tmp,
        "guardian_socket": os.path.join(tmp, "guardian.sock"),
        "ydotoold_socket": os.path.join(tmp, "ydotoold.sock"),
        "ydotoold_autostart": False,
        "owner_idle_min_seconds": 0,
    }
    if overrides:
        cfg_dict.update(overrides)
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg_dict, f)
    cfg = guardian_mod.load_config(cfg_path)
    return guardian_mod.Guardian(cfg)


def test_fresh_guardian_starts_stopped():
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        st = g.handle_request({"op": "state"}, SESSION_UID)
        assert st["stopped"] is True, st


def test_act_refused_while_stopped():
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        resp = g.handle_request(
            {"op": "act", "kind": "mouse",
             "steps": [{"t": "move", "x": 10, "y": 10}]}, SESSION_UID)
        assert resp["ok"] is False and resp["error_code"] == "emergency_stop", resp
        assert g.actuator.calls == [], "no step may execute while stopped"


def test_session_uid_cannot_resume_root_can():
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        resp = g.handle_request({"op": "resume"}, SESSION_UID)
        assert resp["ok"] is False, resp
        assert g.handle_request({"op": "state"}, SESSION_UID)["stopped"] is True
        resp = g.handle_request({"op": "resume"}, 0)
        assert resp["ok"] is True, resp
        assert g.handle_request({"op": "state"}, SESSION_UID)["stopped"] is False


def test_act_executes_after_resume_and_sweeps_unpaired_keydown():
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        g.handle_request({"op": "resume"}, 0)
        resp = g.handle_request(
            {"op": "act", "kind": "keys",
             "steps": [{"t": "keydown", "key": "ctrl"},
                       {"t": "type", "text": "x"}]}, SESSION_UID)
        assert resp["ok"] is True, resp
        # ctrl was left down by the plan; the act-end sweep must release it.
        assert g.actuator._held_keys == set(), g.actuator._held_keys


def test_stop_sweeps_held_keys():
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        g.handle_request({"op": "resume"}, 0)
        # Simulate a key physically down at stop time.
        g.actuator.key(29, True)  # KEY_LEFTCTRL
        assert g.actuator._held_keys
        resp = g.handle_request({"op": "stop", "source": "panic"}, SESSION_UID)
        assert resp["ok"] is True and resp["stopped"] is True, resp
        assert g.actuator._held_keys == set()


def test_stranger_peer_refused():
    # The peer gate lives in the socket layer (_serve_conn), not in
    # handle_request, so this test drives a real socket. The guardian
    # builder verified the same path live with setpriv; here we repeat it
    # when running as root with setpriv available, else skip.
    import shutil
    import socket
    import subprocess
    import threading
    if os.getuid() != 0 or not shutil.which("setpriv"):
        print("SKIP test_stranger_peer_refused (needs root + setpriv)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o755)  # let the nobody-uid probe reach the socket
        g = make_guardian(tmp)
        t = threading.Thread(target=g.serve, daemon=True)
        t.start()
        sock_path = g.config["guardian_socket"]
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            import time as _t
            _t.sleep(0.1)
        # serve() chmods the socket 0660 — the filesystem fence refuses a
        # stranger before SO_PEERCRED ever runs (correct in production).
        # Loosen it here on purpose to prove the second fence (peer creds)
        # also refuses on its own.
        os.chmod(sock_path, 0o666)
        code = (
            "import socket,sys;"
            "s=socket.socket(socket.AF_UNIX);"
            f"s.connect({sock_path!r});"
            "s.sendall(b'{\\\"op\\\":\\\"state\\\"}\\n');"
            "print(s.recv(4096).decode())"
        )
        out = subprocess.run(
            ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
             "python3", "-c", code],
            capture_output=True, text=True, timeout=15)
        assert "unauthorized peer" in out.stdout, out
        g.shutdown.set()


def test_restart_comes_back_stopped():
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        g.handle_request({"op": "resume"}, 0)
        assert g.handle_request({"op": "state"}, SESSION_UID)["stopped"] is False
        g2 = make_guardian(tmp)  # same state dir: a "restart"
        assert g2.handle_request({"op": "state"}, SESSION_UID)["stopped"] is True


def test_queued_act_discarded_across_stop_resume():
    """STOP forgets pending work: an act queued behind a running act
    when the stop lands must NOT execute after a resume (external
    review, 2026-11-03 — cancellation generation)."""
    import threading
    import time as _time
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        g.handle_request({"op": "resume"}, 0)
        results = {}

        def run(name, steps, gen=None):
            results[name] = g.execute_act(steps, generation=gen)

        t1 = threading.Thread(
            target=run, args=("first", [{"t": "sleep", "s": 1.5}]))
        t1.start()
        _time.sleep(0.25)  # first act holds the act lock
        gen = g.latch.generation()  # second act "arrives" now
        t2 = threading.Thread(
            target=run,
            args=("second", [{"t": "keydown", "key": "a"}], gen))
        t2.start()
        _time.sleep(0.25)  # second act is queued on the lock
        g.trip_stop("test")
        g.resume()
        t1.join(timeout=5)
        t2.join(timeout=5)
        assert results["second"].get("error_code") == "act_discarded", \
            results
        key_calls = [c for c in g.actuator.calls if c[0] == "key"]
        assert key_calls == [], key_calls


def test_malformed_plan_never_executes():
    """Whole-plan validation: a bad step anywhere means NOTHING runs,
    so a held key can never be stranded by a malformed tail."""
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        g.handle_request({"op": "resume"}, 0)
        for steps in (
            [{"t": "keydown", "key": "ctrl"}, "junk"],
            [{"t": "keydown", "key": "ctrl"}, {"t": "nope"}],
            [{"t": "keydown", "key": "nosuchkey"}],
            [{"t": "move", "x": "left", "y": 10}],
        ):
            r = g.execute_act(steps)
            assert r["ok"] is False, (steps, r)
            assert g.actuator.calls == [], (steps, g.actuator.calls)
            assert g.actuator.held() == ([], [])


def test_unexpected_actuator_error_sweeps_held():
    """The finally-sweep: even an exception validation cannot foresee
    leaves no input held."""
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        g.handle_request({"op": "resume"}, 0)

        def boom(text):
            raise RuntimeError("injected failure")

        g.actuator.type_text = boom
        r = g.execute_act([{"t": "keydown", "key": "ctrl"},
                           {"t": "type", "text": "x"}])
        assert r["ok"] is False, r
        assert g.actuator.held() == ([], []), g.actuator.held()


def test_owner_active_refused_in_guardian():
    """Owner-activity is enforced by the guardian itself, not only by
    the session app (external review, 2026-11-03)."""
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp, {"owner_idle_min_seconds": 10 ** 9})
        g.handle_request({"op": "resume"}, 0)
        r = g.execute_act([{"t": "keydown", "key": "a"}])
        assert r.get("error_code") == "owner_active", r
        assert g.actuator.calls == []


def test_window_liveness_watchdog():
    """A status window that reported and then went silent (crash)
    latches the stop; a window that never ran never triggers it."""
    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp, {"window_liveness_seconds": 5})
        g.handle_request({"op": "resume"}, 0)
        g.check_window_liveness()  # never pinged: no fire
        assert g.latch.is_stopped() is False
        g.note_window_ping()
        g._window_last_seen -= 60  # window went silent a minute ago
        g.check_window_liveness()
        assert g.latch.is_stopped() is True
        assert "window-watchdog" in (g.latch.snapshot()["reason"] or "")


def test_owner_activity_ignores_sensor_noise():
    """On-box 2026-11-04: a resting DualSense streams ~1,200 evdev
    events/sec (IMU + stick noise). Counting every event as owner
    activity pinned idle at ~0 and refused every act. Only deliberate
    input may count."""
    class Ev:
        def __init__(self, type, code, value):
            self.type, self.code, self.value = type, code, value

    with tempfile.TemporaryDirectory() as tmp:
        g = make_guardian(tmp)
        calls = []
        g.note_owner_activity = lambda: calls.append(1)
        mon = guardian_mod.EvdevMonitor(g)
        motion = "Sony DualSense Motion Sensors"
        pad = "Sony DualSense"
        # IMU stream on the motion node: never activity, any delta.
        for i in range(50):
            mon._on_event(Ev(3, 3, 1000 + i * 40), motion)
        # Stick jitter on the pad: baseline, then sub-dead-zone deltas.
        mon._on_event(Ev(3, 0, 128), pad)
        mon._on_event(Ev(3, 0, 130), pad)
        mon._on_event(Ev(3, 0, 127), pad)
        # Bookkeeping events: never activity.
        mon._on_event(Ev(0, 0, 0), pad)   # EV_SYN
        mon._on_event(Ev(4, 4, 0), pad)   # EV_MSC
        assert calls == [], calls
        # A deliberate stick throw (delta >= dead-zone) counts.
        mon._on_event(Ev(3, 0, 200), pad)
        assert len(calls) == 1, calls
        # A hat press (delta 1 on a hat axis) counts.
        mon._on_event(Ev(3, 0x10, 0), pad)
        mon._on_event(Ev(3, 0x10, 1), pad)
        assert len(calls) == 2, calls
        # Keys and relative motion always count.
        mon._on_event(Ev(1, 30, 1), "Razer Razer BlackWidow V3")
        mon._on_event(Ev(2, 0, 5), "Logitech G502")
        assert len(calls) == 4, calls


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"{len(fns)} guardian safety tests passed")
