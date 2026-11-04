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


def make_guardian(tmp):
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as f:
        json.dump({
            "session_uid": SESSION_UID,
            "actuator": "fake",
            "state_dir": tmp,
            "guardian_socket": os.path.join(tmp, "guardian.sock"),
            "ydotoold_socket": os.path.join(tmp, "ydotoold.sock"),
            "ydotoold_autostart": False,
        }, f)
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


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"{len(fns)} guardian safety tests passed")
