"""P1 wire tests for the session app (hands_linux.create_app).

Run with flask available:
  PYTHONPATH=/tmp/p1test:. python3 test_hands_linux_wire.py

Pins the HTTP contract the gateway will see: /health open, X-Secret gate
(401/429), 423 while the guardian is stopped, 409 while the owner is
active, /state shape, /screenshot PNG + headers, act plumbing to the
guardian.
"""

import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PIL import Image  # noqa: E402

import hands_linux  # noqa: E402

SECRET = "test-secret"


class StubGuardian:
    def __init__(self):
        self.stopped = True
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
        return [{"name": "DP-3", "x": 0, "y": 0, "w": 2560, "h": 1440}]

    def grab(self, rect=None, monitor_name=None):
        return Image.new("RGB", (16, 9), (255, 0, 0))


def make_client():
    g = StubGuardian()
    app = hands_linux.create_app(g, StubCapture(), **{"secret": SECRET})
    app.testing = True
    return app.test_client(), g


H = {"X-Secret": SECRET}


def test_health_open_without_secret():
    c, _g = make_client()
    assert c.get("/health").status_code == 200


def test_bad_secret_401():
    c, _g = make_client()
    assert c.get("/state", headers={"X-Secret": "nope"}).status_code == 401
    assert c.get("/state").status_code == 401


def test_state_shape_and_stopped_flag():
    c, _g = make_client()
    r = c.get("/state", headers=H)
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True and body["platform"] == "linux"
    assert body["emergency_stop"] is True


def test_act_423_while_stopped():
    c, _g = make_client()
    r = c.post("/click", headers=H, json={"x": 5, "y": 5})
    assert r.status_code == 423, r.status_code
    assert r.get_json()["error_code"] == "emergency_stop"


def test_screenshot_also_423_while_stopped():
    c, _g = make_client()
    r = c.get("/screenshot", headers=H)
    assert r.status_code == 423


def test_click_flows_to_guardian_when_running():
    c, g = make_client()
    g.stopped = False
    r = c.post("/click", headers=H, json={"x": 100, "y": 100})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert g.acts and g.acts[0][0] == "mouse"


def test_owner_active_yield_409():
    c, g = make_client()
    g.stopped = False
    g.idle = 0.5  # owner touched something half a second ago
    r = c.post("/click", headers=H, json={"x": 1, "y": 1})
    assert r.status_code == 409
    assert r.get_json()["error"] == "owner active"


def test_screenshot_png_and_headers_when_running():
    c, g = make_client()
    g.stopped = False
    r = c.get("/screenshot", headers=H)
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("image/png")
    assert r.headers["X-Screen-Width"] == "16"
    assert r.data[:8] == b"\x89PNG\r\n\x1a\n"


def test_type_paste_is_501_in_p1():
    c, g = make_client()
    g.stopped = False
    r = c.post("/type", headers=H, json={"text": "hi", "method": "paste"})
    assert r.status_code == 501


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"{len(fns)} session-app wire tests passed")
