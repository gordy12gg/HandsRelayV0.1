#!/usr/bin/env python3
"""Read-only /files browsing tests: confined root, secret gate.

Run: python3 hands/linux/test_files_browse.py (plain-assert runner;
needs flask importable, same as test_hands_linux_wire.py).
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hands_linux  # noqa: E402

SECRET = "test-secret-files"


class StubGuardian:
    def state(self):
        return {"ok": True, "stopped": True,
                "reason": "test", "since": 0.0}

    def activity(self):
        return {"ok": True, "idle_seconds": 999.0}

    def act(self, kind, steps):
        return {"ok": True}

    def stop(self, source):
        return {"ok": True, "stopped": True}


class StubCapture:
    def monitor_rects(self):
        return [{"x": 0, "y": 0, "w": 100, "h": 100, "primary": True}]


H = {"X-Secret": SECRET}


def make_client(root):
    app = hands_linux.create_app(StubGuardian(), StubCapture(),
                                 **{"secret": SECRET, "files_root": root})
    return app.test_client()


def test_browse_confined_root():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "Downloads")
        os.makedirs(os.path.join(root, "proj"))
        with open(os.path.join(root, "notes.txt"), "w") as f:
            f.write("hello hands")
        with open(os.path.join(root, "proj", "a.py"), "w") as f:
            f.write("print(1)\n")
        with open(os.path.join(tmp, "outside.txt"), "w") as f:
            f.write("not yours")

        c = make_client(root)

        # Secret gate applies.
        assert c.get("/files").status_code == 401

        r = c.get("/files", headers=H)
        assert r.status_code == 200, r.status_code
        body = r.get_json()
        names = [e["name"] for e in body["entries"]]
        assert names == ["proj", "notes.txt"], names  # dirs first
        assert body["entries"][0]["dir"] is True

        r = c.get("/files", query_string={"path": "proj"}, headers=H)
        assert [e["name"] for e in r.get_json()["entries"]] == ["a.py"]

        r = c.get("/files/download",
                  query_string={"path": "notes.txt"}, headers=H)
        assert r.status_code == 200
        assert r.data == b"hello hands"

        # Escapes are refused: .., nested .., and absolute paths.
        for bad in ("../outside.txt", "proj/../../outside.txt",
                    "/etc/passwd"):
            r = c.get("/files/download",
                      query_string={"path": bad}, headers=H)
            assert r.status_code == 403, (bad, r.status_code)
            r = c.get("/files", query_string={"path": bad}, headers=H)
            assert r.status_code == 403, (bad, r.status_code)

        # Missing file is a clean 404.
        r = c.get("/files/download",
                  query_string={"path": "nope.txt"}, headers=H)
        assert r.status_code == 404
    print("PASS browse confined root")


if __name__ == "__main__":
    test_browse_confined_root()
    print("all files-browse tests passed")
