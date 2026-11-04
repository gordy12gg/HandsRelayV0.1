#!/usr/bin/env python3
"""Encoding + raw-capture tests (P1 smoke regressions).

- ydotool move must use the 1.x -x/-y flag form; positional args are
  ignored by ydotool 1.x and the pointer lands on (0, 0).
- capture._image_from_raw must rebuild an image from raw BGRA pipe
  bytes + a geometry-carrying results dict (ScreenShot2's pipe payload
  is not PNG on this KWin).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import actuator  # noqa: E402


def test_move_encoding():
    calls = []

    class FakeProc:
        returncode = 0
        stderr = ""

    def fake_run(argv, env=None, capture_output=None, text=None,
                 timeout=None):
        calls.append(argv)
        return FakeProc()

    orig = actuator.subprocess.run
    actuator.subprocess.run = fake_run
    try:
        act = actuator.YdotoolActuator("/tmp/yd.sock")
        act.begin_act()
        act.move(500, 300)
        moves = [c for c in calls if c[1] == "mousemove"]
        # First call is the corner slam; the rest are relative chunks
        # of at most 64 px that must sum to exactly (500, 300).
        assert moves[0] == ["ydotool", "mousemove", "-x", "-100000",
                            "-y", "-100000"], moves[0]
        sx = sy = 0
        for c in moves[1:]:
            assert "--absolute" not in c
            cx, cy = int(c[3]), int(c[5])
            assert abs(cx) <= 64 and abs(cy) <= 64, c
            sx += cx
            sy += cy
        assert (sx, sy) == (500, 300), (sx, sy)
        assert act.position() == (500, 300)
        # Anchored now: a follow-up move is deltas only, no second slam.
        calls.clear()
        act.move(560, 300)
        assert calls == [["ydotool", "mousemove", "-x", "60",
                          "-y", "0"]], calls
        act.scroll(0, 3)
        act.key(28, True)
    finally:
        actuator.subprocess.run = orig
    print("PASS move encoding: corner-slam + chunked relative deltas")


def test_raw_reconstruction():
    import capture
    from PIL import Image
    w, h = 4, 2
    # BGRA bytes for a solid red-ish pixel pattern
    px = bytes([10, 20, 30, 255]) * (w * h)
    img = capture._image_from_raw(px, {"width": w, "height": h,
                                       "format": 5, "stride": w * 4})
    assert img is not None and img.size == (w, h), img
    r, g, b = img.getpixel((0, 0))
    assert (r, g, b) == (30, 20, 10), (r, g, b)
    # format 16 = RGBA8888 (what KWin 6.8.2 actually sends): R,G,B,A
    px16 = bytes([30, 20, 10, 255]) * (w * h)
    img16 = capture._image_from_raw(px16, {"width": w, "height": h,
                                           "format": 16,
                                           "stride": w * 4})
    assert img16 is not None
    assert img16.getpixel((0, 0)) == (30, 20, 10), img16.getpixel((0, 0))
    assert capture._image_from_raw(px, {}) is None
    assert capture._image_from_raw(b"\x00" * 8,
                                   {"width": w, "height": h}) is None
    print("PASS raw reconstruction: BGRA pipe bytes -> image")


if __name__ == "__main__":
    test_move_encoding()
    test_raw_reconstruction()
    print("all encoding/raw tests passed")
