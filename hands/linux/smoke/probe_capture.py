#!/usr/bin/env python3
"""Capture probe: grab one screenshot via capture.py and save it.

Usage: probe_capture.py <out.png>
Exit 0 + prints size on success; prints the error and exits 1 otherwise.
Launched two ways by smoke.sh (direct, and via a .desktop identity) to
learn which launch path KWin's ScreenShot2 authorization honors.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # hands/linux/


def main():
    out = sys.argv[1]
    try:
        import capture
        img = capture.grab()
        img.save(out)
        print(f"captured {img.size[0]}x{img.size[1]} -> {out}")
        return 0
    except Exception as e:
        print(f"capture failed: {type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
