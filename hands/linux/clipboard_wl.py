"""Session-side clipboard via wl-clipboard (P2).

The Linux counterpart of upstream's ``_PyperclipBackend`` seam:
``get_text()`` / ``set_text(text)`` over ``wl-paste`` / ``wl-copy``
subprocesses. Wayland compositors have no global clipboard store — the
selection is held by the source client — so ``wl-copy`` forks a holder
process and returns immediately; that is expected, not a leak.

The subprocess runner is injectable (``run=``) so tests drive the
backend headless with a fake. Semantics mirror upstream's ctypes
backend:

* ``get_text()`` returns ``""`` when there is no clipboard content
  (``wl-paste`` exits non-zero, "No selection") instead of raising;
  a missing ``wl-paste`` binary *does* raise, surfacing as the
  route's 502 — an absent tool must not masquerade as an empty
  clipboard.
* ``set_text()`` raises on any failure.

Reading the clipboard is sensitive; the *route* logs every read (the
backend itself stays quiet), exactly like upstream's /clipboard/get.
"""

from __future__ import annotations

import subprocess


class WlClipboard:
    """wl-clipboard backend. Duck-typed for the session app:

        get_text() -> str
        set_text(text) -> None (raises on failure)
    """

    def __init__(self, run=None):
        self._run = run or subprocess.run

    def get_text(self) -> str:
        proc = self._run(
            ["wl-paste", "--no-newline"],
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return ""  # no selection / no text offer: upstream's "" case
        out = proc.stdout or b""
        if isinstance(out, str):
            return out
        return out.decode("utf-8", errors="replace")

    def set_text(self, text: str) -> None:
        proc = self._run(
            ["wl-copy"],
            input=text.encode("utf-8"),
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            err = proc.stderr or b""
            if isinstance(err, bytes):
                err = err.decode("utf-8", errors="replace")
            raise OSError(f"wl-copy failed ({proc.returncode}): {err.strip()}")
