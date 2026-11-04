#!/usr/bin/env python3
"""status_window.py — HandsRelay Linux hands status window (P1).

The stop surface, not the full upstream window (parity is P3). Shows
the guardian's emergency-stop latch state, a big STOP button, a Resume
button, and the owner's idle time, refreshed every 2 seconds.

Safety semantics (DESIGN-P1.md):
  - STOP asks the guardian to latch the stop (source "window"). While
    latched, the guardian refuses every act and the session app answers
    423 on act routes.
  - Resume does NOT talk the guardian out of the latch directly: it
    runs `pkexec /usr/lib/handsrelay/handsrelay-resume`, a root helper
    gated by the custom polkit action org.gordy.handsrelay.resume
    (auth_admin, no auth retention, active session only). Fresh console
    authentication is what proves the human is present; only the helper,
    running as root, may send the guardian a resume op.
  - Closing the window latches the stop first, then destroys the
    window (upstream semantics: the window going away must never leave
    the hands running unattended).
  - If the guardian is unreachable the window still opens and shows
    GUARDIAN DOWN; STOP is disabled (there is nothing to ask) and the
    refresh keeps retrying.

The guardian is reached over its unix socket with the same JSON-lines
IPC the session app uses (DESIGN-P1.md). This file carries its own
minimal stdlib client so the window opens even if the rest of the
package is broken — a stop surface must not depend on the thing it
stops.
"""

import json
import os
import socket
import subprocess
import threading
import time
import tkinter as tk

DEFAULT_SOCKET = "/run/handsrelay-guardian/guardian.sock"
RESUME_HELPER = "/usr/lib/handsrelay/handsrelay-resume"
REFRESH_MS = 2000


class GuardianClient:
    """Minimal JSON-lines client for the guardian IPC (stdlib only)."""

    def __init__(self, path=None, timeout=2.0):
        self.path = path or os.environ.get("HANDS_GUARDIAN_SOCKET", DEFAULT_SOCKET)
        self.timeout = timeout

    def _call(self, payload):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.path)
            sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))

    def state(self):
        return self._call({"op": "state"})

    def activity(self):
        return self._call({"op": "activity"})

    def stop(self, source="window"):
        return self._call({"op": "stop", "source": source})

    def ping(self):
        return self._call({"op": "ping"})


class StatusWindow:
    def __init__(self, root, client):
        self.root = root
        self.client = client
        root.title("HandsRelay — Linux hands")
        root.minsize(340, 260)

        self.state_label = tk.Label(
            root, text="…", font=("Sans", 20, "bold"), pady=10
        )
        self.state_label.pack(fill="x")

        self.detail_label = tk.Label(root, text="", font=("Sans", 10), pady=2)
        self.detail_label.pack(fill="x")

        self.idle_label = tk.Label(root, text="Owner idle: —", font=("Sans", 10), pady=2)
        self.idle_label.pack(fill="x")

        self.stop_button = tk.Button(
            root,
            text="STOP",
            font=("Sans", 18, "bold"),
            bg="#c0392b",
            fg="white",
            activebackground="#922b21",
            activeforeground="white",
            height=2,
            command=self.on_stop,
        )
        self.stop_button.pack(fill="x", padx=16, pady=10)

        self.resume_button = tk.Button(
            root,
            text="Resume (asks for your password)",
            font=("Sans", 11),
            command=self.on_resume,
        )
        self.resume_button.pack(fill="x", padx=16, pady=(0, 12))

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.refresh()

    # ---- actions ---------------------------------------------------

    def on_stop(self):
        try:
            self.client.stop(source="window")
        except Exception:
            pass  # the refresh right after reports the guardian as down
        self.refresh()

    def on_resume(self):
        # pkexec puts up the polkit password dialog; run it off the Tk
        # loop so the window keeps refreshing while it waits. The 2 s
        # refresh picks up the latch change on its own.
        def _run():
            try:
                subprocess.run(["pkexec", RESUME_HELPER], check=False)
            except Exception:
                pass

        threading.Thread(target=_run, daemon=True).start()

    def on_close(self):
        # Closing the window latches the stop — and the window only
        # goes away once the stop is CONFIRMED. Silently closing over
        # a failed stop request would leave actuation running with no
        # visible control surface (external review, 2026-11-03).
        for _ in range(3):
            try:
                reply = self.client.stop(source="window")
                if isinstance(reply, dict) and reply.get("ok"):
                    self.root.destroy()
                    return
            except Exception:
                pass
            time.sleep(0.5)
        self.state_label.config(text="CLOSE BLOCKED", fg="#c0392b")
        self.detail_label.config(
            text="Stop NOT confirmed by the guardian — this window "
                 "stays open. Check the guardian, then close again.")

    # ---- refresh -----------------------------------------------------

    def refresh(self):
        try:
            self.client.ping()
        except Exception:
            pass  # the state call below surfaces a dead guardian
        try:
            st = self.client.state()
            if not isinstance(st, dict) or not st.get("ok"):
                raise RuntimeError("bad guardian state")
        except Exception:
            self.state_label.config(text="GUARDIAN DOWN", fg="#7b241c")
            self.detail_label.config(
                text="Guardian unreachable — no act can run in this state."
            )
            self.idle_label.config(text="Owner idle: —")
            self.stop_button.config(state="disabled")
            self._schedule()
            return

        self.stop_button.config(state="normal")
        if st.get("stopped"):
            self.state_label.config(text="STOPPED", fg="#c0392b")
            reason = st.get("reason") or "no reason recorded"
            since = st.get("since")
            when = (
                time.strftime("%H:%M:%S", time.localtime(since))
                if isinstance(since, (int, float))
                else "unknown time"
            )
            self.detail_label.config(text=f"Since {when} — {reason}")
        else:
            self.state_label.config(text="RUNNING", fg="#1e8449")
            self.detail_label.config(text="Emergency stop is not latched.")

        try:
            act = self.client.activity()
            idle = act.get("idle_seconds") if isinstance(act, dict) else None
        except Exception:
            idle = None
        if isinstance(idle, (int, float)):
            self.idle_label.config(text=f"Owner idle: {idle:.0f} s")
        else:
            self.idle_label.config(text="Owner idle: —")
        self._schedule()

    def _schedule(self):
        self.root.after(REFRESH_MS, self.refresh)


def main():
    root = tk.Tk()
    StatusWindow(root, GuardianClient())
    root.mainloop()


if __name__ == "__main__":
    main()
