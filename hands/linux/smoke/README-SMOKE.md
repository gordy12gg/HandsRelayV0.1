# P1 on-box smoke test — Gordon-PC

One command: `bash smoke.sh` (from this folder). It logs everything to
`smoke-log.txt` — paste that file back to Sprx when it's done.

What it proves, in order:

1. **Stage 1 — the emergency stop is real.** A guardian runs as root
   with a *fake* actuator (nothing can be injected). It must start
   STOPPED, refuse an actuation attempt, refuse a session-side resume,
   and resume only through the pkexec helper — which should show you a
   **fresh password prompt** (the polkit action retains no auth).
2. **Stage 2 — capture.** Two screenshot probes: a plain python process,
   and one launched under the shipped `.desktop` identity. KWin's
   ScreenShot2 authorization keys off app identity; this tells us which
   launch path the grant honors.
3. **Stage 3 — the full loop** (needs `sudo pacman -S ydotool` first).
   Guardian with the real ydotool actuator, resume via pkexec, the
   session app up, a screenshot through the app, then a click and the
   text `handsrelay p1 ok` typed into a text editor **while you watch**.
   The script asks you to confirm the text landed.

Safety notes: the guardian always comes up stopped; the script latches
the stop again at the end and kills its own guardian. All state lives in
this folder's `run/`. The only system-level changes: the polkit action
file, the resume helper under `/usr/lib/handsrelay/`, and two `.desktop`
files in your `~/.local/share/applications/`.
