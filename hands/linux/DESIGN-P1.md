# HandsRelay Linux port — P1 design (contracts)

Implements SCOPE.md §3/§4 P1 in the fork, under `hands/linux/`. Upstream
Windows code stays untouched; `hands/motion.py` is reused unchanged.

## Components

1. **guardian.py** — root-owned systemd *system* service. Owns:
   - the emergency-stop **latch** (in memory + `/var/lib/handsrelay-guardian/latch.json`, root-owned; **always starts STOPPED** after any restart — fail-safe),
   - the **evdev panic listener** (reads `/dev/input/event*` as root; default combo Ctrl+Alt+Esc, configurable in root-owned `/etc/handsrelay-guardian/config.json`),
   - the **owner-activity monitor** (evdev events on *physical* devices only; devices whose name matches virtual patterns — ydotool/libei/EIS — are excluded, so injected input never counts as owner activity),
   - **all input injection** (via its actuator; see below). The session component holds no injection capability.
   - IPC: unix socket `/run/handsrelay-guardian/guardian.sock` (dir root-owned; socket 0660, group `handsrelay`). Peer credentials checked with SO_PEERCRED: requests accepted only from the configured session UID or root.

2. **Session hands app** (`hands_linux.py`, Gordy's UID) — Flask on
   127.0.0.1:5000, per-launch secret + `X-Secret` gate with lockout
   (mirrors upstream `_auth_decide`). P1 routes: `/health`, `/state`,
   `/screenshot`, `/move`, `/click`, `/drag`, `/scroll`, `/key`,
   `/hotkey`, `/break`, `/type`. It plans motion with `motion.py`
   (plan_move / plan_scroll / landing_point / attention_delay) and sends
   **act step lists** to the guardian for execution. Capture is local
   (ScreenShot2) — capture holds no injection capability.

3. **status_window.py** — minimal tkinter window (P1 scope: the stop
   surface, not full parity — parity is P3): big STOP button (→ guardian
   `stop`), Resume button (→ `pkexec /usr/lib/handsrelay/handsrelay-resume`,
   a root helper gated by the custom polkit action
   `org.gordy.handsrelay.resume`: `auth_admin`, **no `_keep`**,
   `allow_active` only), live state line (stopped/running, last owner
   activity). Closing the window also latches the stop (upstream
   semantics).

## Guardian IPC (JSON lines over the unix socket)

Requests:
- `{"op":"state"}` → `{"ok":true,"stopped":bool,"reason":str|null,"since":float}`
- `{"op":"activity"}` → `{"ok":true,"idle_seconds":float}` (physical devices only)
- `{"op":"act","kind":"mouse"|"keys","steps":[step,...]}` → latch checked
  first: stopped → `{"ok":false,"error_code":"emergency_stop"}`; else the
  guardian executes the steps serially (acts are mutex-serialized) →
  `{"ok":true}` or `{"ok":false,"error":str}`.
- `{"op":"stop","source":"window"|"panic"|"api"}` → latch set, key-up
  sweep executed (every tracked held key/button explicitly released),
  `{"ok":true,"stopped":true}`.
- `{"op":"resume"}` → **refused unless peer UID is 0** (the polkit helper
  runs as root after fresh auth): `{"ok":false,"error":"resume requires polkit helper"}` otherwise.

Steps (executed by the guardian's actuator):
- `{"t":"move","x":int,"y":int}`
- `{"t":"sleep","s":float}` (capped at 2.0 s per step)
- `{"t":"button","button":"left"|"right"|"middle","down":bool}`
- `{"t":"scroll","dy":int,"dx":int}` (clicks, ydotool sign convention handled in actuator)
- `{"t":"key","key":"enter"}` — a named key press (down+up). Names map to evdev keycodes in the actuator (Linux key names: enter, tab, esc, space, backspace, ctrl, alt, shift, super, arrows, a–z, 0–9, f1–f12, punctuation by name where unambiguous).
- `{"t":"keydown","key":...}` / `{"t":"keyup","key":...}` — for chords (`/hotkey`, `/break`).
- `{"t":"type","text":str}` — guardian types the text via the actuator; per-keystroke delay plan is session-side: session sends one `type` step per character with `sleep` steps between (keeps the guardian dumb and the plan identical to upstream's).

The guardian tracks held keys/buttons across acts so the stop sweep can
release exactly what is down; an act that ends with keys still down is
auto-swept at act end except for explicit `keydown` from `/hotkey`
(which always pairs its own keyups inside the same act).

## Actuator interface (`actuator.py`)

```python
class Actuator:  # protocol
    def move(self, x, y): ...
    def button(self, button, down): ...
    def scroll(self, dx, dy): ...
    def key(self, evdev_keycode, down): ...
    def position(self): -> (x, y) | None
```

- `YdotoolActuator` — drives the guardian's own `ydotoold` (socket
  `/run/handsrelay-guardian/ydotoold.sock`) via the `ydotool` CLI.
  Absolute positioning caveat (SCOPE §5.2): tracks last-known position;
  `position()` returns the tracked value. P1 ships this actuator: it is
  the documented fallback made first, behind the same interface.
- `EisActuator` — **stub raising `NotImplementedError`** with the design
  for the follow-up: session component calls KWin
  `org.kde.KWin.EIS.RemoteDesktop.connectToEIS`, passes the returned fd
  to the guardian over the IPC socket via SCM_RIGHTS, guardian speaks
  the EI protocol on it and owns injection fully. (Pure-Python EI wire
  client is the known least-trodden piece, SCOPE §5.1; it lands behind
  this interface without API change.)
- `FakeActuator` — records calls; for tests.

## Capture (`capture.py`, session side)

- ScreenShot2 via `dbus-fast` (session bus): `CaptureActiveScreen` /
  `CaptureScreen(name)` / `CaptureArea(x,y,w,h)`. Wire reality (verified
  against the P0 introspection, corrected 2026-11-03 during the build):
  the fd is an *input* (`a{sv}h` in, `a{sv}` out) — the caller creates a
  pipe, passes the write end, KWin writes the PNG into it, and the call
  returns a results dict. Current dbus-fast (5.x) has no sync MessageBus,
  so capture drives the aio bus from a short-lived `asyncio.run` per call
  (callers must not be inside a running event loop; the Flask app isn't). Requires the calling
  app to run under the shipped `.desktop` identity
  (`packaging/org.gordy.handsrelay.desktop` with
  `X-KDE-DBUS-Restricted-Interfaces=org.kde.KWin.ScreenShot2;org.kde.KWin.EIS.RemoteDesktop`).
- Monitor rects: parse `kscreen-doctor -o` output.
- If `dbus-fast` is unavailable, raise a clear error (the on-box smoke
  script checks the dependency); no silent fallback.

## Emergency-stop behavior in the session app

- `/health`: always answers (liveness), even stopped/locked out.
- `/state`: answers while stopped and reports `"emergency_stop": true`.
- Every other route: while the guardian reports stopped →
  `423 {"error_code":"emergency_stop"}` (checked in the gate, after auth).
- Yield-if-owner-active: before act routes, if guardian activity shows
  idle < 2 s, refuse `409 {"ok":false,"error":"owner active"}` (queued-act
  polish is P3 with the gateway).

## Packaging (`packaging/`)

- `handsrelay-guardian.service` (system unit; `User=root`, hardening flags, `Restart=on-failure` — restart comes back stopped by design).
- `handsrelay-hands.service` (user unit for the session app).
- `org.gordy.handsrelay.resume.policy` (polkit action).
- `org.gordy.handsrelay.desktop` (session app identity for KWin restricted interfaces).
- `handsrelay-resume` (root helper script: connects to the guardian socket and sends `resume`; installed root-owned, only reachable via pkexec + the polkit action).
- `config.json.example` (guardian config: session_uid, panic combo, virtual-device name patterns, ydotoold socket path).

## Hardening addendum (2026-11-03, external review)

An outside review reproduced four gaps; all are fixed in guardian.py /
status_window.py and pinned by new tests in test_p1_safety.py:

1. **Cancellation generation.** The latch carries a generation counter,
   bumped by every trip. Acts capture it on arrival; an act still queued
   when a stop lands is discarded (`error_code: act_discarded`) even if
   a resume happens first. STOP forgets pending work.
2. **Whole-plan validation + finally-sweep.** `validate_steps` checks
   every step (shape, type, fields, key names) before anything runs,
   and act execution wraps in try/finally that releases all held inputs
   on any exit — a non-dict step previously raised an uncaught
   AttributeError and could strand a held key.
3. **Owner-activity in the guardian.** The guardian itself refuses acts
   while the owner is active (`owner_idle_min_seconds`, default 2.0,
   error_code `owner_active`); the session-app check is now a courtesy
   layer. The socket's same-UID trust boundary is unchanged and
   documented: the root-owned latch/injection path is the hard wall.
4. **Status-window liveness.** The window pings the guardian each
   refresh; a watchdog latches the stop (`window-watchdog`) if a
   once-reporting window goes silent for `window_liveness_seconds`
   (default 15). The window's close handler now destroys the window
   only after the guardian confirms the stop.
