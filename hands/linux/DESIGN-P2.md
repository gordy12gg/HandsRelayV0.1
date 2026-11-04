# HandsRelay Linux port — P2 design (what was built)

Implements SCOPE.md §4 P2 in the fork, under `hands/linux/`. Upstream
Windows code stays untouched; every P2 route mirrors the upstream
route name, request fields, response shape and error strings from
`hands/hands_relay_hands.py` so the unmodified gateway keeps working.

**The P1 safety model is unchanged and still total:** the session app
gained *no* injection path. Window activation asks the compositor to
change the active window (a session operation, the same thing the
owner's window rules do); clipboard operations move text only — the
one place P2 touches keys, `/type`'s paste path, sends its Ctrl+V as
an **act through the guardian**, exactly like every other keystroke.
All new routes sit behind the existing `gate()`: while the guardian
reports stopped they answer `423 {"error_code": "emergency_stop"}`,
same as the P1 act routes (only `/health`, `/state` and the read-only
`/files` browser remain exempt).

All backends are injected through `create_app(...)` keyword arguments
(`windows_backend`, `clipboard_backend`, `filedrop_dirs`, `proc_root`,
`keep_awake`/`keep_awake_enabled`), duck-typed exactly like the P1
`guardian_client`/`capture_module` pair, so the whole surface is
testable headless. `main()` constructs the real backends, each
degrading to `None` (→ the route's unavailable surface) when its
module can't load.

## Components

1. **windows_kwin.py — `KWinWindowsBackend`** (new). Window list +
   activation via the KWin scripting bridge:
   `org.kde.KWin /Scripting` `loadScript(path, pluginName) -> id`,
   then `run()` on `/Scripting/Script<id>` (dbus-fast aio, one
   `asyncio.run` per call — capture.py's pattern). Scripts read
   `workspace.windowList()` (Plasma 6): `internalId` (QUuid — our
   HWND stand-in), `caption`, `pid`, `frameGeometry`, `minimized`,
   `desktops`/`onAllDesktops`, and `workspace.activeWindow` for the
   focused flag. Activation is `workspace.activeWindow = <window>`
   (un-minimising first).
   **Return channel:** scripts have no D-Bus return value, so before
   loading, the backend exports a one-shot
   `org.gordy.handsrelay.ScriptBridge` service under a unique bus
   name (`org.gordy.handsrelay.bridge<48 random bits>`); the script
   JSON-encodes its result and calls back via the KWin script global
   `callDBus(service, path, interface, "Deliver", token, payload)`.
   A random per-call token is checked on delivery, the script is
   unloaded in a `finally`, and the call times out (5 s) instead of
   hanging. The pure pieces — script construction and the payload →
   raw-window mapping (`visible := not minimised and on the current
   desktop`, pid 0 → None) — are unit-tested headless.
   The shipped `.desktop` identity
   (`packaging/org.gordy.handsrelay.desktop`) now also lists
   `org.kde.KWin.Scripting` in `X-KDE-DBUS-Restricted-Interfaces`, in
   case `loadScript` is itself a restricted interface.

2. **clipboard_wl.py — `WlClipboard`** (new). `get_text()` /
   `set_text()` over `wl-paste --no-newline` / `wl-copy`
   subprocesses, with an injectable `run=` for tests. Mirrors
   upstream's backend semantics: no selection → `""` (wl-paste's
   non-zero exit), a *missing binary* raises (the route's 502 — an
   absent tool must not masquerade as an empty clipboard). `wl-copy`
   forks a selection holder and returns; that is how Wayland
   clipboards work, not a leak.

3. **keepawake.py — `KeepAwake` + backends** (new). Upstream keeps
   the PC awake for the packaged app's whole life
   (`SetThreadExecutionState(ES_CONTINUOUS|ES_SYSTEM_REQUIRED)`) and
   exposes **no route**, so P2 mirrors that: an internal behaviour
   gated by a config flag — env `HANDS_KEEP_AWAKE` (default on in
   `main()`, upstream parity; `0/false/no/off` disables) /
   `create_app(keep_awake_enabled=...)`. `KeepAwake.start()` is
   called at app creation, `stop()` is registered with `atexit`, and
   `/state` reports `"keep_awake": bool`. Backends, tried in order:
   - `ScreenSaverInhibit` — `org.freedesktop.ScreenSaver`
     `Inhibit(app, reason) -> cookie` / `UnInhibit(cookie)` on the
     session bus (KDE implements the freedesktop interface). The
     inhibition is tied to the D-Bus connection, so this backend
     holds its bus open on a dedicated thread/loop for the hold's
     lifetime (unlike capture.py's one-shot calls).
   - `SystemdInhibit` — a held
     `systemd-inhibit --what=idle:sleep --mode=block sleep infinity`
     child; release = terminate. Coarser but contract-free.
   A failed engage is logged, never fatal — the relay runs either way.

4. **hands_linux.py — the routes** (extended; see the map below),
   including the file-drop protocol ported into the app (upstream's
   state machine, validation and error strings verbatim; state is
   per-app-instance instead of module-global so test apps stay
   independent) and `_process_snapshot` / `_process_name` /
   `_monitor_for_bounds` helpers.

## Route-by-route mapping to upstream

| Route | Upstream | Linux P2 | Notes |
|---|---|---|---|
| `GET /monitors` | `EnumDisplayMonitors` → `{ok, monitors:[{x,y,w,h,primary}], count}` | capture module's `monitor_rects()` (kscreen-doctor), same body; `primary` defaults to the first rect when kscreen doesn't say; connector `name` rides along when known | read-only |
| `GET /windows` | `_enum_windows()` + `_shape_window()` → `{ok, windows:[...]}` | KWin backend raw dicts shaped identically, **plus `"id"`** (KWin UUID for the HWND); `process` resolved from the pid via `/proc/<pid>/comm`; `monitor` from bounds centre vs capture rects; no backend → `{ok, windows: [], supported: false}` (upstream's off-Windows surface); backend failure → 502 | read-only |
| `GET /window_titles` | `pyautogui.getAllTitles()` → `{ok, titles}` | titles of the backend's windows (empty titles dropped, like upstream's pywin32 path); no backend → `{ok, titles: []}` | read-only |
| `POST /focus` | title match (substring, `exact` flag), `_activate_window`, 404 / 409-with-window | **by UUID first**: `{"id": ...}` activates that window; upstream's `{"title", "exact"}` form still works as a fallback. Owner-active yield check first (upstream's `_yield_if_active` position); no match → 404, compositor refused → 409 with the shaped window, bridge failure → 502, no backend → 501 | compositor activation — **not** input injection |
| `POST /clipboard/set` | `{text}` → `{ok}`; 400 / 501 / 502 | identical, over `WlClipboard.set_text` | — |
| `GET /clipboard/get` | → `{ok, text}`; read logged (`log_line("clipboard read via relay")`) | identical, logged via the app's `_log` after a successful read; contents never logged | read **is** logged, per upstream + SCOPE §3 |
| `POST /type` paste path | `_type_dispatch`: paste saves clipboard → set → Ctrl+V → restore; failures fall back to keys with `"note"`; `auto` pastes when len > 120 and a backend exists | same dispatch and response body (`delays_planned`/`planned_seconds` are 0 on the paste path). Ctrl+V is a **guardian act**, not local injection. The P1 501 stays for exactly one case: `method: "paste"` with **no clipboard backend injected** (upstream has no equivalent — its dispatch would fall back; the Linux app keeps the explicit 501 so a misconfigured host can't silently keystroke-type a payload the caller asked to paste) | paste save/restore reads are internal and, as upstream, not log-lined |
| `POST /filedrop/begin` | allowlist folder + bare filename + size 1..16 MB + sha256 → `{ok, upload_id, chunk_max: 524288}`; unconfigured → 501 | identical. Allowlist source differs: `create_app(filedrop_dirs=...)` or env `HANDS_FILEDROP_DIRS` (`os.pathsep`-separated); upstream also reads its config file — the session app has none, so env/argument only | writes only inside allowlisted dirs |
| `POST /filedrop/chunk` | offset-checked append (409 with `expected_offset`), base64-validated, size-capped | identical | — |
| `POST /filedrop/commit` | size + sha256 verify, temp file + `os.replace`, `{ok, path, size, sha256}` | identical | — |
| `POST /filedrop/abort` | drop state → `{ok}` / 404 | identical | — |
| `GET /process/<pid>` | `_process_snapshot` → `{ok, pid, running, instance}` (creation-time instance id) | `/proc`: same keys **plus** `name` (comm), `cmdline` (argv list), `state`, `ppid`. Instance = `"<boot_id>:<starttime-jiffies>"` — the same PID-reuse-detection property as upstream's creation FILETIME. Missing pid → `running: false, instance: null`; zombie (state Z) → `running: false` with instance still readable | read-only |
| keep-awake | app-lifetime `SetThreadExecutionState`, no route | internal, flag-gated (see above), `/state` reports it | no route, like upstream |

## Emergency-stop gating (unchanged rule, wider surface)

`gate()` was already path-based: everything except `/health`,
`/state`, `/files`, `/files/download` 423s while stopped. All P2
routes — including the read-only `/windows`, `/monitors`,
`/process/<pid>` and the whole file-drop family — are therefore gated
with no new code, and `test_p2_routes.py` pins every one of them at
423 while stopped. `/state` additionally reports `keep_awake`.

## Tests

`hands/linux/test_p2_routes.py` (new, 25 tests, existing plain-assert
style): window shape + /proc process resolution, unsupported surface,
titles, focus by UUID / unknown 404 / refused 409 / title fallback /
400 validation, backend-failure 502, monitors shape, clipboard
get/set + read-logging assertion, 502/501 clipboard surfaces, the
`WlClipboard` backend against a fake runner, /type paste (Ctrl+V act
shape + clipboard save/restore), auto-paste threshold, paste-failure
fallback with note, file-drop happy path + abort + allowlist/bare-name
/sha validation + unconfigured 501, /process for self and a bogus pid,
keep-awake engagement + fallback chain + systemd-inhibit argv, the
KWin payload mapping and script building, and the 423 sweep.

Full `hands/linux` suite: **49 passed** (9 P1 wire + 12 guardian
safety + 1 files-browse + 2 encodings + 25 P2), via both the
plain-assert runners and pytest.

## Needs on-box verification (nothing here has touched a live KWin)

1. **The scripting return channel (the big unknown).** Does a script
   loaded via `org.kde.KWin.Scripting.loadScript` run under
   `run()` on `/Scripting/Script<id>`, and does the script global
   `callDBus(...)` reach a service exported by an unprivileged
   same-session process (our one-shot bridge)? If `callDBus` is
   absent/blocked, fallbacks to evaluate live: scrape the script's
   `print()` output from the journal, or have the gateway poll a
   second `loadScript` round-trip. Do not assume — test first.
2. **Is `loadScript` a restricted interface?** The shipped
   `.desktop` identity now lists `org.kde.KWin.Scripting`; verify
   whether KWin honours/denies the call with and without that entry,
   and whether scripts must live at a particular path.
3. **Plasma 6.8 scripting API surface:** `workspace.windowList()`
   (vs the pre-6 `clientList()`), `Window.internalId` stability
   across calls (it must be the same UUID in list and focus),
   `Window.pid`, `frameGeometry`, `desktops` list identity vs
   `workspace.currentDesktop`, and whether assigning
   `workspace.activeWindow` is honoured for windows on other
   desktops / when a fullscreen window holds focus.
4. **`visible` semantics:** our `not minimised and on current
   desktop` approximation vs what the gateway expects from upstream's
   `IsWindowVisible` (which is true for windows on other virtual
   desktops). Decide live whether other-desktop windows should read
   visible.
5. **wl-clipboard under the real session:** `wl-paste`/`wl-copy`
   behaviour for non-text offers (images), selection ownership when
   the source app exits, and `/type` paste against real targets
   (terminals that want Ctrl+Shift+V are a known upstream-shared
   caveat — Ctrl+V is what upstream sends too).
6. **Keep-awake on Plasma 6.8:** whether the session bus name is
   `org.freedesktop.ScreenSaver` as assumed, whether the inhibition
   survives the dedicated-connection pattern, and whether it also
   blocks auto-lock (the actual goal) or only screen blanking.
7. **kscreen-doctor primary flag:** P2 falls back to "first rect is
   primary"; verify against a real two-monitor layout whether
   kscreen-doctor marks the primary and whether the order is stable.
8. **File-drop on the real filesystem:** commit into an allowlisted
   dir on the owner's disk (permissions, `os.replace` across the temp
   file in the same dir) — code-identical to upstream, but the
   allowlist env must be present in the packaged user unit's
   environment, which is a P3 packaging decision.

## Verified on-box (2026-11-04, Gordon-PC, Plasma 6.8.2, desk session C)

1. **Return channel: WORKS.** A loadScript'd script's `callDBus`
   reaches the one-shot bridge exported by the unprivileged
   session-app process; `/windows` returned the real window list
   (plasmashell desktop + panel, two Firefox windows, Konsole with
   `focused: true` matching reality). No fallback needed.
2. **loadScript is not restricted** for an unprivileged same-session
   process; no `.desktop` identity was involved in the test process.
   BUT the interface names are the Plasma 6 lowercase forms —
   `org.kde.kwin.Scripting` at `/Scripting`, `org.kde.kwin.Script`
   at `/Scripting/Script<id>` (gdbus introspect; the pre-6
   `org.kde.KWin.*` spelling gets UnknownInterface). Fixed in
   1816a8e. Two bridge bugs were found and fixed on the way:
   dbus-fast raises TypeError at class-definition time if a
   @method carries a `-> None` annotation under
   `from __future__ import annotations` (annotation stringizes to
   "None" -> signature None), and kscreen-doctor colourises output
   even when piped, which parsed to zero monitors until ANSI codes
   were stripped in `capture.monitor_rects`.
3. **API surface as designed:** `workspace.windowList()`,
   `internalId` (braced UUID strings, consistent between list and
   focus), `Window.pid`, `frameGeometry` all present. Activation
   via `workspace.activeWindow = w` honoured live: `/focus` on the
   Firefox window raised it to the front (owner-confirmed).
4. **visible semantics:** kept as designed (not minimised + on
   current desktop). All current-desktop windows reported
   `visible: true` correctly; no other-desktop window existed
   during the test, so the upstream divergence stays theoretical.
5. **wl-clipboard:** `wl-paste` reads fine. `wl-copy`'s parent
   lingers past the subprocess timeout while its forked holder has
   taken the selection — the route's first live set reported a
   false failure while the text had landed. `set_text` now uses a
   short timeout and verifies by read-back (1816a8e). Live retest
   + the `/type` paste path against a real target: pending the
   same session's next battery.
6. **Keep-awake:** engages at app start ("keeping this PC awake
   while the relay runs") and `/state` reports
   `"keep_awake": true`. Blanking-vs-lock distinction not yet
   exercised (needs an idle wait).
7. **Monitors:** the box has a SINGLE monitor (DP-3 2560x1440), so
   "first rect is primary" is trivially correct here; `/monitors`
   returns it with name + primary after the ANSI fix. The
   two-monitor question stays open until such a layout exists.
8. **File-drop:** live round trip pending the same session's next
   battery; the packaged-unit allowlist env question carries to
   section D (production install).
