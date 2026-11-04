#!/usr/bin/env python3
"""hands_linux.py — HandsRelay session hands app, Linux (P1).

Flask on 127.0.0.1:5000, running as the session user. Mirrors the wire
behavior of the upstream Windows app (hands/hands_relay_hands.py): the
same JSON request fields, the same {"ok": true} responses, the X-Secret
header gate with the per-peer failed-guess lockout (10 bad secrets
inside 10 minutes -> authentication pauses for 5 minutes, 429; a bad
secret is 401; a valid secret is never locked out).

The one architectural difference: this process holds NO injection
capability. It plans motion with hands/motion.py (reused unchanged,
loaded by path exactly like upstream's _load_motion) and sends ONE act
— a list of primitive steps — per route to the root-owned guardian over
its unix-socket IPC (see DESIGN-P1.md). The guardian checks its
emergency-stop latch before executing; a stopped guardian makes every
route except /health, /state and the read-only /files browser answer
423 {"error_code": "emergency_stop"} — the P2 routes included.

Pointer position is tracked session-side: every act we send ends at a
known point, so the last planned landing becomes the next plan's start.
Before the first act the position is unknown and plans start at the
target itself (a zero-length plan), mirroring how the guardian's
ydotool actuator tracks last-known position.

The app is built behind create_app(guardian_client, capture_module)
dependency injection so tests can stub both:

guardian_client (duck-typed):
    state()    -> {"ok": True, "stopped": bool,
                   "reason": str | None, "since": float}
    activity() -> {"ok": True, "idle_seconds": float}
    act(kind, steps) -> {"ok": True} |
                        {"ok": False, "error_code": "emergency_stop"} |
                        {"ok": False, "error": str}
    stop(source) -> {"ok": True, "stopped": True}
Any method may raise on transport failure; the app fails safe.

capture_module (duck-typed, ScreenShot2-backed on the real box):
    monitor_rects() -> [{"x", "y", "w", "h", "primary"}, ...]
    capture_png(rect | None) -> PNG bytes, or (bytes, w, h)
    — or — grab(rect | None) -> PIL-style image (.size, .save) or bytes

P2 backends (all optional; None means the route reports unavailable
with upstream's surface — 501, or "supported": false for /windows):

windows_backend (duck-typed, windows_kwin.KWinWindowsBackend):
    list_windows() -> [{"id", "title", "pid", "bounds", "visible",
                        "focused"}, ...]   (KWin internal UUIDs stand
                        in for HWNDs; process/monitor are added here)
    activate(window_id) -> bool
    Window operations are session operations, NOT input injection:
    listing is observation, and activation asks the compositor to
    change the active window — no input event is ever synthesized.

clipboard_backend (duck-typed, clipboard_wl.WlClipboard):
    get_text() -> str
    set_text(text) -> None (raises on failure)
    Every clipboard READ through /clipboard/get is logged via _log,
    mirroring upstream; /type's paste path saves/restores through the
    same backend and sends Ctrl+V as a guardian act — the clipboard
    itself never injects anything.

keep_awake (duck-typed, keepawake.KeepAwake): start()/stop()/active.
Started at app creation when keep_awake_enabled; upstream exposes no
route for keep-awake, and neither do we.
"""

import atexit
import base64
import binascii
import hashlib
import io
import json
import math
import os
import random
import re
import secrets as secrets_mod
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from flask import Flask, jsonify, request, send_file

PORT = 5000

# ---- failed-guess lockout (values mirror upstream) --------------------
MAX_FAILS = 10         # bad secrets allowed inside the window...
FAIL_WINDOW = 600      # ...of 10 minutes, then auth pauses for...
LOCKOUT_SECONDS = 300  # ...5 minutes (restart the app to clear early)

_ACT_PATHS = {
    "/move",
    "/click",
    "/drag",
    "/scroll",
    "/key",
    "/hotkey",
    "/break",
    "/type",
}

_BUTTONS = ("left", "right", "middle")

# ---- file-drop (values mirror upstream) --------------------------------
_FILEDROP_CHUNK_MAX = 524288
_FILEDROP_MAX_SIZE = 16 * 1024 * 1024
_FILEDROP_TTL = 600  # uploads older than 10 minutes are purged lazily


def _load_motion():
    """hands/motion.py, loaded by path (one directory up from here),
    the same way upstream's hands_relay_hands.py loads its sibling."""
    import importlib.util

    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "motion.py"
    )
    spec = importlib.util.spec_from_file_location("hands_linux_motion", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


motion = _load_motion()


def _log(message):
    print(f"[hands-linux] {message}", flush=True)


# ---- input-realism planner (mirrors upstream _plan_key_delays) ---------


def _plan_key_delays(text, rng):
    """Per-character typing delays (seconds slept AFTER each character).

    Base delay is uniform in [0.04, 0.16]; a character that ends a word
    (space) adds uniform [0.05, 0.20] and one that ends a sentence
    (. ! ?) adds uniform [0.10, 0.30]. If the total exceeds the budget
    max(5.0, len(text) * 0.16) every delay is scaled down proportionally
    so long pastes stay bounded.
    """
    delays = []
    for ch in text:
        delay = rng.uniform(0.04, 0.16)
        if ch == " ":
            delay += rng.uniform(0.05, 0.20)
        elif ch in ".!?":
            delay += rng.uniform(0.10, 0.30)
        delays.append(delay)
    budget = max(5.0, len(text) * 0.16)
    total = sum(delays)
    if total > budget and total > 0:
        scale = budget / total
        delays = [d * scale for d in delays]
    return delays


# ---- session lock state (loginctl LockedHint) --------------------------

_session_id_cache = None


def _find_session_id():
    """This user's logind session id: $XDG_SESSION_ID, else the first
    session in `loginctl list-sessions` owned by our uid."""
    global _session_id_cache
    if _session_id_cache:
        return _session_id_cache
    sid = os.environ.get("XDG_SESSION_ID")
    if sid:
        _session_id_cache = sid
        return sid
    try:
        out = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout
        for line in out.splitlines():
            fields = line.split()
            # SESSION UID USER SEAT TTY ...
            if len(fields) >= 2 and fields[1] == str(os.getuid()):
                _session_id_cache = fields[0]
                return _session_id_cache
    except Exception:
        pass
    return None


def _probe_locked():
    """True/False from loginctl LockedHint, or None when unknown
    (no session, no loginctl, probe failure) — mirrors upstream's
    _probe_lock_state returning None off Windows / on failure."""
    sid = _find_session_id()
    if not sid:
        return None
    try:
        out = subprocess.run(
            ["loginctl", "show-session", sid, "-p", "LockedHint", "--value"],
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
    except Exception:
        return None
    if out == "yes":
        return True
    if out == "no":
        return False
    return None


# ---- capture helpers ----------------------------------------------------


def _parse_region(raw):
    """'x,y,w,h' -> rect dict, or None if malformed / non-positive size.
    (Mirrors upstream.)"""
    try:
        parts = [int(p) for p in str(raw).split(",")]
    except ValueError:
        return None
    if len(parts) != 4 or parts[2] <= 0 or parts[3] <= 0:
        return None
    return {"x": parts[0], "y": parts[1], "w": parts[2], "h": parts[3]}


def _png_size(data):
    """(width, height) from a PNG's IHDR, or (0, 0) if not a PNG."""
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
        w, h = struct.unpack(">II", data[16:24])
        return int(w), int(h)
    return 0, 0


def _capture_png(capture_module, rect):
    """Normalize the injected capture module to (png_bytes, w, h)."""
    fn = getattr(capture_module, "capture_png", None) or getattr(
        capture_module, "grab", None
    )
    if fn is None:
        raise RuntimeError("capture module provides neither capture_png nor grab")
    out = fn(rect)
    if isinstance(out, tuple):
        data, w, h = out
        return bytes(data), int(w), int(h)
    if isinstance(out, (bytes, bytearray)):
        data = bytes(out)
        w, h = _png_size(data)
        return data, w, h
    # PIL-style image, as upstream's _grab returns.
    buf = io.BytesIO()
    out.save(buf, format="PNG")
    return buf.getvalue(), int(out.size[0]), int(out.size[1])


def _monitor_rects(capture_module):
    fn = getattr(capture_module, "monitor_rects", None)
    if fn is not None:
        return fn()
    # Fallback: a single primary rect the size of the full frame.
    _data, w, h = _capture_png(capture_module, None)
    return [{"x": 0, "y": 0, "w": w, "h": h, "primary": True}]


def _monitor_for_bounds(bounds, rects):
    """Index of the monitor rect containing the window's centre, else
    None. (Mirrors upstream.)"""
    cx = bounds["x"] + bounds["w"] / 2
    cy = bounds["y"] + bounds["h"] / 2
    for i, r in enumerate(rects):
        if r["x"] <= cx < r["x"] + r["w"] and r["y"] <= cy < r["y"] + r["h"]:
            return i
    return None


# ---- /proc process probe (the Linux _process_snapshot) -------------------


def _process_name(proc_root, pid):
    """Process name (comm) for a pid, or None — never raises.
    (Mirrors upstream _process_name's contract.)"""
    if not pid:
        return None
    try:
        with open(os.path.join(proc_root, str(int(pid)), "comm"),
                  encoding="utf-8", errors="replace") as fh:
            return fh.read().strip() or None
    except Exception:
        return None


def _process_snapshot(proc_root, pid):
    """Read-only /proc probe: the Linux counterpart of upstream's
    _process_snapshot.

    Upstream identifies a process instance by its creation time so PID
    reuse is detectable; the Linux instance string is
    "<boot_id>:<starttime-jiffies>" (field 22 of /proc/<pid>/stat plus
    the boot id), which has the same reuse-detection property.

    Returns {"running", "instance", "name", "cmdline", "state",
    "ppid"}. A missing pid is {"running": False, "instance": None,
    ...} — never an exception (upstream: access errors are not process
    exit, but "no such pid" is). A zombie (state Z) has exited from
    every caller's perspective, so it reports running False with its
    instance still readable.
    """
    empty = {"running": False, "instance": None, "name": None,
             "cmdline": [], "state": None, "ppid": None}
    pdir = os.path.join(proc_root, str(pid))
    if not os.path.isdir(pdir):
        return empty
    try:
        with open(os.path.join(pdir, "stat"), "rb") as fh:
            stat_raw = fh.read().decode("utf-8", errors="replace")
    except (OSError, UnicodeError):
        return empty
    # comm is parenthesised and may itself contain spaces/parens, so
    # split at the LAST ')': the fields after it start with the state.
    rparen = stat_raw.rfind(")")
    if rparen < 0:
        return empty
    fields = stat_raw[rparen + 2:].split()
    # fields[0] is stat field 3 (state); starttime is field 22 -> idx 19.
    if len(fields) <= 19:
        return empty
    state = fields[0]
    try:
        ppid = int(fields[1])
        starttime = int(fields[19])
    except ValueError:
        return empty
    boot_id = None
    try:
        with open(os.path.join(proc_root, "sys", "kernel", "random",
                               "boot_id"), encoding="utf-8") as fh:
            boot_id = fh.read().strip() or None
    except OSError:
        pass
    instance = f"{boot_id}:{starttime}" if boot_id else str(starttime)
    name = _process_name(proc_root, pid)
    cmdline = []
    try:
        with open(os.path.join(pdir, "cmdline"), "rb") as fh:
            raw = fh.read()
        cmdline = [part.decode("utf-8", errors="replace")
                   for part in raw.split(b"\0") if part]
    except OSError:
        cmdline = []
    return {
        "running": state != "Z",
        "instance": instance,
        "name": name,
        "cmdline": cmdline,
        "state": state,
        "ppid": ppid,
    }


# ---- fallback guardian client (stdlib unix-socket, design-doc IPC) -----


class SocketGuardianClient:
    """Minimal guardian client speaking the DESIGN-P1 JSON-lines IPC.

    Used by main() when the packaged guardian_client module is not
    importable (P1 dev). One request per connection: a JSON object and
    a newline, one JSON line back.
    """

    def __init__(self, path=None, timeout=5.0):
        self.path = path or os.environ.get(
            "HANDS_GUARDIAN_SOCKET", "/run/handsrelay-guardian/guardian.sock"
        )
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

    def act(self, kind, steps):
        return self._call({"op": "act", "kind": kind, "steps": steps})

    def stop(self, source="api"):
        return self._call({"op": "stop", "source": source})


# ---- the app -------------------------------------------------------------


def create_app(guardian_client, capture_module, secret=None, rng=None,
               files_root=None, windows_backend=None, clipboard_backend=None,
               filedrop_dirs=None, proc_root="/proc", keep_awake=None,
               keep_awake_enabled=False):
    """Build the Flask app around injected guardian/capture backends.

    P2 injections (all optional, see the module docstring):
    windows_backend, clipboard_backend, filedrop_dirs (list of allowed
    drop folders; None resolves HANDS_FILEDROP_DIRS, default none ->
    the filedrop routes answer 501, mirroring upstream), proc_root,
    and keep_awake + keep_awake_enabled.
    """
    if secret is None:
        secret = os.environ.get("HANDS_SECRET") or secrets_mod.token_urlsafe(24)
    rng = rng if rng is not None else random

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1_000_000  # requests are tiny JSON
    app.hands_secret = secret

    # Failed-guess lockout state (per peer), mirroring upstream.
    fail_lock = threading.Lock()
    fail_by_peer = {}
    lockout_by_peer = {}

    # Serializes planning + act submission so the tracked pointer
    # position stays consistent (the guardian serializes execution too).
    act_lock = threading.Lock()
    position = {"x": None, "y": None}  # last planned landing point

    # Keep-awake (P2): upstream holds it for the app's whole life and
    # exposes no route for it; here it engages only when a backend was
    # injected AND the flag is on. Failure to engage is logged, never
    # fatal — the relay runs either way.
    if keep_awake is not None and keep_awake_enabled:
        if keep_awake.start():
            _log("keeping this PC awake while the relay runs")
            atexit.register(keep_awake.stop)
        else:
            _log("keep-awake requested but no backend engaged")

    # File-drop upload state (P2), per app instance (upstream keeps it
    # module-global; per-instance keeps test apps independent).
    uploads = {}
    uploads_lock = threading.Lock()

    def peer_key():
        try:
            return request.remote_addr or "-"
        except RuntimeError:
            return "-"

    def auth_decide(provided):
        """One critical section. A valid secret is never locked out.

        Mirrors upstream _auth_decide, including: an empty app secret
        does not compare equal to an empty header, and those rejects
        are not counted toward the lockout.
        """
        import hmac

        now = time.monotonic()
        peer = peer_key()
        with fail_lock:
            app_secret = secret or ""
            if app_secret and hmac.compare_digest(provided, app_secret):
                return "ok", False
            if now < lockout_by_peer.get(peer, 0.0):
                return "locked", False
            if not app_secret:
                return "bad", False
            times = fail_by_peer.setdefault(peer, [])
            times[:] = [t for t in times if now - t < FAIL_WINDOW]
            times.append(now)
            tripped = len(times) >= MAX_FAILS
            if tripped:
                lockout_by_peer[peer] = now + LOCKOUT_SECONDS
                times.clear()
            return "bad", tripped

    def guardian_stopped():
        """(stopped, state_dict). Fails safe: an unreachable guardian
        reads as stopped — /health still answers, /state reports it."""
        try:
            st = guardian_client.state()
        except Exception:
            return True, None
        if not isinstance(st, dict):
            return True, None
        return bool(st.get("stopped")), st

    def yield_threshold():
        try:
            return float(os.environ.get("HANDS_YIELD_IDLE_SECONDS", "2"))
        except (TypeError, ValueError):
            return 2.0

    def yield_if_owner_active():
        """409 before an act when the owner is (probably) at the desk.

        Design-doc P1 rule: guardian activity idle < 2 s ->
        409 {"ok": false, "error": "owner active"}. A locked desktop
        also yields, mirroring upstream (input injected at the lock
        screen goes nowhere yet would report success).
        """
        if _probe_locked() is True:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "desktop locked — control yielded",
                        "error_code": "locked",
                    }
                ),
                409,
            )
        try:
            idle = guardian_client.activity().get("idle_seconds")
        except Exception:
            idle = None
        if idle is not None and idle < yield_threshold():
            return jsonify({"ok": False, "error": "owner active"}), 409
        return None

    def send_act(kind, steps):
        """Ship one act to the guardian. None on success, else a
        Flask (body, status) refusal."""
        try:
            resp = guardian_client.act(kind, steps)
        except Exception:
            return jsonify({"ok": False, "error": "guardian unreachable"}), 503
        if isinstance(resp, dict) and resp.get("ok"):
            return None
        if isinstance(resp, dict) and resp.get("error_code") == "emergency_stop":
            return jsonify({"error_code": "emergency_stop"}), 423
        err = resp.get("error") if isinstance(resp, dict) else None
        return jsonify({"ok": False, "error": err or "guardian act failed"}), 500

    # ---- gate ------------------------------------------------------

    @app.before_request
    def gate():
        if request.path == "/health":
            return  # liveness only: a lockout or a bad probe must never
            # read as "down" (mirrors upstream's contract for /health)
        provided = request.headers.get("X-Secret") or ""
        decision, tripped = auth_decide(provided)
        if decision == "locked":
            return jsonify({"ok": False, "error": "locked out"}), 429
        if decision != "ok":
            if tripped:
                _log(
                    "LOCKOUT: too many bad secrets -- authentication "
                    "paused for 5 minutes"
                )
            _log(f"rejected request to {request.path} (bad secret)")
            return jsonify({"ok": False, "error": "bad secret"}), 401
        if request.path == "/state":
            return  # /state answers while stopped and reports the latch
        if request.path in ("/files", "/files/download"):
            return  # read-only browsing: the stop governs INPUT, and
            # these routes hold no injection capability (secret-gated
            # above). Requiring a polkit resume just to read files
            # would invert the safety model.
        stopped, _st = guardian_stopped()
        if stopped:
            return jsonify({"error_code": "emergency_stop"}), 423
        return None

    @app.after_request
    def noindex(resp):
        resp.headers["X-Robots-Tag"] = "noindex, nofollow"
        return resp

    # ---- liveness / state ------------------------------------------

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/state")
    def state():
        stopped, st = guardian_stopped()
        try:
            idle = guardian_client.activity().get("idle_seconds")
        except Exception:
            idle = None
        body = {
            "ok": True,
            "platform": "linux",
            "locked": _probe_locked(),
            "idle_seconds": idle,
            "emergency_stop": stopped,
            "keep_awake": bool(keep_awake is not None and keep_awake.active),
        }
        if st is None:
            body["guardian"] = "unreachable"
        else:
            body["stopped_reason"] = st.get("reason")
            body["stopped_since"] = st.get("since")
        return body

    # ---- read-only file browsing (confined root) ----------------------
    # Session-side and read-only: no guardian involvement, no injection.
    # The root defaults to ~/Downloads (HANDS_FILES_ROOT overrides);
    # every path is realpath-resolved and must stay inside it.

    files_root_real = os.path.realpath(
        files_root or os.environ.get("HANDS_FILES_ROOT")
        or os.path.expanduser("~/Downloads"))

    def _resolve_in_root(rel):
        rel = (rel or "").strip()
        if os.path.isabs(rel):
            return None
        cand = os.path.realpath(os.path.join(files_root_real, rel))
        if os.path.commonpath([cand, files_root_real]) != files_root_real:
            return None
        return cand

    @app.get("/files")
    def files_list():
        target = _resolve_in_root(request.args.get("path", ""))
        if target is None:
            return jsonify({"ok": False,
                            "error": "path escapes files root"}), 403
        if not os.path.isdir(target):
            return jsonify({"ok": False, "error": "not a directory"}), 404
        entries = []
        for name in os.listdir(target):
            p = os.path.join(target, name)
            try:
                st = os.stat(p)
            except OSError:
                continue
            entries.append({"name": name, "dir": os.path.isdir(p),
                            "size": st.st_size, "mtime": st.st_mtime})
        entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
        rel_out = os.path.relpath(target, files_root_real)
        return {"ok": True, "root": files_root_real,
                "path": "" if rel_out == "." else rel_out,
                "entries": entries}

    @app.get("/files/download")
    def files_download():
        target = _resolve_in_root(request.args.get("path", ""))
        if target is None:
            return jsonify({"ok": False,
                            "error": "path escapes files root"}), 403
        if not os.path.isfile(target):
            return jsonify({"ok": False, "error": "not a file"}), 404
        return send_file(target, as_attachment=True)

    # ---- monitors (P2) --------------------------------------------------
    # Monitor geometry comes from the capture module (kscreen-doctor
    # parsing there); the shape matches upstream's /monitors exactly:
    # {"ok", "monitors": [{"x","y","w","h","primary"}...], "count"}.
    # The connector "name" rides along when the capture module has it.

    @app.get("/monitors")
    def monitors():
        rects = []
        for i, r in enumerate(_monitor_rects(capture_module)):
            entry = {
                "x": int(r.get("x", 0)),
                "y": int(r.get("y", 0)),
                "w": int(r.get("w", 0)),
                "h": int(r.get("h", 0)),
                "primary": bool(r.get("primary", i == 0)),
            }
            if r.get("name"):
                entry["name"] = r["name"]
            rects.append(entry)
        return {"ok": True, "monitors": rects, "count": len(rects)}

    # ---- windows + focus (P2) -------------------------------------------
    # Session-side observation + compositor activation via the injected
    # KWin backend. Neither is input injection: listing is read-only,
    # activation asks KWin to change the active window (the owner's own
    # window rules do the same). No route here synthesizes input — all
    # actuation still flows through the guardian.
    #
    # The public window shape matches upstream _shape_window, plus "id":
    # the KWin internal UUID standing in for the HWND.

    def shape_window(win, rects):
        b = win.get("bounds") or {}
        bounds = {
            "x": int(b.get("x", 0)), "y": int(b.get("y", 0)),
            "w": int(b.get("w", 0)), "h": int(b.get("h", 0)),
        }
        pid = win.get("pid")
        process = win.get("process")
        if process is None and pid:
            process = _process_name(proc_root, pid)
        return {
            "id": win.get("id"),
            "title": win.get("title") or "",
            "process": process,
            "pid": pid,
            "bounds": bounds,
            "monitor": _monitor_for_bounds(bounds, rects),
            "visible": bool(win.get("visible", True)),
            "focused": bool(win.get("focused", False)),
        }

    def enum_windows():
        """(raw windows, monitor rects) from the injected backend."""
        if windows_backend is None:
            return [], _monitor_rects(capture_module)
        return windows_backend.list_windows(), _monitor_rects(capture_module)

    @app.get("/windows")
    def windows():
        if windows_backend is None:
            return jsonify({"ok": True, "windows": [], "supported": False})
        try:
            raw, rects = enum_windows()
        except Exception as exc:
            return jsonify({"ok": False, "error": f"window list failed: {exc}"}), 502
        return jsonify(
            {"ok": True, "windows": [shape_window(w, rects) for w in raw]}
        )

    @app.get("/window_titles")
    def window_titles():
        if windows_backend is None:
            return {"ok": True, "titles": []}
        try:
            raw, _rects = enum_windows()
        except Exception as exc:
            return jsonify({"ok": False, "error": f"window list failed: {exc}"}), 502
        return {"ok": True,
                "titles": [w.get("title") or "" for w in raw
                           if w.get("title")]}

    @app.post("/focus")
    def focus():
        """Activate one window: by KWin UUID {"id": ...} (the P2 form),
        or by upstream's title match {"title": ..., "exact": bool}.
        No match -> 404; backend refused -> 409 (upstream's contract)."""
        d = request.get_json(force=True, silent=True) or {}
        win_id = d.get("id")
        title = d.get("title")
        if win_id is not None and not (isinstance(win_id, str) and win_id):
            return jsonify({"ok": False, "error": "id must be a non-empty string"}), 400
        if win_id is None and not (isinstance(title, str) and title.strip()):
            return jsonify(
                {"ok": False, "error": "id or title must be a non-empty string"}
            ), 400
        if windows_backend is None:
            return jsonify(
                {"ok": False, "error": "window focus unavailable on this host"}
            ), 501
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        try:
            raw, rects = enum_windows()
        except Exception as exc:
            return jsonify({"ok": False, "error": f"window list failed: {exc}"}), 502
        match = None
        if win_id is not None:
            for win in raw:
                if win.get("id") == win_id:
                    match = win
                    break
            label = win_id
        else:
            exact = bool(d.get("exact", False))
            needle = title.casefold()
            for win in raw:
                candidate = (win.get("title") or "").casefold()
                if (candidate == needle) if exact else (needle in candidate):
                    match = win
                    break
            label = title
        if match is None:
            return jsonify(
                {"ok": False, "error": f"no window matching {label!r}"}
            ), 404
        try:
            activated = windows_backend.activate(match.get("id"))
        except Exception as exc:
            return jsonify({"ok": False, "error": f"activation failed: {exc}"}), 502
        if not activated:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "activation failed",
                        "window": shape_window(match, rects),
                    }
                ),
                409,
            )
        return jsonify({"ok": True, "window": shape_window(match, rects)})

    # ---- clipboard (P2) ---------------------------------------------------
    # wl-clipboard via the injected backend. Sensitive: the same
    # X-Secret gate as every route, and every READ through
    # /clipboard/get is logged via _log so the operator sees it in the
    # app output — upstream logs reads; contents are never logged.

    @app.post("/clipboard/set")
    def clipboard_set():
        d = request.get_json(force=True, silent=True) or {}
        text = d.get("text")
        if not isinstance(text, str):
            return jsonify({"ok": False, "error": "text must be a string"}), 400
        if clipboard_backend is None:
            return jsonify(
                {"ok": False, "error": "clipboard unavailable on this host"}
            ), 501
        try:
            clipboard_backend.set_text(text)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"clipboard set failed: {exc}"}), 502
        return {"ok": True}

    @app.get("/clipboard/get")
    def clipboard_get():
        if clipboard_backend is None:
            return jsonify(
                {"ok": False, "error": "clipboard unavailable on this host"}
            ), 501
        try:
            text = clipboard_backend.get_text()
        except Exception as exc:
            return jsonify({"ok": False, "error": f"clipboard read failed: {exc}"}), 502
        _log("clipboard read via relay")
        return jsonify({"ok": True, "text": text if isinstance(text, str) else ""})

    # ---- process probe (P2) ----------------------------------------------

    @app.get("/process/<int:pid>")
    def process_state(pid):
        """Read-only process-exit observation; no process control.
        (Mirrors upstream; the snapshot comes from /proc.)"""
        if not 0 < pid <= 0xFFFFFFFF:
            return jsonify({"ok": False, "error": "pid must be a positive DWORD"}), 400
        return jsonify({"ok": True, "pid": pid,
                        **_process_snapshot(proc_root, pid)})

    # ---- file-drop (P2) ----------------------------------------------------
    # Ported from upstream's protocol verbatim where the platform allows:
    # same state machine (begin -> offset-checked chunks -> commit
    # verifies size + sha256, writes via temp file + os.replace), same
    # validation and error strings. Linux adaptations: the allowlist
    # comes from the create_app argument or HANDS_FILEDROP_DIRS (the
    # session app has no upstream-style config file), and _accept uses
    # realpath on POSIX paths. File contents are never logged.

    def _accept_drop_dir(p):
        """Absolute allowlist entries only. Relative entries are
        rejected (not realpath'd against the cwd). Exact path match —
        not a prefix match. (Mirrors upstream.)"""
        text = str(p).strip()
        if not text or not os.path.isabs(text):
            return None
        return os.path.normcase(os.path.realpath(text))

    def resolve_filedrop_dirs():
        if filedrop_dirs is not None:
            source = filedrop_dirs
        else:
            env = os.environ.get("HANDS_FILEDROP_DIRS")
            if env is None or not env.strip():
                return []
            source = env.split(os.pathsep)
        return [d for d in (_accept_drop_dir(p) for p in source) if d]

    def _purge_uploads():
        now = time.time()
        with uploads_lock:
            stale = [uid for uid, up in uploads.items()
                     if now - up["created_at"] > _FILEDROP_TTL]
            for uid in stale:
                del uploads[uid]

    def filedrop_gate():
        """Shared preamble: purge stale uploads, enforce configuration."""
        _purge_uploads()
        if not resolve_filedrop_dirs():
            return (jsonify({"ok": False,
                             "error": "file-drop not configured on the hands"}),
                    501)
        return None

    @app.post("/filedrop/begin")
    def filedrop_begin():
        gate_resp = filedrop_gate()
        if gate_resp is not None:
            return gate_resp
        body = request.get_json(force=True, silent=True) or {}
        folder = body.get("folder")
        filename = body.get("filename")
        size = body.get("size")
        sha256 = body.get("sha256")
        if not isinstance(folder, str) or not folder:
            return jsonify({"ok": False, "error": "folder required"}), 400
        real_folder = os.path.normcase(os.path.realpath(folder))
        if real_folder not in resolve_filedrop_dirs():
            return jsonify({"ok": False, "error": "folder not in file-drop allowlist"}), 403
        if (
            not isinstance(filename, str)
            or not filename
            or "/" in filename
            or "\\" in filename
            or ".." in filename
        ):
            return jsonify({"ok": False, "error": "filename must be a bare name"}), 400
        if (isinstance(size, bool) or not isinstance(size, int)
                or size < 1 or size > _FILEDROP_MAX_SIZE):
            return jsonify({"ok": False, "error": "size must be an integer in 1..16MB"}), 400
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
            return jsonify({"ok": False, "error": "sha256 must be a 64-hex string"}), 400
        upload_id = uuid.uuid4().hex
        with uploads_lock:
            uploads[upload_id] = {
                "id": upload_id,
                "dir": real_folder,
                "filename": filename,
                "size": size,
                "sha256": sha256.lower(),
                "buffer": bytearray(),
                "created_at": time.time(),
            }
        return jsonify({"ok": True, "upload_id": upload_id,
                        "chunk_max": _FILEDROP_CHUNK_MAX})

    @app.post("/filedrop/chunk")
    def filedrop_chunk():
        gate_resp = filedrop_gate()
        if gate_resp is not None:
            return gate_resp
        body = request.get_json(force=True, silent=True) or {}
        upload_id = body.get("upload_id")
        offset = body.get("offset")
        data_b64 = body.get("data_b64")
        with uploads_lock:
            upload = uploads.get(upload_id)
            if upload is None or upload.get("closed"):
                return jsonify({"ok": False, "error": "unknown upload_id"}), 404
            expected = len(upload["buffer"])
            if (isinstance(offset, bool) or not isinstance(offset, int)
                    or offset != expected):
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": "offset mismatch",
                            "expected_offset": expected,
                            "expected": expected,
                        }
                    ),
                    409,
                )
            if not isinstance(data_b64, str):
                return jsonify({"ok": False, "error": "data_b64 required"}), 400
            try:
                chunk = base64.b64decode(data_b64, validate=True)
            except (binascii.Error, ValueError):
                return jsonify({"ok": False, "error": "data_b64 is not valid base64"}), 400
            if expected + len(chunk) > upload["size"]:
                return jsonify({"ok": False, "error": "chunk exceeds declared size"}), 400
            upload["buffer"].extend(chunk)
            received = len(upload["buffer"])
        return jsonify({"ok": True, "received": received, "offset": received})

    @app.post("/filedrop/commit")
    def filedrop_commit():
        gate_resp = filedrop_gate()
        if gate_resp is not None:
            return gate_resp
        body = request.get_json(force=True, silent=True) or {}
        upload_id = body.get("upload_id")
        with uploads_lock:
            upload = uploads.get(upload_id)
            if upload is None or upload.get("closed"):
                return jsonify({"ok": False, "error": "unknown upload_id"}), 404
            # Close under the same lock as chunk append so a concurrent
            # chunk cannot extend a buffer this commit already copied.
            data = bytes(upload["buffer"])
            meta_size = upload["size"]
            meta_sha = upload["sha256"]
            meta_dir = upload["dir"]
            meta_name = upload["filename"]
            upload["closed"] = True
        if len(data) != meta_size:
            with uploads_lock:
                uploads.pop(upload_id, None)
            return jsonify({"ok": False, "error": "incomplete upload: size mismatch"}), 400
        digest = hashlib.sha256(data).hexdigest()
        if digest != meta_sha:
            with uploads_lock:
                uploads.pop(upload_id, None)
            return jsonify({"ok": False, "error": "sha256 mismatch"}), 400
        final_path = os.path.join(meta_dir, meta_name)
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(dir=meta_dir,
                                            prefix=".filedrop-", suffix=".tmp")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp_path, final_path)
            tmp_path = None
        except OSError as exc:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            with uploads_lock:
                upload = uploads.get(upload_id)
                if upload is not None:
                    upload["closed"] = False
            return jsonify({"ok": False, "error": f"write failed: {exc}"}), 500
        with uploads_lock:
            uploads.pop(upload_id, None)
        return jsonify({"ok": True, "path": final_path,
                        "size": len(data), "sha256": digest})

    @app.post("/filedrop/abort")
    def filedrop_abort():
        gate_resp = filedrop_gate()
        if gate_resp is not None:
            return gate_resp
        body = request.get_json(force=True, silent=True) or {}
        upload_id = body.get("upload_id")
        with uploads_lock:
            existed = uploads.pop(upload_id, None) is not None
        if not existed:
            return jsonify({"ok": False, "error": "unknown upload_id"}), 404
        return jsonify({"ok": True})

    # ---- capture -----------------------------------------------------

    @app.get("/screenshot")
    def screenshot():
        monitor_raw = request.args.get("monitor")
        region_raw = request.args.get("region")
        if monitor_raw is not None and region_raw is not None:
            return (
                jsonify({"ok": False, "error": "pass monitor or region, not both"}),
                400,
            )
        rect = None
        monitor_idx = None
        region_rect = None
        if monitor_raw is not None:
            try:
                monitor_idx = int(monitor_raw)
            except ValueError:
                return jsonify({"ok": False, "error": "monitor must be an integer"}), 400
            rects = _monitor_rects(capture_module)
            if monitor_idx < 0 or monitor_idx >= len(rects):
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": f"monitor {monitor_idx} out of range: "
                            f"{len(rects)} monitor(s) available",
                        }
                    ),
                    400,
                )
            rect = rects[monitor_idx]
        elif region_raw is not None:
            region_rect = _parse_region(region_raw)
            if region_rect is None:
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": "region must be 'x,y,w,h' (ints, w and h > 0)",
                        }
                    ),
                    400,
                )
            rect = region_rect
        try:
            data, w, h = _capture_png(capture_module, rect)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"capture failed: {exc}"}), 500
        resp = send_file(io.BytesIO(data), mimetype="image/png")
        resp.headers["X-Screen-Width"] = str(w)
        resp.headers["X-Screen-Height"] = str(h)
        if monitor_idx is not None:
            resp.headers["X-Screen-Monitor"] = str(monitor_idx)
        if region_rect is not None:
            resp.headers["X-Screen-Region"] = (
                f"{region_rect['x']},{region_rect['y']},"
                f"{region_rect['w']},{region_rect['h']}"
            )
        return resp

    # ---- act planning helpers ----------------------------------------

    def human(d):
        h = d.get("human")
        if h is not None:
            return bool(h)
        raw = os.environ.get("HANDS_HUMAN_MOTION")
        if raw is not None and raw.strip():
            return raw.strip().lower() not in ("0", "false", "no", "off")
        return True  # upstream default: human motion ON

    def box(d):
        """Optional target box {w, h} from an act body, else (None, None)."""
        try:
            w = float(d["w"]) if d.get("w") is not None else None
            h = float(d["h"]) if d.get("h") is not None else None
        except (TypeError, ValueError):
            return None, None
        if w is None or h is None or w <= 0 or h <= 0:
            return None, None
        return w, h

    def start_pos(x, y):
        """Tracked pointer position; unknown -> the target itself."""
        if position["x"] is None:
            return x, y
        return position["x"], position["y"]

    def path_steps(x0, y0, x1, y1, width=None, path_seconds=None):
        """motion.plan_move output as guardian move/sleep steps."""
        steps = []
        for sx, sy, delay in motion.plan_move(
            x0, y0, x1, y1, rng, width=width, path_seconds=path_seconds
        ):
            steps.append({"t": "move", "x": int(round(sx)), "y": int(round(sy))})
            if delay and delay > 0:
                steps.append({"t": "sleep", "s": float(delay)})
        return steps

    @staticmethod
    def _sleep(seconds):
        return {"t": "sleep", "s": float(seconds)}

    # ---- act routes ----------------------------------------------------

    @app.post("/move")
    def move():
        d = request.get_json(force=True)
        x, y = int(d["x"]), int(d["y"])
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        with act_lock:
            steps = []
            if human(d):
                w, h = box(d)
                if d.get("attention"):
                    steps.append(
                        _sleep(motion.attention_delay(rng, d.get("text_chars")))
                    )
                x0, y0 = start_pos(x, y)
                steps += path_steps(x0, y0, x, y, width=min(w, h) if w else None)
            else:
                steps.append({"t": "move", "x": x, "y": y})
            refused = send_act("mouse", steps)
            if refused is not None:
                return refused
            position["x"], position["y"] = x, y
        return {"ok": True}

    @app.post("/click")
    def click():
        """Click at (x, y). Human mode (default): optional {w, h} target
        box centred on (x, y) — Gaussian landing inside it, its size
        sets the Fitts speed; optional attention (default true) +
        text_chars hesitation. Timing fits the +0.5 s per-click budget.
        (Mirrors upstream.)"""
        d = request.get_json(force=True)
        x, y = int(d["x"]), int(d["y"])
        button = d.get("button", "left")
        if button not in _BUTTONS:
            return (
                jsonify({"ok": False, "error": "button must be left, middle or right"}),
                400,
            )
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        with act_lock:
            if not human(d):
                steps = [
                    {"t": "move", "x": x, "y": y},
                    {"t": "button", "button": button, "down": True},
                    {"t": "button", "button": button, "down": False},
                ]
                refused = send_act("mouse", steps)
                if refused is not None:
                    return refused
                position["x"], position["y"] = x, y
                return {"ok": True}
            w, h = box(d)
            x0, y0 = start_pos(x, y)
            tx, ty = motion.landing_point(x, y, w, h, rng) if w else (x, y)
            dist = math.hypot(tx - x0, ty - y0)
            attention = (
                motion.attention_delay(rng, d.get("text_chars"))
                if d.get("attention", True)
                else 0.0
            )
            travel = (
                motion.fitts_duration(dist, min(w, h) if w else None, rng)
                if dist >= 4
                else 0.02
            )
            hover = motion.hover_delay(rng)
            hold = motion.click_hold(rng)
            attention, travel, hover, hold = motion.fit_click_timing(
                dist, attention, travel, hover, hold
            )
            steps = []
            if attention:
                steps.append(_sleep(attention))
            steps += path_steps(x0, y0, tx, ty, path_seconds=travel)
            if hover:
                steps.append(_sleep(hover))
            steps.append({"t": "button", "button": button, "down": True})
            if hold:
                steps.append(_sleep(hold))
            steps.append({"t": "button", "button": button, "down": False})
            refused = send_act("mouse", steps)
            if refused is not None:
                return refused
            position["x"], position["y"] = tx, ty
        return {
            "ok": True,
            "x": tx,
            "y": ty,
            "timing": {
                "attention": round(attention, 3),
                "travel": round(travel, 3),
                "hover": round(hover, 3),
                "hold": round(hold, 3),
                "budget": round(motion.click_budget(dist), 3),
            },
        }

    @app.post("/drag")
    def drag():
        """Press the mouse button at (x1, y1), drag to (x2, y2), release.
        (Mirrors upstream, including its validation messages.)"""
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        d = request.get_json(force=True, silent=True) or {}
        try:
            x1, y1, x2, y2 = (int(d[k]) for k in ("x1", "y1", "x2", "y2"))
        except (KeyError, TypeError, ValueError):
            return jsonify({"ok": False, "error": "x1, y1, x2, y2 must be integers"}), 400
        button = d.get("button", "left")
        if button not in _BUTTONS:
            return (
                jsonify({"ok": False, "error": "button must be left, middle or right"}),
                400,
            )
        try:
            duration = float(d["duration"]) if d.get("duration") is not None else None
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "duration must be a number"}), 400
        with act_lock:
            steps = []
            if human(d):
                x0, y0 = start_pos(x1, y1)
                steps += path_steps(x0, y0, x1, y1)
                steps.append(_sleep(motion.hover_delay(rng)))
                steps.append({"t": "button", "button": button, "down": True})
                steps.append(_sleep(motion.click_hold(rng)))
                steps += path_steps(x1, y1, x2, y2, path_seconds=duration)
                steps.append({"t": "button", "button": button, "down": False})
            else:
                steps.append({"t": "move", "x": x1, "y": y1})
                steps.append({"t": "button", "button": button, "down": True})
                steps.append({"t": "move", "x": x2, "y": y2})
                steps.append({"t": "button", "button": button, "down": False})
            refused = send_act("mouse", steps)
            if refused is not None:
                return refused
            position["x"], position["y"] = x2, y2
        return {"ok": True}

    @app.post("/scroll")
    def scroll():
        """Scroll by clicks. Human mode: variable 1-3 click chunks with
        30-120 ms pauses instead of one jump; the total is exact.
        (Mirrors upstream.)"""
        d = request.get_json(force=True)
        clicks = int(d.get("clicks", 3))
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        with act_lock:
            steps = []
            if human(d):
                for chunk, pause in motion.plan_scroll(clicks, rng):
                    steps.append({"t": "scroll", "dy": int(chunk), "dx": 0})
                    if pause:
                        steps.append(_sleep(pause))
            else:
                steps.append({"t": "scroll", "dy": clicks, "dx": 0})
            refused = send_act("mouse", steps)
            if refused is not None:
                return refused
        return {"ok": True}

    @app.post("/key")
    def key():
        d = request.get_json(force=True)
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        with act_lock:
            refused = send_act("keys", [{"t": "key", "key": d["key"]}])
            if refused is not None:
                return refused
        return {"ok": True}

    @app.post("/hotkey")
    def hotkey():
        """Press a true key chord, e.g. {"keys": ["ctrl", "l"]}.
        Keydowns in order, keyups in reverse (pyautogui.hotkey shape)."""
        d = request.get_json(force=True, silent=True) or {}
        keys = d.get("keys")
        if (
            not isinstance(keys, list)
            or not keys
            or not all(isinstance(k, str) and k.strip() for k in keys)
        ):
            return (
                jsonify(
                    {"ok": False, "error": "keys must be a non-empty list of strings"}
                ),
                400,
            )
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        steps = [{"t": "keydown", "key": k} for k in keys]
        steps += [{"t": "keyup", "key": k} for k in reversed(keys)]
        with act_lock:
            refused = send_act("keys", steps)
            if refused is not None:
                return refused
        return {"ok": True}

    @app.post("/break")
    def break_():
        """Send Ctrl+C as a true chord, 1..3 times (default 1), 0.15 s
        apart. (Mirrors upstream.)"""
        d = request.get_json(force=True, silent=True) or {}
        times = d.get("times", 1)
        if isinstance(times, bool) or not isinstance(times, int) or not 1 <= times <= 3:
            return jsonify({"ok": False, "error": "times must be an integer 1..3"}), 400
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        steps = []
        for i in range(times):
            steps.append({"t": "keydown", "key": "ctrl"})
            steps.append({"t": "keydown", "key": "c"})
            steps.append({"t": "keyup", "key": "c"})
            steps.append({"t": "keyup", "key": "ctrl"})
            if i < times - 1:
                steps.append(_sleep(0.15))
        with act_lock:
            refused = send_act("keys", steps)
            if refused is not None:
                return refused
        return {"ok": True, "times": times}

    @app.post("/type")
    def type_text():
        """Type text: clipboard paste for long payloads, jittered keys else.

        {text, method?: "auto"|"paste"|"keys", jitter?: bool}

        Method (mirrors upstream _type_dispatch): "auto" pastes when
        the text is over 120 chars and a clipboard backend exists;
        "paste" forces that path; "keys" forces keystrokes. The paste
        path saves the current clipboard, sets the text, sends Ctrl+V
        as a guardian act (injection stays in the guardian — the
        clipboard itself injects nothing), gives the target a beat,
        then restores the saved clipboard. A clipboard failure on the
        paste path falls back to keystrokes with a "note" (upstream's
        contract). With NO clipboard backend injected, "paste" is a
        clear 501 and "auto" always takes the keystroke path.

        The keystroke delay plan mirrors upstream _plan_key_delays;
        the session sends one type step per character with a sleep
        step after it, keeping the guardian dumb and the plan
        identical to upstream's. jitter false restores a flat 0.02 s
        per-character interval.

        Response mirrors upstream: {"ok", "method_used", "chars",
        "elapsed_seconds", "delays_planned", "planned_seconds"} — the
        delay fields describe the keystroke plan (0 on the paste
        path); a fallback adds "note".
        """
        d = request.get_json(force=True, silent=True) or {}
        text = d.get("text")
        if not isinstance(text, str):
            return jsonify({"ok": False, "error": "text must be a string"}), 400
        method = d.get("method", "auto")
        if method not in ("auto", "paste", "keys"):
            return (
                jsonify({"ok": False, "error": "method must be auto, paste or keys"}),
                400,
            )
        if method == "paste" and clipboard_backend is None:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "paste is not available: no clipboard "
                        "backend on this host — use method \"keys\"",
                    }
                ),
                501,
            )
        jitter = bool(d.get("jitter", True))
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        started = time.monotonic()

        def keys_path():
            """(delays, refusal) — refusal is a Flask response or None."""
            if jitter:
                delays = _plan_key_delays(text, rng)
                gaps = delays
            else:
                delays = []
                gaps = [0.02] * len(text)
            steps = []
            for ch, gap in zip(text, gaps):
                steps.append({"t": "type", "text": ch})
                steps.append(_sleep(gap))
            with act_lock:
                refusal = send_act("keys", steps)
            return delays, refusal

        def paste_path():
            """None on success; raises on clipboard failure. A guardian
            refusal of the Ctrl+V act is returned, not raised (keys
            would be refused identically — falling back is pointless)."""
            saved, readable = None, False
            try:
                saved = clipboard_backend.get_text()
                readable = True
            except Exception:
                pass  # unreadable clipboard: paste anyway, skip restore
            try:
                clipboard_backend.set_text(text)
                steps = [
                    {"t": "keydown", "key": "ctrl"},
                    {"t": "keydown", "key": "v"},
                    {"t": "keyup", "key": "v"},
                    {"t": "keyup", "key": "ctrl"},
                ]
                with act_lock:
                    refusal = send_act("keys", steps)
                if refusal is not None:
                    return refusal
                if readable:
                    # Give the target app a beat to consume the paste
                    # before the previous clipboard contents go back.
                    time.sleep(0.1)
                return None
            finally:
                if readable and saved is not None:
                    try:
                        clipboard_backend.set_text(saved)
                    except Exception:
                        pass

        # Dispatch (upstream _type_dispatch semantics).
        method_used = "keys"
        note = None
        delays = []
        want_paste = method == "paste" or (
            method == "auto" and clipboard_backend is not None and len(text) > 120
        )
        if want_paste:
            try:
                refusal = paste_path()
                if refusal is not None:
                    return refusal
                method_used = "paste"
            except Exception as exc:
                if method == "paste":
                    note = f"paste requested but unavailable ({exc}); used keys"
                else:
                    note = f"paste failed ({exc}); used keys"
                delays, refusal = keys_path()
                if refusal is not None:
                    return refusal
        else:
            delays, refusal = keys_path()
            if refusal is not None:
                return refusal
        body = {
            "ok": True,
            "method_used": method_used,
            "chars": len(text),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "delays_planned": len(delays),
            "planned_seconds": sum(delays),
        }
        if note:
            body["note"] = note
        return jsonify(body)

    return app


# ---- entry point ---------------------------------------------------------


class _MissingCapture:
    """Placeholder when the packaged capture module is unavailable:
    /screenshot fails loudly, everything else still runs for P1 dev."""

    def monitor_rects(self):
        raise RuntimeError("capture module (capture.py) is not installed")

    def capture_png(self, rect):
        raise RuntimeError("capture module (capture.py) is not installed")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import guardian_client as guardian_client_module

        sock = os.environ.get("HANDS_GUARDIAN_SOCKET")
        guardian = (guardian_client_module.GuardianClient(sock) if sock
                    else guardian_client_module.GuardianClient())
    except Exception:
        guardian = SocketGuardianClient()
    try:
        import capture as capture_module
    except Exception:
        _log("WARNING: capture.py not importable; /screenshot will 500")
        capture_module = _MissingCapture()
    # P2 backends: each degrades to None (= the route's 501 /
    # "supported": false surface) when its module can't load; the KWin
    # and wl-clipboard backends only touch D-Bus/subprocesses when a
    # route actually calls them.
    windows_backend = None
    try:
        import windows_kwin

        windows_backend = windows_kwin.KWinWindowsBackend()
    except Exception:
        _log("WARNING: windows_kwin.py not importable; window routes degraded")
    clipboard_backend = None
    try:
        import clipboard_wl

        clipboard_backend = clipboard_wl.WlClipboard()
    except Exception:
        _log("WARNING: clipboard_wl.py not importable; clipboard routes 501")
    # Keep-awake defaults ON while the app runs (upstream parity);
    # HANDS_KEEP_AWAKE=0/false/no/off disables it.
    keep_awake_enabled = (
        os.environ.get("HANDS_KEEP_AWAKE", "").strip().lower()
        not in ("0", "false", "no", "off")
    )
    keep_awake_obj = None
    if keep_awake_enabled:
        try:
            import keepawake

            keep_awake_obj = keepawake.default_keep_awake()
        except Exception:
            _log("WARNING: keepawake.py not importable; keep-awake off")
            keep_awake_enabled = False
    app = create_app(
        guardian,
        capture_module,
        windows_backend=windows_backend,
        clipboard_backend=clipboard_backend,
        keep_awake=keep_awake_obj,
        keep_awake_enabled=keep_awake_enabled,
    )
    # The packaged app displays the per-launch secret in its window;
    # for P1 dev the stdout line is where an operator copies it from.
    # HANDS_BIND exists so a deliberate, owner-launched instance can
    # listen on the tailnet address; the default stays loopback.
    print(f"SECRET {app.hands_secret}", flush=True)
    app.run(host=os.environ.get("HANDS_BIND", "127.0.0.1"), port=PORT)


if __name__ == "__main__":
    main()
