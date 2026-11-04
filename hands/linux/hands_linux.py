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
route except /health and /state answer 423 {"error_code":
"emergency_stop"}.

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
"""

import io
import json
import math
import os
import random
import secrets as secrets_mod
import socket
import struct
import subprocess
import sys
import threading
import time

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


def create_app(guardian_client, capture_module, secret=None, rng=None):
    """Build the Flask app around injected guardian/capture backends."""
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
        }
        if st is None:
            body["guardian"] = "unreachable"
        else:
            body["stopped_reason"] = st.get("reason")
            body["stopped_since"] = st.get("since")
        return body

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
        """Type text with jittered per-character steps.

        {text, method?: "auto"|"paste"|"keys", jitter?: bool}

        P1 has no clipboard backend, so "paste" is a clear 501 and
        "auto" always takes the keystroke path (upstream only pastes
        when a backend exists). The delay plan mirrors upstream
        _plan_key_delays; the session sends one type step per character
        with a sleep step after it, keeping the guardian dumb and the
        plan identical to upstream's. jitter false restores a flat
        0.02 s per-character interval.

        Response mirrors upstream's keystroke-path body:
        {"ok", "method_used", "chars", "elapsed_seconds",
        "delays_planned", "planned_seconds"}.
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
        if method == "paste":
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "paste is not available in P1: the clipboard "
                        "backend lands in P2 — use method \"keys\"",
                    }
                ),
                501,
            )
        jitter = bool(d.get("jitter", True))
        refused = yield_if_owner_active()
        if refused is not None:
            return refused
        started = time.monotonic()
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
            refused = send_act("keys", steps)
            if refused is not None:
                return refused
        return jsonify(
            {
                "ok": True,
                "method_used": "keys",
                "chars": len(text),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "delays_planned": len(delays),
                "planned_seconds": sum(delays),
            }
        )

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
    app = create_app(guardian, capture_module)
    # The packaged app displays the per-launch secret in its window;
    # for P1 dev the stdout line is where an operator copies it from.
    print(f"SECRET {app.hands_secret}", flush=True)
    app.run(host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    main()
