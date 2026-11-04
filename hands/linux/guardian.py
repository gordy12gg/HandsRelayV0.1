#!/usr/bin/env python3
"""HandsRelay guardian — the root-owned half of the Linux port (P1).

Run as a systemd *system* service (User=root). The guardian owns every
piece of the safety story from SCOPE.md §3 / DESIGN-P1.md:

  * the emergency-stop **latch** — always STOPPED at startup, whatever
    the persisted record says (fail-safe: a crash or restart can never
    silently restore actuation);
  * **all input injection**, through its actuator (actuator.py) — the
    session component holds no injection capability of its own;
  * the **evdev panic listener** (default Ctrl+Alt+Esc) — fires even if
    KWin or the session app is hung, because it reads /dev/input
    directly as root;
  * the **owner-activity monitor** — evdev events on *physical* devices
    only, so injected input never masquerades as the owner being active.

IPC: JSON lines over a unix socket. Peer UID is taken from SO_PEERCRED
on every connection; only the configured session UID and root are
served at all, and `resume` is refused unless the peer UID is 0 — the
only path to a resume is the polkit helper (packaging/handsrelay-
resume), which runs as root after *fresh* admin authentication
(auth_admin, no _keep retention). There is deliberately no way for the
session UID to clear a stop.

No KDE / D-Bus imports: the guardian must work even when the session's
compositor stack does not.

Usage: python3 guardian.py [--config /etc/handsrelay-guardian/config.json]
"""

import argparse
import grp
import json
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

# actuator.py sits next to this file, whether we are run as a script
# from the repo or installed into /usr/lib/handsrelay.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from actuator import (  # noqa: E402
    ActuatorError,
    EisActuator,
    FakeActuator,
    YdotoolActuator,
    keycode_for,
)

log = logging.getLogger("handsrelay-guardian")

DEFAULT_CONFIG_PATH = "/etc/handsrelay-guardian/config.json"

DEFAULTS = {
    # The interactive user's UID — the only non-root peer served.
    "session_uid": 1000,
    # Panic combo, as step-list key names (actuator.keycode_for).
    "panic_keys": ["ctrl", "alt", "esc"],
    # Device-name substrings (case-insensitive) treated as *virtual*:
    # their events never count as owner activity and never trip panic.
    "virtual_device_name_patterns": ["ydotool", "libei", "eis", "virtual"],
    # The guardian's private ydotoold.
    "ydotoold_socket": "/run/handsrelay-guardian/ydotoold.sock",
    "ydotoold_autostart": True,
    # This daemon's IPC socket.
    "guardian_socket": "/run/handsrelay-guardian/guardian.sock",
    "socket_group": "handsrelay",
    # Which actuator to drive: "ydotool" (P1), "eis" (stub), "fake".
    "actuator": "ydotool",
    # Latch record lives here (root-owned; see StateDirectory in unit).
    "state_dir": "/var/lib/handsrelay-guardian",
}

MAX_SLEEP_STEP = 2.0  # seconds; per DESIGN-P1.md a sleep step is capped


def load_config(path):
    """Load root-owned JSON config over DEFAULTS.

    A missing or unparseable config must never leave the box without a
    stop owner, so on any error we fall back to defaults and log loudly.
    (Defaults keep the latch stopped, like everything else here.)
    """
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        try:
            with open(path) as f:
                user_cfg = json.load(f)
            if isinstance(user_cfg, dict):
                cfg.update(user_cfg)
            else:
                log.error("config %s is not a JSON object; using defaults",
                          path)
        except Exception as e:
            log.error("cannot parse config %s (%s); using defaults", path, e)
    else:
        log.warning("no config at %s; using defaults", path)
    return cfg


# ---------------------------------------------------------------------------
# The latch
# ---------------------------------------------------------------------------

class Latch:
    """The emergency-stop latch: in memory, mirrored to a JSON record.

    Starts STOPPED unconditionally. The persisted file is a diagnostic
    record (why/when the last change happened), never a source of truth
    to restore "running" from — after any restart, actuation stays off
    until a local, authenticated resume.
    """

    def __init__(self, record_path):
        self._lock = threading.Lock()
        self._record_path = record_path
        self._stopped = True
        self._reason = "startup: fail-safe stopped"
        self._since = time.time()
        self._persist()

    def snapshot(self):
        with self._lock:
            return {"stopped": self._stopped,
                    "reason": self._reason,
                    "since": self._since}

    def is_stopped(self):
        with self._lock:
            return self._stopped

    def trip(self, reason):
        """Set the latch. Returns True if this call changed the state."""
        with self._lock:
            changed = not self._stopped
            self._stopped = True
            self._reason = reason
            self._since = time.time()
            self._persist()
            return changed

    def clear(self):
        with self._lock:
            self._stopped = False
            self._reason = None
            self._since = time.time()
            self._persist()

    def _persist(self):
        # Called with the lock held (and once from __init__). Atomic
        # replace so a crash mid-write can't leave a torn record.
        if not self._record_path:
            return
        try:
            os.makedirs(os.path.dirname(self._record_path), exist_ok=True)
            tmp = self._record_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"stopped": self._stopped,
                           "reason": self._reason,
                           "since": self._since}, f)
            os.replace(tmp, self._record_path)
        except Exception as e:
            log.error("cannot persist latch record: %s", e)


# ---------------------------------------------------------------------------
# evdev monitor: panic combo + owner activity
# ---------------------------------------------------------------------------

class EvdevMonitor(threading.Thread):
    """Watches physical input devices.

    The panic listener and the owner-activity monitor share one reader:
    an evdev fd cannot be read by two threads without splitting the
    event stream, so a single thread per device feeds both concerns.
    Virtual devices (ydotool / libei / EIS — i.e. injected input) are
    never opened, so our own actuation can neither trip the panic combo
    nor fake owner activity.

    Degrades gracefully: if python-evdev is missing or no device can be
    opened, the thread simply doesn't run — the latch, IPC and stop
    sweep are unaffected; only the panic combo and activity signal are
    lost, and that is logged at startup.
    """

    def __init__(self, guardian):
        super().__init__(daemon=True, name="evdev-monitor")
        self.guardian = guardian
        self._patterns = [p.lower() for p in
                          guardian.config["virtual_device_name_patterns"]]
        self._down = set()  # evdev keycodes currently held (all devices)
        try:
            self._panic_codes = frozenset(
                keycode_for(k) for k in guardian.config["panic_keys"])
        except Exception as e:
            log.error("bad panic_keys in config (%s); panic combo disabled",
                      e)
            self._panic_codes = frozenset()

    def _is_virtual(self, name):
        n = (name or "").lower()
        return any(p in n for p in self._patterns)

    def run(self):
        try:
            import evdev
        except ImportError:
            log.warning("python-evdev not available; panic listener and "
                        "owner-activity monitor disabled (latch and IPC "
                        "unaffected)")
            return
        devices = []
        for path in evdev.list_devices():
            try:
                dev = evdev.InputDevice(path)
            except Exception as e:
                log.warning("cannot open %s: %s", path, e)
                continue
            if self._is_virtual(dev.name):
                log.info("ignoring virtual device: %s (%s)", dev.name, path)
                dev.close()
                continue
            log.info("monitoring physical device: %s (%s)", dev.name, path)
            devices.append(dev)
        if not devices:
            log.warning("no physical input devices could be opened; "
                        "panic/activity monitoring inactive")
            return
        # One blocking reader thread per device, all feeding _on_event.
        # (Devices are opened once at startup; hotplug is a P-future
        # concern — a replugged device is picked up on guardian restart.)
        for dev in devices:
            t = threading.Thread(target=self._read_loop, args=(dev,),
                                 daemon=True, name="evdev-%s" % dev.name)
            t.start()
        # Keep this thread alive so the monitor's lifetime is visible.
        while not self.guardian.shutdown.is_set():
            time.sleep(1.0)

    def _read_loop(self, dev):
        try:
            import evdev  # already imported in run(); cheap re-import
            for event in dev.read_loop():
                if self.guardian.shutdown.is_set():
                    return
                self._on_event(event)
        except OSError as e:
            log.warning("device %s stopped: %s", dev.path, e)
        except Exception as e:
            log.error("evdev reader for %s died: %s", dev.path, e)

    def _on_event(self, event):
        # Any event from a physical device is owner activity.
        self.guardian.note_owner_activity()
        if not self._panic_codes:
            return
        # EV_KEY == 1 in evdev.ecodes; avoid a hard ecodes import here.
        if event.type != 1:
            return
        if event.value == 1:      # key down
            self._down.add(event.code)
        elif event.value == 0:    # key up
            self._down.discard(event.code)
        else:                     # autorepeat — not a state change
            return
        if self._panic_codes and self._panic_codes.issubset(self._down):
            # Clear the tracked set so a held combo doesn't re-trip in a
            # loop; trip() is idempotent anyway.
            self._down.clear()
            log.warning("panic combo pressed — emergency stop")
            self.guardian.trip_stop("panic combo")


# ---------------------------------------------------------------------------
# The guardian
# ---------------------------------------------------------------------------

class Guardian:
    def __init__(self, config):
        self.config = config
        self.shutdown = threading.Event()
        state_dir = config["state_dir"]
        self.latch = Latch(os.path.join(state_dir, "latch.json")
                           if state_dir else None)
        self.actuator = self._make_actuator()
        self._act_lock = threading.Lock()   # acts are mutex-serialized
        self._started_at = time.time()
        # Owner-activity baseline: until the first physical event, idle
        # counts from daemon start (conservative — and we start stopped
        # anyway, so this can only ever delay actuation, never enable it
        # early).
        self._last_activity = self._started_at
        self._activity_lock = threading.Lock()
        self._ydotoold_proc = None

    # -- setup -----------------------------------------------------------

    def _make_actuator(self):
        kind = str(self.config.get("actuator", "ydotool")).lower()
        if kind == "fake":
            return FakeActuator()
        if kind == "eis":
            return EisActuator()
        return YdotoolActuator(self.config["ydotoold_socket"])

    def _maybe_start_ydotoold(self):
        """Start the guardian's private ydotoold if configured to.

        The daemon is ours alone: its socket lives in the guardian's
        runtime dir with 0660 perms, and the interactive user is not in
        the input group, so this socket is the only injection path.
        """
        if not self.config.get("ydotoold_autostart", True):
            return
        if not isinstance(self.actuator, YdotoolActuator):
            return
        sock = self.config["ydotoold_socket"]
        if os.path.exists(sock):
            log.info("ydotoold socket already present: %s", sock)
            return
        try:
            self._ydotoold_proc = subprocess.Popen(
                ["ydotoold", "--socket-path=%s" % sock,
                 "--socket-perm=0660"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
        except FileNotFoundError:
            log.error("ydotoold binary not found; actuator calls will "
                      "fail until it is installed")
            return
        except Exception as e:
            log.error("cannot start ydotoold: %s", e)
            return
        for _ in range(40):  # wait up to ~2 s for the socket to appear
            if os.path.exists(sock):
                log.info("ydotoold started (pid %d), socket %s",
                         self._ydotoold_proc.pid, sock)
                return
            time.sleep(0.05)
        log.error("ydotoold started but socket %s never appeared", sock)

    # -- owner activity ----------------------------------------------------

    def note_owner_activity(self):
        with self._activity_lock:
            self._last_activity = time.time()

    def idle_seconds(self):
        with self._activity_lock:
            return max(0.0, time.time() - self._last_activity)

    # -- the latch ---------------------------------------------------------

    def trip_stop(self, source):
        """Latch the stop and sweep every held key/button up.

        Safe to call from any thread (IPC, panic listener) and any
        number of times. The sweep runs outside the act lock on purpose:
        a stop must not queue behind a long act.
        """
        changed = self.latch.trip("stop via %s" % source)
        if changed:
            log.warning("EMERGENCY STOP latched (source: %s)", source)
        try:
            n = self.actuator.release_all()
            if n:
                log.info("stop sweep released %d held input(s)", n)
        except Exception as e:
            log.error("stop sweep failed: %s", e)

    def resume(self):
        self.latch.clear()
        log.warning("guardian RESUMED by root helper (polkit-authenticated)")

    # -- act execution -------------------------------------------------------

    def execute_act(self, steps):
        """Execute one act's step list serially.

        The latch is checked before the first step and between every
        pair of steps; if it trips mid-act, remaining steps are dropped
        and whatever is held is swept. After a *successful* act, any
        input still held is also swept: well-formed plans pair every
        keydown with a keyup inside the same act (DESIGN-P1.md), so a
        leftover means a malformed plan, and a stuck key is never an
        acceptable outcome.
        """
        if not isinstance(steps, list):
            return {"ok": False, "error": "steps must be a list"}
        with self._act_lock:
            if self.latch.is_stopped():
                return {"ok": False, "error_code": "emergency_stop"}
            try:
                for step in steps:
                    if self.latch.is_stopped():
                        self.actuator.release_all()
                        return {"ok": False,
                                "error_code": "emergency_stop"}
                    self._execute_step(step)
            except (ActuatorError, KeyError, ValueError, TypeError) as e:
                # A failed act must not leave inputs down either.
                try:
                    self.actuator.release_all()
                except Exception:
                    pass
                return {"ok": False, "error": str(e)}
            keys, buttons = self.actuator.held()
            if keys or buttons:
                log.warning("act ended with inputs still held "
                            "(keys=%s buttons=%s); sweeping", keys, buttons)
                self.actuator.release_all()
            return {"ok": True}

    def _execute_step(self, step):
        t = step.get("t")
        a = self.actuator
        if t == "move":
            a.move(step["x"], step["y"])
        elif t == "sleep":
            # Capped per step; slept in slices so a stop lands fast.
            remaining = min(float(step.get("s", 0)), MAX_SLEEP_STEP)
            while remaining > 0:
                if self.latch.is_stopped():
                    return
                time.sleep(min(remaining, 0.05))
                remaining -= 0.05
        elif t == "button":
            a.button(step["button"], bool(step["down"]))
        elif t == "scroll":
            a.scroll(step.get("dx", 0), step.get("dy", 0))
        elif t == "key":
            code = keycode_for(step["key"])
            a.key(code, True)
            a.key(code, False)
        elif t == "keydown":
            a.key(keycode_for(step["key"]), True)
        elif t == "keyup":
            a.key(keycode_for(step["key"]), False)
        elif t == "type":
            a.type_text(step.get("text", ""))
        else:
            raise ValueError("unknown step type: %r" % (t,))

    # -- IPC -----------------------------------------------------------------

    def handle_request(self, req, peer_uid):
        op = req.get("op")
        if op == "state":
            s = self.latch.snapshot()
            return {"ok": True, "stopped": s["stopped"],
                    "reason": s["reason"], "since": s["since"]}
        if op == "activity":
            return {"ok": True, "idle_seconds": self.idle_seconds()}
        if op == "act":
            # Defense in depth: the latch check lives in execute_act,
            # before and between steps; this is the same code path the
            # session app hits, so there is no way to act while stopped.
            return self.execute_act(req.get("steps"))
        if op == "stop":
            self.trip_stop(req.get("source", "api"))
            return {"ok": True, "stopped": True}
        if op == "resume":
            # ONLY root may resume — the polkit helper runs as root
            # after fresh admin auth. The session UID can *request*
            # nothing here; this refusal is the whole point of the
            # split.
            if peer_uid != 0:
                return {"ok": False,
                        "error": "resume requires polkit helper"}
            self.resume()
            return {"ok": True, "stopped": False}
        return {"ok": False, "error": "unknown op: %r" % (op,)}

    def _peer_uid(self, conn):
        # SO_PEERCRED: struct ucred { pid_t, uid_t, gid_t }.
        cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                               struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", cred)
        return uid

    def _serve_conn(self, conn):
        try:
            uid = self._peer_uid(conn)
            if uid != 0 and uid != int(self.config["session_uid"]):
                log.warning("refused IPC connection from uid %d", uid)
                conn.sendall(b'{"ok":false,"error":"unauthorized peer"}\n')
                return
            f = conn.makefile("rb")
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line.decode("utf-8"))
                except Exception:
                    conn.sendall(b'{"ok":false,"error":"invalid json"}\n')
                    return
                try:
                    resp = self.handle_request(req, uid)
                except Exception as e:  # never hang a client on a crash
                    log.exception("request handler failed")
                    resp = {"ok": False, "error": str(e)}
                conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        except Exception as e:
            log.debug("IPC connection ended: %s", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def serve(self):
        sock_path = self.config["guardian_socket"]
        os.makedirs(os.path.dirname(sock_path), exist_ok=True)
        if os.path.exists(sock_path):
            os.unlink(sock_path)  # stale socket from a previous run
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        # 0660 + group handsrelay: the session app (in that group, via
        # its service user) can connect; nobody else can. Root ignores
        # perms regardless — SO_PEERCRED is still checked on every
        # connection, perms are just the first fence.
        os.chmod(sock_path, 0o660)
        group = self.config.get("socket_group")
        if group:
            try:
                os.chown(sock_path, -1, grp.getgrnam(group).gr_gid)
            except KeyError:
                log.warning("group %r does not exist; socket stays "
                            "root-group (session app may not connect "
                            "until the group exists)", group)
        srv.listen(16)
        srv.settimeout(0.5)
        log.info("guardian listening on %s (session_uid=%s, actuator=%s)",
                 sock_path, self.config["session_uid"], self.actuator.name)
        while not self.shutdown.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_conn, args=(conn,),
                             daemon=True, name="ipc-conn").start()
        srv.close()
        log.info("guardian shutting down")

    # -- lifecycle -----------------------------------------------------------

    def run(self):
        self._maybe_start_ydotoold()
        EvdevMonitor(self).start()
        log.warning("guardian up — latch is STOPPED (fail-safe); a local "
                    "polkit-authenticated resume is required before any "
                    "actuation")
        self.serve()
        return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="HandsRelay guardian daemon")
    ap.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                    help="path to root-owned JSON config "
                         "(default: %(default)s)")
    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    guardian = Guardian(load_config(args.config))

    def _sigterm(_signum, _frame):
        guardian.shutdown.set()

    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)
    return guardian.run()


if __name__ == "__main__":
    sys.exit(main())
