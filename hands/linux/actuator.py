"""Actuators for the HandsRelay Linux port (P1).

The guardian owns exactly one actuator; it is the *only* input-injection
path in the port (DESIGN-P1.md / SCOPE.md §3). The session component
never imports this module for injection — it sends act step lists to the
guardian over IPC and the guardian drives the actuator.

Interface (per DESIGN-P1.md):

    class Actuator:
        def move(self, x, y): ...
        def button(self, button, down): ...   # button: "left"|"right"|"middle"
        def scroll(self, dx, dy): ...         # wheel clicks, pyautogui sign
        def key(self, evdev_keycode, down): ...
        def type_text(self, text): ...
        def position(self): -> (x, y) | None

Scroll sign convention: steps follow upstream's pyautogui semantics —
positive dy scrolls *up*, positive dx scrolls *right*. evdev REL_WHEEL /
REL_HWHEEL use the same signs, so the ydotool actuator passes the values
through unchanged (this is the "ydotool sign convention handled in the
actuator" the design calls for: there is no flip, and it is pinned here
so nobody "fixes" it later).

Held-state tracking lives in the base class: every concrete primitive
reports key/button transitions through _note_key/_note_button, and
release_all() — the emergency-stop sweep — releases exactly what is
tracked as down. A stopped system must never leave a key or button
physically held, so the sweep is implemented once, here, and shared by
every actuator.
"""

import os
import subprocess
import threading

__all__ = [
    "Actuator",
    "ActuatorError",
    "YdotoolActuator",
    "EisActuator",
    "FakeActuator",
    "KEY_NAME_TO_CODE",
    "keycode_for",
]


class ActuatorError(RuntimeError):
    """An actuator operation failed (e.g. the ydotool CLI errored)."""


# --------------------------------------------------------------------------
# Key names -> evdev keycodes (linux/input-event-codes.h)
#
# Step lists name keys ("enter", "ctrl", "f5", "a", ...); the guardian
# resolves names through keycode_for() and hands raw keycodes to the
# actuator. Only unambiguous names are mapped (DESIGN-P1.md).
# --------------------------------------------------------------------------

def _build_key_map():
    m = {}
    # Letters (evdev QWERTY positions).
    for name, code in (
        ("q", 16), ("w", 17), ("e", 18), ("r", 19), ("t", 20),
        ("y", 21), ("u", 22), ("i", 23), ("o", 24), ("p", 25),
        ("a", 30), ("s", 31), ("d", 32), ("f", 33), ("g", 34),
        ("h", 35), ("j", 36), ("k", 37), ("l", 38),
        ("z", 44), ("x", 45), ("c", 46), ("v", 47), ("b", 48),
        ("n", 49), ("m", 50),
    ):
        m[name] = code
    # Digits.
    for i, code in enumerate((11, 2, 3, 4, 5, 6, 7, 8, 9, 10)):
        m[str(i)] = code  # "0"->11, "1"->2, ..., "9"->10
    # Function keys.
    for i in range(1, 13):
        m["f%d" % i] = (59 + i - 1) if i <= 10 else (87 + i - 11)
    # Named keys.
    m.update({
        "enter": 28, "return": 28,
        "tab": 15,
        "esc": 1, "escape": 1,
        "space": 57,
        "backspace": 14,
        "ctrl": 29, "control": 29, "leftctrl": 29, "rightctrl": 97,
        "alt": 56, "leftalt": 56, "rightalt": 100,
        "shift": 42, "leftshift": 42, "rightshift": 54,
        "super": 125, "meta": 125, "win": 125, "leftmeta": 125,
        "rightmeta": 126,
        "capslock": 58,
        # Arrows.
        "up": 103, "down": 108, "left": 105, "right": 106,
        "arrowup": 103, "arrowdown": 108,
        "arrowleft": 105, "arrowright": 106,
        # Navigation cluster.
        "home": 102, "end": 107,
        "pageup": 104, "pgup": 104, "pagedown": 109, "pgdn": 109,
        "insert": 110, "ins": 110, "delete": 111, "del": 111,
        # Punctuation, by name where unambiguous.
        "minus": 12, "equal": 13, "equals": 13,
        "leftbracket": 26, "rightbracket": 27,
        "backslash": 43,
        "semicolon": 39, "apostrophe": 40, "quote": 40,
        "grave": 41, "backtick": 41,
        "comma": 51, "dot": 52, "period": 52, "slash": 53,
    })
    # Single punctuation characters map to the same codes.
    for ch, name in (
        ("-", "minus"), ("=", "equal"), ("[", "leftbracket"),
        ("]", "rightbracket"), ("\\", "backslash"), (";", "semicolon"),
        ("'", "apostrophe"), ("`", "grave"), (",", "comma"),
        (".", "dot"), ("/", "slash"), (" ", "space"),
    ):
        m[ch] = m[name]
    return m


KEY_NAME_TO_CODE = _build_key_map()

# Modifier keycodes, for callers that need to reason about chords.
MODIFIER_KEYCODES = frozenset({29, 97, 56, 100, 42, 54, 125, 126})


def keycode_for(name):
    """Resolve a step-list key name to an evdev keycode.

    Accepts names case-insensitively ("Enter", "CTRL", "F5"), single
    letters/digits, and single punctuation characters. Raises KeyError
    for anything unmapped — better loud than a silently wrong key.
    """
    if isinstance(name, int):
        return name
    code = KEY_NAME_TO_CODE.get(str(name).strip().lower())
    if code is None:
        raise KeyError("unknown key name: %r" % (name,))
    return code


# --------------------------------------------------------------------------
# Base class: held-state tracking + the stop sweep.
# --------------------------------------------------------------------------

class Actuator:
    """Actuator protocol plus shared held-state tracking.

    Concrete actuators implement the primitives (move/button/scroll/
    key/type_text/position) and call _note_key/_note_button after each
    successful key/button transition. release_all() is the stop sweep:
    it releases every tracked held button and key, exactly once, and is
    safe to call at any time (including from the panic path while an act
    is in flight).
    """

    name = "base"

    def __init__(self):
        self._held_keys = set()      # evdev keycodes currently down
        self._held_buttons = set()   # button names currently down
        self._state_lock = threading.Lock()

    # -- primitives (override) -------------------------------------------
    def move(self, x, y):
        raise NotImplementedError

    def button(self, button, down):
        raise NotImplementedError

    def scroll(self, dx, dy):
        raise NotImplementedError

    def key(self, evdev_keycode, down):
        raise NotImplementedError

    def type_text(self, text):
        raise NotImplementedError

    def position(self):
        return None

    # -- held-state bookkeeping ------------------------------------------
    def _note_key(self, evdev_keycode, down):
        with self._state_lock:
            if down:
                self._held_keys.add(evdev_keycode)
            else:
                self._held_keys.discard(evdev_keycode)

    def _note_button(self, button, down):
        with self._state_lock:
            if down:
                self._held_buttons.add(button)
            else:
                self._held_buttons.discard(button)

    def held(self):
        """Snapshot of what is currently down: (keycodes, button names)."""
        with self._state_lock:
            return (sorted(self._held_keys), sorted(self._held_buttons))

    def release_all(self):
        """Key-up/button-up sweep. Returns how many inputs were released.

        Order: buttons first, then keys — either is safe; what matters is
        that nothing the guardian pressed is left physically down after a
        stop. Individual release failures are collected, not raised, so
        one bad release cannot prevent the rest of the sweep.
        """
        keys, buttons = self.held()
        released = 0
        errors = []
        for b in buttons:
            try:
                self.button(b, False)
                released += 1
            except Exception as e:  # sweep must not stop sweeping
                errors.append("button %s: %s" % (b, e))
        for k in keys:
            try:
                self.key(k, False)
                released += 1
            except Exception as e:
                errors.append("key %s: %s" % (k, e))
        if errors:
            raise ActuatorError(
                "release_all incomplete: " + "; ".join(errors))
        return released


# --------------------------------------------------------------------------
# ydotool actuator (P1's shipping actuator)
# --------------------------------------------------------------------------

# ydotool click encoding: low bits are the button index, 0x40 = press,
# 0x80 = release (0xC0|idx would be press+release in one call).
_BUTTON_INDEX = {"left": 0x00, "right": 0x01, "middle": 0x02}


class YdotoolActuator(Actuator):
    """Drives the guardian's own ydotoold via the ydotool CLI.

    The daemon socket path is passed in (the guardian starts its private
    ydotoold on /run/handsrelay-guardian/ydotoold.sock); the CLI finds
    it through the YDOTOOL_SOCKET environment variable.

    Absolute-positioning caveat (SCOPE §5.2): ydotool absolute moves are
    best-effort and there is no way to read the true pointer position
    back through uinput, so this actuator tracks the last position it
    commanded and position() returns that tracked value (None before
    the first move).
    """

    name = "ydotool"

    def __init__(self, socket_path, ydotool_bin="ydotool"):
        super().__init__()
        self.socket_path = socket_path
        self.ydotool_bin = ydotool_bin
        self._pos = None
        self._run_lock = threading.Lock()

    def _run(self, args):
        env = dict(os.environ)
        env["YDOTOOL_SOCKET"] = self.socket_path
        # Serialize CLI invocations: ydotool calls are quick, and serial
        # execution keeps held-state bookkeeping race-free.
        with self._run_lock:
            try:
                proc = subprocess.run(
                    [self.ydotool_bin] + args,
                    env=env, capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                raise ActuatorError(
                    "ydotool binary not found: %s" % self.ydotool_bin)
            except subprocess.TimeoutExpired:
                raise ActuatorError("ydotool timed out: %r" % (args,))
        if proc.returncode != 0:
            raise ActuatorError(
                "ydotool %s failed (rc=%d): %s"
                % (args[0], proc.returncode, proc.stderr.strip()))

    def move(self, x, y):
        x, y = int(x), int(y)
        # ydotool 1.x takes -x/-y flags; positional args are ignored and
        # the move lands on (0, 0) — found the hard way in the P1 smoke.
        self._run(["mousemove", "--absolute", "-x", str(x), "-y", str(y)])
        self._pos = (x, y)

    def button(self, button, down):
        try:
            idx = _BUTTON_INDEX[button]
        except KeyError:
            raise ActuatorError("unknown button: %r" % (button,))
        code = (0x40 if down else 0x80) | idx
        self._run(["click", "0x%02X" % code])
        self._note_button(button, down)

    def scroll(self, dx, dy):
        dx, dy = int(dx), int(dy)
        if dx == 0 and dy == 0:
            return
        # mousemove --wheel moves the wheel relatively; signs already
        # match the pyautogui convention (see module docstring).
        self._run(["mousemove", "--wheel", "-x", str(dx), "-y", str(dy)])

    def key(self, evdev_keycode, down):
        self._run(["key", "%d:%d" % (int(evdev_keycode), 1 if down else 0)])
        self._note_key(int(evdev_keycode), down)

    def type_text(self, text):
        if not text:
            return
        args = ["type"]
        if text.startswith("-"):
            args.append("--")
        args.append(text)
        self._run(args)

    def position(self):
        return self._pos


# --------------------------------------------------------------------------
# EIS actuator (stub — follow-up behind this same interface)
# --------------------------------------------------------------------------

class EisActuator(Actuator):
    """KWin EIS (libei) actuator — not yet implemented.

    Design for the follow-up (DESIGN-P1.md, SCOPE §5.1):

    1. The *session* component calls KWin's
       `org.kde.KWin.EIS.RemoteDesktop.connectToEIS` over the session
       bus (authorized by the shipped .desktop identity) and receives a
       connected EI socket fd.
    2. The session passes that fd to the guardian over the guardian IPC
       socket using SCM_RIGHTS ancillary data. Possession of the fd —
       not the session — is what transfers.
    3. The guardian speaks the EI wire protocol on the fd itself
       (ei_device / ei_pointer_absolute / ei_keyboard interfaces) and
       owns injection fully, exactly as it does with ydotool today: the
       latch check and the stop sweep stay in the guardian, unchanged.

    A pure-Python EI wire client is the known least-trodden piece of
    the port, which is why P1 ships the ydotool actuator behind this
    same interface: swapping actuators changes nothing above this class.
    """

    name = "eis"

    def _pending(self, what):
        raise NotImplementedError(
            "EisActuator.%s is not implemented in P1; the guardian ships "
            "with YdotoolActuator behind the same interface (see the "
            "class docstring for the SCM_RIGHTS design)" % what)

    def move(self, x, y):
        self._pending("move")

    def button(self, button, down):
        self._pending("button")

    def scroll(self, dx, dy):
        self._pending("scroll")

    def key(self, evdev_keycode, down):
        self._pending("key")

    def type_text(self, text):
        self._pending("type_text")

    def position(self):
        self._pending("position")


# --------------------------------------------------------------------------
# Fake actuator (tests / dry runs)
# --------------------------------------------------------------------------

class FakeActuator(Actuator):
    """Records every call instead of injecting input. For tests."""

    name = "fake"

    def __init__(self):
        super().__init__()
        self.calls = []  # list of tuples, in call order
        self._pos = None

    def move(self, x, y):
        self.calls.append(("move", int(x), int(y)))
        self._pos = (int(x), int(y))

    def button(self, button, down):
        self.calls.append(("button", button, bool(down)))
        self._note_button(button, down)

    def scroll(self, dx, dy):
        self.calls.append(("scroll", int(dx), int(dy)))

    def key(self, evdev_keycode, down):
        self.calls.append(("key", int(evdev_keycode), bool(down)))
        self._note_key(int(evdev_keycode), down)

    def type_text(self, text):
        self.calls.append(("type_text", text))

    def position(self):
        return self._pos
