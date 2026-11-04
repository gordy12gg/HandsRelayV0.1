"""Synchronous client for the HandsRelay guardian IPC.

The guardian (root-owned systemd service, see DESIGN-P1.md) owns the
emergency-stop latch and all input injection. The session hands app talks
to it over a unix socket using JSON lines: one request per connection,
one JSON object per line in each direction.

Protocol (from DESIGN-P1.md):

    {"op":"state"}                          -> {"ok":true,"stopped":bool,
                                                "reason":str|null,"since":float}
    {"op":"activity"}                       -> {"ok":true,"idle_seconds":float}
    {"op":"act","kind":"mouse"|"keys",
     "steps":[step, ...]}                   -> {"ok":true}
                                                | {"ok":false,
                                                   "error_code":"emergency_stop"}
                                                | {"ok":false,"error":str}
    {"op":"stop","source":"window"|"panic"|"api"}
                                            -> {"ok":true,"stopped":true}

There is deliberately **no** ``resume()`` method here: the guardian refuses
resume unless the peer UID is 0, and the only sanctioned path is the
pkexec/polkit root helper (``handsrelay-resume``). The session app must
never grow a resume call.

This module uses only the standard library.
"""

from __future__ import annotations

import json
import socket

DEFAULT_SOCKET_PATH = "/run/handsrelay-guardian/guardian.sock"
DEFAULT_TIMEOUT = 30.0

_ACT_KINDS = ("mouse", "keys")
_STOP_SOURCES = ("window", "panic", "api")


class GuardianError(Exception):
    """The guardian exchange failed or the reply was malformed."""


class GuardianUnavailable(GuardianError):
    """The guardian socket could not be reached (service down/absent)."""


def is_stopped(resp: dict | None) -> bool:
    """True if a guardian response indicates the emergency stop is latched.

    Covers both response shapes: a ``state`` reply carries
    ``"stopped": true``; an ``act`` refused by the latch instead carries
    ``"error_code": "emergency_stop"`` with ``ok: false``.
    """
    if not isinstance(resp, dict):
        return False
    if resp.get("stopped"):
        return True
    return resp.get("error_code") == "emergency_stop"


class GuardianClient:
    """One-shot-per-request client for the guardian unix socket.

    A fresh connection is opened for every request (the protocol is
    one-request-per-connection), so an instance is cheap to keep around
    and safe to share between threads.
    """

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH,
                 timeout: float = DEFAULT_TIMEOUT):
        self.socket_path = socket_path
        self.timeout = timeout

    # -- transport ------------------------------------------------------

    def _request(self, payload: dict) -> dict:
        line = (json.dumps(payload) + "\n").encode("utf-8")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            try:
                sock.connect(self.socket_path)
            except OSError as exc:
                raise GuardianUnavailable(
                    f"cannot connect to guardian at {self.socket_path}: {exc}"
                ) from exc
            try:
                sock.sendall(line)
                chunks = []
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break
            except OSError as exc:
                raise GuardianUnavailable(
                    f"guardian exchange failed on {self.socket_path}: {exc}"
                ) from exc
        finally:
            sock.close()

        raw = b"".join(chunks).split(b"\n", 1)[0].strip()
        if not raw:
            raise GuardianError("guardian closed the connection with no reply")
        try:
            resp = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise GuardianError(f"malformed guardian reply: {raw!r}") from exc
        if not isinstance(resp, dict):
            raise GuardianError(f"guardian reply is not an object: {resp!r}")
        return resp

    # -- operations -----------------------------------------------------

    def state(self) -> dict:
        """Return the latch state: ok/stopped/reason/since."""
        return self._request({"op": "state"})

    def activity(self) -> dict:
        """Return owner idleness: ok/idle_seconds (physical devices only)."""
        return self._request({"op": "activity"})

    def act(self, kind: str, steps: list) -> dict:
        """Ask the guardian to execute a list of input steps.

        ``kind`` is "mouse" or "keys"; ``steps`` are the step dicts defined
        in DESIGN-P1.md (move/sleep/button/scroll/key/keydown/keyup/type).
        The guardian checks the latch first, so a stopped reply comes back
        as ``{"ok": false, "error_code": "emergency_stop"}`` — test it with
        :func:`is_stopped`.
        """
        if kind not in _ACT_KINDS:
            raise ValueError(f"act kind must be one of {_ACT_KINDS}, got {kind!r}")
        return self._request({"op": "act", "kind": kind, "steps": steps})

    def stop(self, source: str) -> dict:
        """Latch the emergency stop. ``source``: window | panic | api."""
        if source not in _STOP_SOURCES:
            raise ValueError(
                f"stop source must be one of {_STOP_SOURCES}, got {source!r}")
        return self._request({"op": "stop", "source": source})
