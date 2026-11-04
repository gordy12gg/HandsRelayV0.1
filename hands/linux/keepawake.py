"""Keep-awake for the Linux session app (P2).

Upstream keeps the PC awake for the whole life of the packaged app
(``SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)`` in the
Windows app window) and exposes **no route** for it, so the Linux port
mirrors that shape: an internal behaviour gated by a config flag —
``HANDS_KEEP_AWAKE`` (env) / the ``keep_awake_enabled`` argument of
``create_app`` — never an HTTP endpoint.

Backends, tried in order by :func:`default_keep_awake`:

1. :class:`ScreenSaverInhibit` — ``org.freedesktop.ScreenSaver``
   ``Inhibit``/``UnInhibit`` on the session bus (KDE implements the
   freedesktop ScreenSaver interface). The inhibition is tied to the
   D-Bus *connection*, so unlike capture.py's one-shot calls this
   backend holds a dedicated bus connection open on its own thread for
   as long as the inhibition is held. Inhibiting idle+screensaver also
   keeps Plasma from auto-locking mid-session, which is the point.
2. :class:`SystemdInhibit` — a held ``systemd-inhibit --what=idle:sleep
   --mode=block sleep infinity`` child process; released by
   terminating it. Coarser (blocks system sleep/idle system-wide) but
   needs no session-bus contract.

:class:`KeepAwake` wraps one inhibitor (plus an optional fallback) with
idempotent start/stop and an ``active`` flag the app reports in
``/state``. Inhibitors are duck-typed (``inhibit()`` / ``uninhibit()``)
so tests drive the manager headless with fakes.
"""

from __future__ import annotations

import asyncio
import subprocess
import threading

SCREENSAVER_BUS_NAME = "org.freedesktop.ScreenSaver"
SCREENSAVER_PATH = "/org/freedesktop/ScreenSaver"
SCREENSAVER_INTERFACE = "org.freedesktop.ScreenSaver"

SCREENSAVER_XML = """
<node>
  <interface name="org.freedesktop.ScreenSaver">
    <method name="Inhibit">
      <arg name="application_name" type="s" direction="in"/>
      <arg name="reason" type="s" direction="in"/>
      <arg name="cookie" type="u" direction="out"/>
    </method>
    <method name="UnInhibit">
      <arg name="cookie" type="u" direction="in"/>
    </method>
  </interface>
</node>
"""

APP_NAME = "HandsRelay"
REASON = "relay session active"


class ScreenSaverInhibit:
    """freedesktop ScreenSaver inhibition on a held-open bus connection."""

    def __init__(self, app_name: str = APP_NAME, reason: str = REASON):
        self.app_name = app_name
        self.reason = reason
        self._loop = None
        self._thread = None
        self._bus = None
        self._iface = None
        self._cookie = None
        self._ready = threading.Event()
        self._start_error = None

    # -- thread / loop plumbing ------------------------------------------

    def _thread_main(self):
        try:
            import dbus_fast
            from dbus_fast import BusType, introspection
            from dbus_fast.aio import MessageBus
        except ImportError as exc:
            self._start_error = RuntimeError(
                "keepawake ScreenSaver backend requires the 'dbus-fast' "
                "package, which is not installed"
            )
            self._ready.set()
            return

        async def _setup():
            bus = MessageBus(bus_type=BusType.SESSION)
            await bus.connect()
            node = introspection.Node.parse(SCREENSAVER_XML)
            proxy = bus.get_proxy_object(
                SCREENSAVER_BUS_NAME, SCREENSAVER_PATH, node
            )
            self._bus = bus
            self._iface = proxy.get_interface(SCREENSAVER_INTERFACE)

        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_setup())
        except Exception as exc:  # bus absent / interface missing
            self._start_error = exc
            self._ready.set()
            return
        self._ready.set()
        loop.run_forever()

    def _ensure_started(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._thread_main, name="handsrelay-keepawake", daemon=True
        )
        self._thread.start()
        self._ready.wait(timeout=10)
        if self._start_error is not None:
            raise RuntimeError(
                f"ScreenSaver inhibit unavailable: {self._start_error}"
            )

    def _call(self, coro_factory):
        self._ensure_started()
        fut = asyncio.run_coroutine_threadsafe(coro_factory(), self._loop)
        return fut.result(timeout=10)

    # -- inhibitor seam ----------------------------------------------------

    def inhibit(self):
        async def _do():
            self._cookie = await self._iface.call_inhibit(
                self.app_name, self.reason
            )

        self._call(_do)
        return self._cookie

    def uninhibit(self):
        if self._cookie is None:
            return

        async def _do():
            await self._iface.call_un_inhibit(self._cookie)

        try:
            self._call(_do)
        finally:
            self._cookie = None
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._teardown)

    def _teardown(self):
        try:
            if self._bus is not None:
                self._bus.disconnect()
        except Exception:
            pass
        self._loop.stop()


class SystemdInhibit:
    """Fallback: hold a ``systemd-inhibit`` child process."""

    def __init__(self, popen=None):
        self._popen = popen or subprocess.Popen
        self._proc = None

    def inhibit(self):
        if self._proc is not None:
            return None
        self._proc = self._popen(
            [
                "systemd-inhibit",
                "--what=idle:sleep",
                f"--who={APP_NAME}",
                f"--why={REASON}",
                "--mode=block",
                "sleep",
                "infinity",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return None

    def uninhibit(self):
        proc, self._proc = self._proc, None
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass


class KeepAwake:
    """Idempotent hold over an inhibitor + optional fallback."""

    def __init__(self, inhibitor, fallback=None):
        self._inhibitor = inhibitor
        self._fallback = fallback
        self._held = None  # the inhibitor that actually engaged
        self.active = False

    def start(self) -> bool:
        """Engage the inhibition. True when held (or already held);
        False when every backend failed — the app logs and runs on."""
        if self.active:
            return True
        for candidate in (self._inhibitor, self._fallback):
            if candidate is None:
                continue
            try:
                candidate.inhibit()
            except Exception:
                continue
            self._held = candidate
            self.active = True
            return True
        return False

    def stop(self) -> None:
        held, self._held = self._held, None
        self.active = False
        if held is not None:
            try:
                held.uninhibit()
            except Exception:
                pass


def default_keep_awake() -> KeepAwake:
    """The packaged chain: ScreenSaver D-Bus first, systemd-inhibit
    as the fallback."""
    return KeepAwake(ScreenSaverInhibit(), fallback=SystemdInhibit())
