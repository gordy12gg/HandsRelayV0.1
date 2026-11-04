"""Session-side window enumeration + activation via KWin scripting.

This is the Linux counterpart of upstream's ``_enum_windows()`` /
``_activate_window()`` seam (hands/hands_relay_hands.py). It holds **no
injection capability**: KWin scripting can list windows and ask the
compositor to make one active — the same thing the owner's own window
rules do — and it cannot synthesize input events. All input injection
stays in the root guardian (DESIGN-P1.md).

How it works
------------
KWin exposes a scripting bridge on the session bus:
``org.kde.KWin`` object ``/Scripting`` (interface
``org.kde.kwin.Scripting``) loads a JavaScript file with
``loadScript(path, pluginName) -> id``; the loaded script lives at
``/Scripting/Script<id>`` (interface ``org.kde.kwin.Script``) and runs
when its ``run()`` method is called. Scripts see the ``workspace``
object: ``workspace.windowList()`` (Plasma 6; ``clientList()`` before),
each window carrying ``internalId`` (a QUuid — our HWND stand-in),
``caption``, ``pid``, ``frameGeometry``, ``minimized``, ``desktops`` /
``onAllDesktops``; ``workspace.activeWindow`` is gettable *and*
settable — setting it is the activation primitive.

**The return channel is the design's known unknown.** KWin scripts
have no D-Bus return value, so the script calls *back* into this
process with the ``callDBus`` global: before loading the script we
export a one-shot ``org.gordy.handsrelay.ScriptBridge`` service under a
unique bus name and bake the name + a random token into the script
text; the script JSON-encodes its result and invokes
``Deliver(token, payload)``. Whether ``callDBus`` reaches a
same-session service exported by an unprivileged process, and whether
``loadScript`` itself is gated behind KWin's restricted-interface
identity (the shipped ``.desktop`` file now also lists
``org.kde.kwin.Scripting``), **must be verified on the box** — see
DESIGN-P2.md. Nothing here has run against a live KWin yet; the module
is built to the documented interface and its pure pieces (script
building, payload mapping) are unit-tested headless.

Like capture.py, the async dbus-fast bus is driven from a short-lived
``asyncio.run`` per call, so callers must not be inside a running event
loop (the Flask session app satisfies this). If ``dbus_fast`` is not
installed, every call raises ``RuntimeError`` — no silent fallback.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import tempfile

KWIN_BUS_NAME = "org.kde.KWin"
SCRIPTING_PATH = "/Scripting"
# Interface names are lowercase "kwin" on Plasma 6 (verified on-box
# 2026-11-04 with gdbus introspect: /Scripting implements
# org.kde.kwin.Scripting; the org.kde.KWin.* spelling is pre-6).
SCRIPTING_INTERFACE = "org.kde.kwin.Scripting"
SCRIPT_INTERFACE = "org.kde.kwin.Script"
BRIDGE_INTERFACE = "org.gordy.handsrelay.ScriptBridge"
BRIDGE_PATH = "/org/gordy/handsrelay/ScriptBridge"

# Inline introspection for the scripting bridge (same pattern as
# capture.py's ScreenShot2 XML).
SCRIPTING_XML = """
<node>
  <interface name="org.kde.kwin.Scripting">
    <method name="loadScript">
      <arg name="filePath" type="s" direction="in"/>
      <arg name="pluginName" type="s" direction="in"/>
      <arg name="id" type="i" direction="out"/>
    </method>
    <method name="unloadScript">
      <arg name="pluginName" type="s" direction="in"/>
      <arg name="success" type="b" direction="out"/>
    </method>
    <method name="isScriptLoaded">
      <arg name="pluginName" type="s" direction="in"/>
      <arg name="loaded" type="b" direction="out"/>
    </method>
  </interface>
  <interface name="org.kde.kwin.Script">
    <method name="run"/>
    <method name="stop"/>
  </interface>
</node>
"""


# ---------------------------------------------------------------------------
# Pure pieces (unit-tested headless)

_LIST_BODY = """
var wins = [];
var list = workspace.windowList();
var activeId = workspace.activeWindow
    ? String(workspace.activeWindow.internalId) : "";
for (var i = 0; i < list.length; i++) {
    var w = list[i];
    var g = w.frameGeometry;
    var onCurrent = true;
    try {
        onCurrent = !!w.onAllDesktops
            || (w.desktops
                && w.desktops.indexOf(workspace.currentDesktop) >= 0);
    } catch (e) { onCurrent = true; }
    wins.push({
        id: String(w.internalId),
        title: w.caption || "",
        pid: w.pid || 0,
        x: g.x, y: g.y, w: g.width, h: g.height,
        minimized: !!w.minimized,
        on_current_desktop: onCurrent,
        active: String(w.internalId) === activeId
    });
}
"""

_ACTIVATE_BODY = """
var target = null;
var list = workspace.windowList();
for (var i = 0; i < list.length; i++) {
    if (String(list[i].internalId) === __TARGET_ID__) { target = list[i]; break; }
}
var ok = false;
if (target) {
    if (target.minimized) { target.minimized = false; }
    workspace.activeWindow = target;
    ok = true;
}
"""


def build_script(body: str, service: str, token: str, result_expr: str) -> str:
    """Wrap a JS body with the callDBus delivery of ``result_expr``.

    ``service``/``token`` are baked in as JSON string literals (they are
    ours — a bus-name suffix and a random hex token — never raw user
    input)."""
    return (
        body
        + "\ncallDBus("
        + json.dumps(service)
        + ", "
        + json.dumps(BRIDGE_PATH)
        + ", "
        + json.dumps(BRIDGE_INTERFACE)
        + ', "Deliver", '
        + json.dumps(token)
        + ", "
        + result_expr
        + ");\n"
    )


def windows_from_payload(payload: str) -> list[dict]:
    """Map the list script's JSON payload to raw window dicts.

    Raw shape (the app's shaping layer adds process/monitor):
    ``{"id", "title", "pid", "bounds", "visible", "focused"}`` —
    ``visible`` mirrors upstream's IsWindowVisible closely enough for
    the relay: not minimised and on the current desktop.
    """
    data = json.loads(payload)
    wins = []
    for item in data:
        wins.append(
            {
                "id": str(item.get("id") or ""),
                "title": item.get("title") or "",
                "pid": int(item["pid"]) if item.get("pid") else None,
                "bounds": {
                    "x": int(item.get("x", 0)),
                    "y": int(item.get("y", 0)),
                    "w": int(item.get("w", 0)),
                    "h": int(item.get("h", 0)),
                },
                "visible": bool(
                    not item.get("minimized") and item.get("on_current_desktop", True)
                ),
                "focused": bool(item.get("active")),
            }
        )
    return wins


# ---------------------------------------------------------------------------
# The backend

_plugin_counter = [0]


def _import_dbus_fast():
    """Import dbus-fast lazily so this module loads without the dependency."""
    try:
        import dbus_fast
        from dbus_fast import BusType, introspection
        from dbus_fast.aio import MessageBus
        from dbus_fast.service import ServiceInterface, method
    except ImportError as exc:
        raise RuntimeError(
            "windows_kwin.py requires the 'dbus-fast' package, which is "
            "not installed. Install dbus-fast for the session app "
            "(e.g. pip install dbus-fast); there is no fallback window path."
        ) from exc
    return dbus_fast, BusType, introspection, MessageBus, ServiceInterface, method


class KWinWindowsBackend:
    """Window list + activation through the KWin scripting bridge.

    Duck-typed for the session app:

        list_windows() -> [raw window dicts]   (see windows_from_payload)
        activate(window_id) -> bool
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    # -- public API -----------------------------------------------------

    def list_windows(self) -> list[dict]:
        payload = self._run_script(_LIST_BODY, "JSON.stringify(wins)")
        return windows_from_payload(payload)

    def activate(self, window_id: str) -> bool:
        body = _ACTIVATE_BODY.replace("__TARGET_ID__", json.dumps(str(window_id)))
        payload = self._run_script(body, 'ok ? "true" : "false"')
        return payload.strip() == "true"

    # -- internals ------------------------------------------------------

    def _bridge_args(self):
        token = secrets.token_hex(16)
        service = f"org.gordy.handsrelay.bridge{token[:12]}"
        return service, token

    def _run_script(self, body: str, result_expr: str) -> str:
        service, token = self._bridge_args()
        script_text = build_script(body, service, token, result_expr)
        try:
            return asyncio.run(self._run_async(script_text, service, token))
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"KWin scripting bridge failed: {exc}") from exc

    async def _run_async(self, script_text: str, service: str, token: str) -> str:
        (_dbus_fast, BusType, introspection, MessageBus,
         ServiceInterface, method) = _import_dbus_fast()

        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()

        class _Bridge(ServiceInterface):
            def __init__(self):
                super().__init__(BRIDGE_INTERFACE)

            @method()
            # No "-> None" return annotation here: this module uses
            # "from __future__ import annotations", which stringizes it
            # to "None", and dbus-fast's method parser turns that into
            # signature=None and raises TypeError at class-definition
            # time (found on-box 2026-11-04; reproduced headless).
            def Deliver(self, got_token: "s", payload: "s"):
                if got_token == token and not future.done():
                    future.set_result(payload)

        bus = MessageBus(bus_type=BusType.SESSION)
        await bus.connect()
        _plugin_counter[0] += 1
        plugin_name = f"handsrelay-bridge-{os.getpid()}-{_plugin_counter[0]}"
        script_path = None
        try:
            # The name carries 48 random bits and Deliver checks the
            # full token, so a name collision could only ever cause a
            # timeout, never a wrong delivery.
            await bus.request_name(service)
            bus.export(BRIDGE_PATH, _Bridge())

            node = introspection.Node.parse(SCRIPTING_XML)
            proxy = bus.get_proxy_object(KWIN_BUS_NAME, SCRIPTING_PATH, node)
            scripting = proxy.get_interface(SCRIPTING_INTERFACE)

            with tempfile.NamedTemporaryFile(
                "w", suffix=".js", prefix="handsrelay-", delete=False
            ) as fh:
                fh.write(script_text)
                script_path = fh.name
            script_id = await scripting.call_load_script(script_path, plugin_name)
            if not isinstance(script_id, int) or script_id < 0:
                raise RuntimeError(f"loadScript returned {script_id!r}")
            script_proxy = bus.get_proxy_object(
                KWIN_BUS_NAME, f"/Scripting/Script{script_id}", node
            )
            script_iface = script_proxy.get_interface(SCRIPT_INTERFACE)
            await script_iface.call_run()
            return await asyncio.wait_for(future, timeout=self.timeout)
        finally:
            try:
                node = introspection.Node.parse(SCRIPTING_XML)
                proxy = bus.get_proxy_object(KWIN_BUS_NAME, SCRIPTING_PATH, node)
                scripting = proxy.get_interface(SCRIPTING_INTERFACE)
                await scripting.call_unload_script(plugin_name)
            except Exception:
                pass
            if script_path:
                try:
                    os.unlink(script_path)
                except OSError:
                    pass
            try:
                bus.disconnect()
            except Exception:
                pass
