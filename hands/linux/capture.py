"""Session-side screen capture via KWin ScreenShot2 (DESIGN-P1.md).

Capture holds no injection capability; it only reads pixels. It uses the
``org.kde.KWin.ScreenShot2`` D-Bus interface on the session bus, which is a
KWin *restricted* interface: the calling process must run under the shipped
desktop identity (``packaging/org.gordy.handsrelay.desktop`` with
``X-KDE-DBUS-Restricted-Interfaces=org.kde.KWin.ScreenShot2;...``) or KWin
refuses the call.

API notes — verified by inspecting dbus-fast 5.2.0 (the smoke test should
re-confirm against the version installed on the box):

* dbus-fast has **no synchronous MessageBus** (there is no ``dbus_fast.sync``
  in current releases; only ``dbus_fast.aio`` and ``dbus_fast.glib``). This
  module therefore drives the asyncio bus from a short-lived event loop per
  call (``asyncio.run``). Consequence: call these functions from a plain
  thread, not from inside a running event loop — the Flask session app
  satisfies this.
* Per the on-box introspection (P0), the ScreenShot2 capture methods take
  the fd as an **input** argument (signatures ``a{sv}h``, ``iiuua{sv}h``,
  ``sa{sv}h``; results are the ``a{sv}`` out arg). The caller creates a
  pipe, passes its write end, and reads the PNG from the read end. (The
  design doc's "returns an fd" phrasing is the same pipe seen from the
  other side.)
* FD PASSING SPOT: with dbus-fast's proxy objects you pass the raw fd
  number as the ``h`` argument and the generated ``call_*`` method converts
  it into the message's ``unix_fds`` array for you
  (``replace_fds_with_idx`` in ``dbus_fast/aio/proxy_object.py``). If a
  future dbus-fast changes that, this is the place that breaks.
* The pipe is drained on a reader thread while the call is in flight: a
  full-screen PNG is far larger than the 64 KiB pipe buffer, so reading
  only after the reply could deadlock against KWin's writes.

If ``dbus_fast`` is not installed, :func:`grab` raises ``RuntimeError``
with a clear message — there is no silent fallback (DESIGN-P1.md).
"""

from __future__ import annotations

import asyncio
import io
import os
import re
import subprocess
import threading

from PIL import Image

KWIN_BUS_NAME = "org.kde.KWin"
KWIN_OBJECT_PATH = "/org/kde/KWin/ScreenShot2"
SCREENSHOT2_INTERFACE = "org.kde.KWin.ScreenShot2"

# Inline introspection for org.kde.KWin.ScreenShot2. Signatures match the
# on-box busctl output from the P0 checklist (ScreenShot2 Version 5).
SCREENSHOT2_XML = """
<node>
  <interface name="org.kde.KWin.ScreenShot2">
    <method name="CaptureActiveScreen">
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="fd" type="h" direction="in"/>
      <arg name="results" type="a{sv}" direction="out"/>
    </method>
    <method name="CaptureScreen">
      <arg name="name" type="s" direction="in"/>
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="fd" type="h" direction="in"/>
      <arg name="results" type="a{sv}" direction="out"/>
    </method>
    <method name="CaptureArea">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
      <arg name="width" type="u" direction="in"/>
      <arg name="height" type="u" direction="in"/>
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="fd" type="h" direction="in"/>
      <arg name="results" type="a{sv}" direction="out"/>
    </method>
    <method name="CaptureActiveWindow">
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="fd" type="h" direction="in"/>
      <arg name="results" type="a{sv}" direction="out"/>
    </method>
    <property name="Version" type="u" access="read"/>
  </interface>
</node>
"""


def _import_dbus_fast():
    """Import dbus-fast lazily so this module loads without the dependency."""
    try:
        import dbus_fast
        from dbus_fast import BusType, introspection
        from dbus_fast.aio import MessageBus
    except ImportError as exc:
        raise RuntimeError(
            "capture.py requires the 'dbus-fast' package, which is not "
            "installed. Install dbus-fast for the session app "
            "(e.g. pip install dbus-fast); there is no fallback capture path."
        ) from exc
    return dbus_fast, BusType, introspection, MessageBus


async def _capture_async(member: str, args_prefix: list, options: dict) -> bytes:
    """Run one ScreenShot2 call; return the PNG bytes KWin wrote to the pipe."""
    _, BusType, introspection, MessageBus = _import_dbus_fast()

    read_fd, write_fd = os.pipe()
    chunks: list[bytes] = []

    def _drain():
        with os.fdopen(read_fd, "rb") as pipe:
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)

    drainer = threading.Thread(target=_drain, name="screenshot2-drain",
                               daemon=True)
    drainer.start()

    # negotiate_unix_fd is load-bearing: ScreenShot2 takes the screenshot
    # pipe as an 'h' argument, and unless fd passing was negotiated during
    # bus auth the daemon strips it and KWin answers "No valid file
    # descriptor" (dbus-fast defaults it to False; found in the P1 smoke).
    bus = MessageBus(bus_type=BusType.SESSION, negotiate_unix_fd=True)
    try:
        await bus.connect()
        node = introspection.Node.parse(SCREENSHOT2_XML)
        proxy = bus.get_proxy_object(KWIN_BUS_NAME, KWIN_OBJECT_PATH, node)
        iface = proxy.get_interface(SCREENSHOT2_INTERFACE)
        method = getattr(iface, "call_" + member)
        # The fd goes in as a plain int; dbus-fast moves it into the
        # message's unix_fds array (see module docstring, "FD PASSING SPOT").
        results = await method(*args_prefix, options, write_fd,
                               unpack_variants=True)
    finally:
        # Our copy of the write end closes so the reader sees EOF once
        # KWin's dup'd copy is done; KWin's side closes when it finishes.
        os.close(write_fd)
        try:
            bus.disconnect()
        except Exception:
            pass
    drainer.join(timeout=10)

    data = b"".join(chunks)
    if not data:
        raise RuntimeError(
            f"ScreenShot2 {member} completed but produced no image data")
    return data, results if isinstance(results, dict) else {}


# QImage::Format values KWin may report for raw pipe data. On the
# observed box (KWin 6.8.2) format 16 came back: RGBA8888, R,G,B,A in
# memory. The 32-bit RGB32/ARGB32 family (4/5/6) is B,G,R,A in memory
# on little-endian; RGBX8888 (15) is R,G,B,X.
_QIMAGE_BGRA_FORMATS = {4, 5, 6}
_QIMAGE_RGBA_FORMATS = {16, 17}
_QIMAGE_RGBX_FORMATS = {15}


def _image_from_raw(data: bytes, results: dict) -> Image.Image | None:
    """Rebuild an image from raw pipe bytes + the results dict, if the
    dict carries geometry. ScreenShot2's pipe payload is raw pixels
    (results say type='raw'), not PNG (P1 smoke, run 4)."""
    try:
        w = int(results["width"])
        h = int(results["height"])
        fmt = int(results.get("format", 16))
        stride = int(results.get("stride", w * 4))
    except Exception:
        return None
    if stride < w * 4 or len(data) < stride * h:
        return None
    if fmt in _QIMAGE_RGBA_FORMATS:
        decoder = "RGBA"
    elif fmt in _QIMAGE_BGRA_FORMATS:
        decoder = "BGRA"
    elif fmt in _QIMAGE_RGBX_FORMATS:
        decoder = "RGBX"
    else:
        return None
    img = Image.frombytes("RGBA", (w, h), data[: stride * h],
                          "raw", decoder, stride, 1)
    return img.convert("RGB")


def _capture(member: str, args_prefix: list, options: dict | None) -> Image.Image:
    opts = dict(options) if options else {}
    try:
        data, results = asyncio.run(_capture_async(member, args_prefix, opts))
    except RuntimeError:
        raise
    except Exception as exc:  # DBusError and friends -> one clear surface
        raise RuntimeError(f"ScreenShot2 {member} failed: {exc}") from exc
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        return img
    except Exception:
        pass
    raw = _image_from_raw(data, results)
    if raw is not None:
        return raw
    raise RuntimeError(
        f"ScreenShot2 {member} returned undecodable image data: "
        f"len={len(data)} head={data[:16].hex()} results={results!r}")


def grab(rect: dict | None = None, monitor_name: str | None = None,
         options: dict | None = None) -> Image.Image:
    """Capture a screenshot as a PIL Image.

    Exactly one selector may be given:

    * ``rect`` — ``{"x","y","w","h"}`` in global compositor coordinates
      (see :func:`monitor_rects`); uses ``CaptureArea``.
    * ``monitor_name`` — a connector name such as ``"DP-3"``; uses
      ``CaptureScreen``.
    * neither — the active screen, via ``CaptureActiveScreen``.

    ``options`` is passed through as the ScreenShot2 ``a{sv}`` options
    dict (values are wrapped as Variants by dbus-fast as needed).
    """
    if rect is not None and monitor_name is not None:
        raise ValueError("grab() takes either rect or monitor_name, not both")
    if rect is not None:
        args = [int(rect["x"]), int(rect["y"]),
                int(rect["w"]), int(rect["h"])]
        return _capture("capture_area", args, options)
    if monitor_name is not None:
        return _capture("capture_screen", [str(monitor_name)], options)
    return _capture("capture_active_screen", [], options)


# ---------------------------------------------------------------------------
# Monitor geometry

_OUTPUT_RE = re.compile(r"^Output:\s+\d+\s+(\S+)\s")
_GEOMETRY_RE = re.compile(r"^\s*Geometry:\s+(-?\d+),(-?\d+)\s+(\d+)x(\d+)\s*$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def monitor_rects() -> list[dict]:
    """Return enabled monitors as ``[{"name","x","y","w","h"}, ...]``.

    Parses ``kscreen-doctor -o`` output. Coordinates are global compositor
    coordinates, ready to feed to :func:`grab` as a rect.
    """
    try:
        proc = subprocess.run(
            ["kscreen-doctor", "-o"],
            capture_output=True, text=True, timeout=15, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "kscreen-doctor not found; monitor_rects() requires KDE's "
            "kscreen tools on PATH") from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"kscreen-doctor -o failed ({proc.returncode}): "
            f"{proc.stderr.strip()}")

    # kscreen-doctor colourises its output even when piped (ANSI SGR
    # sequences around labels and values, found on-box 2026-11-04);
    # strip them or no line ever matches the patterns below.
    clean = _ANSI_RE.sub("", proc.stdout)

    monitors: list[dict] = []
    current: dict | None = None
    for line in clean.splitlines():
        out_match = _OUTPUT_RE.match(line)
        if out_match:
            current = {"name": out_match.group(1)}
            monitors.append(current)
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped == "disabled":
            monitors.remove(current)
            current = None
            continue
        geo_match = _GEOMETRY_RE.match(line)
        if geo_match:
            x, y, w, h = (int(g) for g in geo_match.groups())
            current.update({"x": x, "y": y, "w": w, "h": h})
    return [m for m in monitors if "w" in m]
