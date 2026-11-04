#!/bin/bash
# HandsRelay Linux port — P1 on-box smoke test (Gordon-PC, KDE Wayland).
#
# Run from the extracted bundle:   bash smoke.sh
# Everything is logged to smoke-log.txt — paste that file back to Sprx.
#
# Stages:
#   0  setup: venv + python deps, .desktop identity, polkit resume action
#   1  guardian latch cycle with the fake actuator (no input is injected)
#   2  ScreenShot2 capture probes (direct + via .desktop identity)
#   3  full loop with real ydotool actuation through the guardian:
#      resume via pkexec (fresh password), app up, screenshot, click +
#      type into a text editor YOU watch. Skip conditions are printed.
#
# Root is used only for: installing the polkit action + resume helper,
# and running the guardian (a root daemon by design). Nothing else on
# the system is changed; all state lives in this folder's run/ dir.

set -u
cd "$(dirname "$0")"
SMOKE_DIR="$PWD"
LINUX_DIR="$(dirname "$SMOKE_DIR")"
RUN_DIR="$SMOKE_DIR/run"
mkdir -p "$RUN_DIR"
LOG="$SMOKE_DIR/smoke-log.txt"
exec > >(tee -a "$LOG") 2>&1

echo "=== HandsRelay P1 smoke — $(date -Is) on $(hostname) ==="
MY_UID="$(id -u)"
MY_GROUP="$(id -gn)"
GUARDIAN_SOCK="$RUN_DIR/guardian.sock"
export SMOKE_GUARDIAN_SOCKET="$GUARDIAN_SOCK"

# ---------- stage 0: setup -------------------------------------------------
echo "--- stage 0: setup"
if [ ! -x "$SMOKE_DIR/.venv/bin/python" ]; then
  python3 -m venv "$SMOKE_DIR/.venv" || { echo "FAIL stage0: venv creation"; exit 1; }
  "$SMOKE_DIR/.venv/bin/pip" install --quiet flask pillow dbus-fast \
    || { echo "FAIL stage0: pip install"; exit 1; }
fi
PY="$SMOKE_DIR/.venv/bin/python"
echo "python deps ok ($PY)"

install -Dm644 "$LINUX_DIR/packaging/org.gordy.handsrelay.desktop" \
  "$HOME/.local/share/applications/org.gordy.handsrelay.desktop" \
  && echo "desktop identity installed"

if [ ! -f /usr/share/polkit-1/actions/org.gordy.handsrelay.resume.policy ]; then
  echo "installing polkit resume action + helper (sudo)…"
  sudo install -Dm644 "$LINUX_DIR/packaging/org.gordy.handsrelay.resume.policy" \
    /usr/share/polkit-1/actions/org.gordy.handsrelay.resume.policy
  sudo install -Dm755 "$LINUX_DIR/packaging/handsrelay-resume" \
    /usr/lib/handsrelay/handsrelay-resume
fi
echo "polkit resume action present"

if command -v ydotool >/dev/null && command -v ydotoold >/dev/null; then
  echo "ydotool present: $(ydotool --version 2>/dev/null || echo '?')"
  HAVE_YDOTOOL=1
else
  echo "NOTE: ydotool missing — stage 3 will be skipped."
  echo "      Install with:  sudo pacman -S ydotool"
  HAVE_YDOTOOL=0
fi

write_config () {  # $1 = actuator kind
  cat > "$RUN_DIR/config.json" <<EOF
{
  "session_uid": $MY_UID,
  "socket_group": "$MY_GROUP",
  "actuator": "$1",
  "state_dir": "$RUN_DIR",
  "guardian_socket": "$GUARDIAN_SOCK",
  "ydotoold_socket": "$RUN_DIR/ydotoold.sock",
  "ydotoold_autostart": true
}
EOF
}

start_guardian () {  # $1 = actuator kind
  write_config "$1"
  sudo pkill -f "guardian.py --config $RUN_DIR/config.json" 2>/dev/null
  sleep 0.5
  rm -f "$GUARDIAN_SOCK"
  sudo nohup "$PY" "$LINUX_DIR/guardian.py" --config "$RUN_DIR/config.json" \
    > "$RUN_DIR/guardian-$1.log" 2>&1 &
  for i in $(seq 1 40); do
    if SMOKE_GUARDIAN_SOCKET="$GUARDIAN_SOCK" "$PY" -c "
import os, sys
sys.path.insert(0, \"$LINUX_DIR\")
from guardian_client import GuardianClient
GuardianClient(os.environ[\"SMOKE_GUARDIAN_SOCKET\"]).state()
" 2>/dev/null; then return 0; fi
    sleep 0.3
  done
  echo "FAIL: guardian socket never appeared; see run/guardian-$1.log"
  return 1
}

# ---------- stage 1: latch cycle (fake actuator) ---------------------------
echo "--- stage 1: guardian latch cycle (fake actuator, nothing injected)"
start_guardian fake || exit 1
"$PY" "$SMOKE_DIR/smoke_drive.py" || echo "stage1 had failures (see above)"

echo "Now resume via pkexec — a password prompt should appear (fresh auth,"
echo "every time; nothing cached). This is the ONLY resume path."
pkexec /usr/lib/handsrelay/handsrelay-resume "$GUARDIAN_SOCK"
"$PY" - <<EOF
import sys
sys.path.insert(0, "$LINUX_DIR")
from guardian_client import GuardianClient
st = GuardianClient("$GUARDIAN_SOCK").state()
print(("PASS" if st.get("stopped") is False else "FAIL"),
      "stage1: resumed via pkexec helper ->", st)
EOF

# ---------- stage 2: capture probes ---------------------------------------
echo "--- stage 2: ScreenShot2 capture probes"
"$PY" "$SMOKE_DIR/probe_capture.py" "$RUN_DIR/probe-direct.png" \
  && echo "PASS stage2: direct launch capture" \
  || echo "FAIL stage2: direct launch capture (see error above)"

cat > "$HOME/.local/share/applications/org.gordy.handsrelay-probe.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=HandsRelay Capture Probe
Exec=$PY $SMOKE_DIR/probe_capture.py $RUN_DIR/probe-desktop.png
Terminal=false
X-KDE-DBUS-Restricted-Interfaces=org.kde.KWin.ScreenShot2;org.kde.KWin.EIS.RemoteDesktop
EOF
rm -f "$RUN_DIR/probe-desktop.png"
# gtk-launch choked on this box in run 1 (GLib assertion); try it, then
# gio launch, then KDE's kioclient — log which one actually fired.
for launcher in gtk gio kio; do
  case $launcher in
    gtk) gtk-launch org.gordy.handsrelay-probe 2>&1 | head -2 ;;
    gio) gio launch "$HOME/.local/share/applications/org.gordy.handsrelay-probe.desktop" 2>&1 | head -2 ;;
    kio) kioclient exec "$HOME/.local/share/applications/org.gordy.handsrelay-probe.desktop" 2>&1 | head -2 ;;
  esac
  for i in $(seq 1 30); do [ -f "$RUN_DIR/probe-desktop.png" ] && break; sleep 0.5; done
  [ -f "$RUN_DIR/probe-desktop.png" ] && { echo "probe launched via: $launcher"; break; }
done
if [ -f "$RUN_DIR/probe-desktop.png" ]; then
  echo "PASS stage2: .desktop-identity capture"
else
  echo "FAIL stage2: .desktop-identity capture (no PNG appeared)"
fi

# ---------- stage 3: full loop, real actuation -----------------------------
echo "--- stage 3: full loop (ydotool actuation through the guardian)"
if [ "$HAVE_YDOTOOL" = "0" ]; then
  echo "SKIP stage3: ydotool not installed"
else
  EDITOR=""
  for e in kate gedit gnome-text-editor code; do
    command -v "$e" >/dev/null && { EDITOR="$e"; break; }
  done
  if [ -z "$EDITOR" ]; then
    echo "SKIP stage3: no known text editor found (kate/gedit/gnome-text-editor/code)"
  else
    SMK="hr-smoke-$$"
    start_guardian ydotool || exit 1
    pkexec /usr/lib/handsrelay/handsrelay-resume "$GUARDIAN_SOCK"
    HANDS_SECRET="$SMK" HANDS_GUARDIAN_SOCKET="$GUARDIAN_SOCK" \
      nohup "$PY" "$LINUX_DIR/hands_linux.py" > "$RUN_DIR/app.log" 2>&1 &
    APP_PID=$!
    sleep 2
    echo "state:  $(curl -s -H "X-Secret: $SMK" http://127.0.0.1:5000/state)"
    CODE=$(curl -s -H "X-Secret: $SMK" http://127.0.0.1:5000/screenshot \
      -o "$RUN_DIR/app-shot.png" -w "%{http_code}")
    echo "app screenshot HTTP $CODE -> $RUN_DIR/app-shot.png"
    echo "HANDS OFF mouse and keyboard for the next few seconds…"
    : > "$RUN_DIR/scratch.txt"
    nohup "$EDITOR" "$RUN_DIR/scratch.txt" >/dev/null 2>&1 &
    sleep 3
    curl -s -X POST -H "X-Secret: $SMK" -H 'Content-Type: application/json' \
      -d '{"x": 500, "y": 300}' http://127.0.0.1:5000/click; echo " <- click"
    curl -s -X POST -H "X-Secret: $SMK" -H 'Content-Type: application/json' \
      -d '{"text": "handsrelay p1 ok"}' http://127.0.0.1:5000/type; echo " <- type"
    sleep 1
    curl -s -H "X-Secret: $SMK" http://127.0.0.1:5000/screenshot \
      -o "$RUN_DIR/post-type.png"
    echo "post-type screenshot saved: $RUN_DIR/post-type.png (visual evidence)"
    echo
    echo "LOOK AT THE EDITOR: did 'handsrelay p1 ok' get typed into it?"
    read -r -p "Type YES if it did, NO if it didn't: " ANSWER
    echo "stage3 visual confirmation: $ANSWER"
    kill $APP_PID 2>/dev/null
  fi
fi

echo "--- cleanup: latching the stop and halting the smoke guardian"
"$PY" - <<EOF 2>/dev/null
import sys
sys.path.insert(0, "$LINUX_DIR")
from guardian_client import GuardianClient
print(GuardianClient("$GUARDIAN_SOCK").stop("api"))
EOF
sudo pkill -f "guardian.py --config $RUN_DIR/config.json" 2>/dev/null
echo "=== smoke done. Paste smoke-log.txt back to Sprx. ==="
