#!/usr/bin/env python3
"""Smoke driver: stage 1 (guardian latch cycle) for the P1 on-box smoke.

Run by smoke.sh; talks to a guardian started with the smoke config
(fake actuator). Prints PASS/FAIL lines; exit code = failures.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # hands/linux/

from guardian_client import GuardianClient, GuardianUnavailable  # noqa: E402

fails = 0


def check(name, cond, detail=""):
    global fails
    print(f"{'PASS' if cond else 'FAIL'} stage1: {name} {detail}")
    if not cond:
        fails += 1


def main():
    sock = os.environ["SMOKE_GUARDIAN_SOCKET"]
    client = GuardianClient(sock)
    try:
        st = client.state()
    except GuardianUnavailable as e:
        check("guardian reachable", False, str(e))
        return 1
    check("guardian reachable", True)
    check("starts STOPPED (fail-safe)", st.get("stopped") is True, str(st))

    resp = client.act("mouse", [{"t": "move", "x": 10, "y": 10}])
    check("act refused while stopped",
          resp.get("ok") is False and resp.get("error_code") == "emergency_stop",
          str(resp))

    # The client's stop uses the session peer; resume must refuse here.
    client.stop("api")
    st = client.state()
    check("stop latches", st.get("stopped") is True)

    # No client resume by design — prove the refusal over the raw socket.
    import json
    import socket as socket_mod
    s = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
    s.connect(sock)
    s.sendall(b'{"op":"resume"}\n')
    reply = json.loads(s.makefile("rb").readline().decode())
    s.close()
    check("session-side resume refused",
          reply.get("ok") is False and "polkit" in str(reply.get("error", "")),
          str(reply))
    print("stage1 done — resume happens in smoke.sh via pkexec (fresh auth).")
    return fails


if __name__ == "__main__":
    sys.exit(main())
