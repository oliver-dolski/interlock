"""Control Panel (controller) driver for the OSDP lab.

Runs as the ``cp`` container's entrypoint. The configuration is chosen by the
``LAB_SCENARIO`` environment variable: it is looked up in ``scenarios`` (the one
validated selection path) and the CP is built from the returned descriptor. An
unknown, empty, or unset value fails closed - the driver lists the valid values on
stderr and exits non-zero rather than defaulting to a scenario (ASVS V5).

The CP holds the Secure Channel key for the profile (``None`` for clear-text) and
adds ``EnforceSecure`` only when the profile enforces it - the downgrade profile
deliberately does not, which is what lets a later MITM force clear-text. The CP
dials the upstream PD (``CP_UPSTREAM``, default ``pd:10000``) with retry, brings up
a LibOSDP ``ControlPanel``, and prints a sentinel when the PD comes online and again
when it receives the PD's card-read event. Those two sentinels are what the smoke
test asserts.
"""

from __future__ import annotations

import os
import sys
import time

import scenarios
from osdp import Command, ControlPanel, Event, LibFlag, LogLevel, PDInfo
from tcp_channel import LAB_PORT, TCPChannel, connect_with_retry

PD_ADDRESS = 101
ONLINE_TIMEOUT_SECONDS = 30
EVENT_POLL_TIMEOUT_SECONDS = 30

# The one legitimate secure CMD_OUT the controller issues under the cve-replay profile: a real
# "controller authorises door open" command carried over the active Secure Channel. It is the
# genuine secure frame the CVE-2024-52288 replay later re-plays without the key; the lab emits
# it ONLY when CVE_LAB is set (the cve override), so every other scenario's bus is unchanged.
_CVE_LAB = os.environ.get("CVE_LAB") == "1"
# output_no=0, control_code=2 (permanent ON = unlock), timer=0 - the same output semantics the
# forged-unlock spoof uses, but here sent legitimately by the CP, in-channel.
_LEGIT_UNLOCK = {"command": Command.Output, "output_no": 0, "control_code": 2, "timer_count": 0}


def _upstream() -> tuple[str, int]:
    """Parse ``CP_UPSTREAM`` (``host:port``) with a ``pd:10000`` default."""
    raw = os.environ.get("CP_UPSTREAM", f"pd:{LAB_PORT}")
    host, _, port = raw.partition(":")
    return host, int(port) if port else LAB_PORT


def _select_profile() -> scenarios.Profile:
    """Resolve LAB_SCENARIO to a profile, or fail closed with the valid values."""
    name = os.environ.get("LAB_SCENARIO", "")
    try:
        return scenarios.get(name)
    except KeyError:
        valid = ", ".join(scenarios.valid_values())
        print(
            f"interlock-lab: unknown LAB_SCENARIO {name!r}. Valid values: {valid}",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2) from None


def main() -> None:
    """Bring up the CP for the selected scenario and report PD online and the first event."""
    profile = _select_profile()
    scenario = os.environ["LAB_SCENARIO"]
    host, port = _upstream()
    print(
        f"interlock-lab: CP starting scenario={scenario} upstream={host}:{port}",
        flush=True,
    )

    # The CP holds the profile's Secure Channel key and enforces SC only when the
    # profile asks it to. The downgrade profile leaves EnforceSecure off on purpose. The
    # cve-replay profile does NOT enforce it either: sc-scbkd is install-mode (the PD derives
    # SCBK-D through the first handshake), and EnforceSecure would drop the PD offline before SC
    # comes up. The CVE replay re-plays genuine SECURE frames, not clear-text, so the fixed core
    # defeats it through the RMAC-freshness fix itself - no clear-text path to fence off.
    cp_flags = [LibFlag.EnforceSecure] if profile.enforce_secure else []

    sock = connect_with_retry(host, port)
    pd_info = PDInfo(PD_ADDRESS, TCPChannel(sock), scbk=profile.scbk, flags=cp_flags)
    cp = ControlPanel([pd_info], log_level=LogLevel.Info)
    cp.start()

    cp.online_wait(PD_ADDRESS, timeout=ONLINE_TIMEOUT_SECONDS)
    print(f"interlock-lab: PD {PD_ADDRESS} online", flush=True)

    while True:
        event = cp.get_event(PD_ADDRESS, timeout=EVENT_POLL_TIMEOUT_SECONDS)
        if event is not None and event.get("event") == Event.CardRead:
            print("interlock-lab: event received", flush=True)
            if not _CVE_LAB:
                break
            # cve-replay: the controller authorises a door-open on a valid card read by issuing a
            # secure CMD_OUT. The first (genuine) card read is baseline sentinel #1; the
            # CVE-2024-52288 replay re-delivers this secure card read to the CP, so a vulnerable CP
            # authorises a SECOND unlock (sentinel #2) off a replayed credential it never saw live.
            cp.send_command(PD_ADDRESS, _LEGIT_UNLOCK)
            print("interlock-lab: CP authorised unlock on card read", flush=True)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
