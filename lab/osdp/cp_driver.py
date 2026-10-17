"""Control Panel (controller) driver for the OSDP lab.

Runs as the ``cp`` container's entrypoint. For this walking-skeleton slice the
CP holds no key and never initiates a Secure Channel (clear-text profile): the
thinnest PD<->CP exchange. ``LAB_SCENARIO`` is read and logged now; scenario
branching lands in plan 02-02.

The CP dials the upstream PD (``CP_UPSTREAM``, default ``pd:10000``) with retry
to tolerate the compose start-order race, brings up a LibOSDP ``ControlPanel``,
and prints a sentinel when the PD comes online and again when it receives the
PD's card-read event. Those two sentinels are what the smoke test asserts.
"""

from __future__ import annotations

import os
import time

from osdp import ControlPanel, Event, LogLevel, PDInfo
from tcp_channel import LAB_PORT, TCPChannel, connect_with_retry

PD_ADDRESS = 101
ONLINE_TIMEOUT_SECONDS = 30
EVENT_POLL_TIMEOUT_SECONDS = 30

# OSDP specification default Secure Channel Base Key (SCBK-D), bytes 0x30..0x3F.
# This is the spec default, not a vendor production key (SAFE-03). The clear-text
# tracer leaves Secure Channel off and does not use it; the SCBK-D and downgrade
# profiles in plan 02-02 consume it.
SCBK_D = bytes(range(0x30, 0x40))


def _upstream() -> tuple[str, int]:
    """Parse ``CP_UPSTREAM`` (``host:port``) with a ``pd:10000`` default."""
    raw = os.environ.get("CP_UPSTREAM", f"pd:{LAB_PORT}")
    host, _, port = raw.partition(":")
    return host, int(port) if port else LAB_PORT


def main() -> None:
    """Bring up the clear-text CP and report PD online and the first event."""
    scenario = os.environ.get("LAB_SCENARIO", "cleartext")
    host, port = _upstream()
    print(
        f"interlock-lab: CP starting scenario={scenario} upstream={host}:{port}",
        flush=True,
    )

    sock = connect_with_retry(host, port)
    pd_info = PDInfo(PD_ADDRESS, TCPChannel(sock), scbk=None)
    cp = ControlPanel([pd_info], log_level=LogLevel.Warning)
    cp.start()

    cp.online_wait(PD_ADDRESS, timeout=ONLINE_TIMEOUT_SECONDS)
    print(f"interlock-lab: PD {PD_ADDRESS} online", flush=True)

    while True:
        event = cp.get_event(PD_ADDRESS, timeout=EVENT_POLL_TIMEOUT_SECONDS)
        if event is not None and event.get("event") == Event.CardRead:
            print("interlock-lab: event received", flush=True)
            break

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
