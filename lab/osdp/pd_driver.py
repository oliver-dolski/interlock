"""Peripheral Device (reader) driver for the OSDP lab.

Runs as the ``pd`` container's entrypoint. For this walking-skeleton slice the
configuration is a single clear-text profile (``scbk=None``, no Secure Channel):
the thinnest PD<->CP exchange that proves the transport and LibOSDP wiring. The
``LAB_SCENARIO`` environment variable is read and logged now; scenario branching
lands in plan 02-02.

The PD listens on the lab TCP port, brings up a LibOSDP ``PeripheralDevice``,
waits until the ControlPanel has it online, and notifies a single card-read
event. It then idles so the refresh loop keeps the PD online for the lifetime of
the container.
"""

from __future__ import annotations

import os
import time

from osdp import (
    Capability,
    CardFormat,
    Event,
    LogLevel,
    PDCapabilities,
    PDInfo,
    PeripheralDevice,
)
from tcp_channel import LAB_PORT, TCPChannel, listen

PD_ADDRESS = 101
ONLINE_TIMEOUT_SECONDS = 30.0


def _card_read_event() -> dict[str, object]:
    """Build one 24-bit raw-Wiegand card-read event."""
    return {
        "event": Event.CardRead,
        "reader_no": 1,
        "format": CardFormat.Wiegand,
        "direction": 0,
        "length": 24,
        "data": bytes([0x55, 0xAA, 0x0F]),
    }


def main() -> None:
    """Bring up the clear-text PD, notify one card read once online, then idle."""
    scenario = os.environ.get("LAB_SCENARIO", "cleartext")
    print(f"interlock-lab: PD starting scenario={scenario}", flush=True)
    print(f"interlock-lab: PD listening on 0.0.0.0:{LAB_PORT}", flush=True)

    conn = listen("0.0.0.0", LAB_PORT)
    pd_info = PDInfo(PD_ADDRESS, TCPChannel(conn), scbk=None)
    pd_cap = PDCapabilities(
        [
            (Capability.OutputControl, 1, 1),
            (Capability.LEDControl, 2, 1),
            (Capability.AudibleControl, 1, 1),
            (Capability.TextOutput, 1, 1),
        ]
    )
    pd = PeripheralDevice(pd_info, pd_cap, log_level=LogLevel.Warning)
    pd.start()

    deadline = time.monotonic() + ONLINE_TIMEOUT_SECONDS
    while not pd.is_online() and time.monotonic() < deadline:
        time.sleep(0.1)
    print(f"interlock-lab: PD session online={pd.is_online()}", flush=True)

    pd.notify_event(_card_read_event())
    print("interlock-lab: PD notified card read", flush=True)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
