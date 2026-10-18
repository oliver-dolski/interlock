"""Peripheral Device (reader) driver for the OSDP lab.

Runs as the ``pd`` container's entrypoint. The configuration is chosen by the
``LAB_SCENARIO`` environment variable: it is looked up in ``scenarios`` (the one
validated selection path) and the PD is built from the returned descriptor. An
unknown, empty, or unset value fails closed - the driver lists the valid values on
stderr and exits non-zero rather than defaulting to a scenario (ASVS V5).

The PD listens on the lab TCP port, brings up a LibOSDP ``PeripheralDevice``,
waits until the ControlPanel has it online, and notifies a single card-read
event. It then idles so the refresh loop keeps the PD online for the lifetime of
the container. For the ``cleartext`` profile this is the clear-text tracer path
the smoke test asserts; the ``sc-scbkd`` and ``downgrade`` profiles bring up
Secure Channel (see ``scenarios`` for the confirmed flag mapping).
"""

from __future__ import annotations

import os
import sys
import time

import scenarios
from osdp import (
    Capability,
    CardFormat,
    Command,
    Event,
    LibFlag,
    LogLevel,
    PDCapabilities,
    PDInfo,
    PeripheralDevice,
)
from tcp_channel import LAB_PORT, TCPChannel, listen

PD_ADDRESS = 101
ONLINE_TIMEOUT_SECONDS = 30.0

# The single lock-state sentinel every door-open attack (ATK-05a replay, ATK-08 spoof) proves
# itself against (D-05). Wave-0 spike confirmed empirically (2026-10-18) that the high-level
# PeripheralDevice command callback receives {'command': Command.Output, ...} when it processes
# a CMD_OUT: fired unconditionally on every output command, regardless of control_code - the
# oracle is the sentinel's appearance itself, not the specific output semantics.
_LOCK_STATE_SENTINEL = "interlock-lab: LOCK state=UNLOCKED"


def _handle_command(command: dict[str, object]) -> tuple[int, None]:
    """Accept every command; fire the single D-05 lock-state sentinel on CMD_OUT.

    Mirrors the accept-everything command handler in ``lab/vuln/pd_driver.py``. This is the
    ONLY lab instrumentation Phase 4 adds (D-05, Pitfall 2 - do not over-instrument): one
    sentinel log line when an output command is processed, nothing else new, and no other
    lab-internal state exposed.
    """
    if command.get("command") == Command.Output:
        print(_LOCK_STATE_SENTINEL, flush=True)
    return 0, None


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
    """Bring up the PD for the selected scenario, notify one card read, then idle."""
    profile = _select_profile()
    scenario = os.environ["LAB_SCENARIO"]
    print(f"interlock-lab: PD starting scenario={scenario}", flush=True)
    print(f"interlock-lab: PD listening on 0.0.0.0:{LAB_PORT}", flush=True)

    # The PD runs install mode (scbk=None, derives the default SCBK-D) whenever the
    # profile carries the InstallMode flag; otherwise it uses the profile's explicit key.
    install_mode = "InstallMode" in profile.flags
    pd_scbk = None if install_mode else profile.scbk
    pd_flags = [getattr(LibFlag, flag) for flag in profile.flags]

    conn = listen("0.0.0.0", LAB_PORT)
    pd_info = PDInfo(PD_ADDRESS, TCPChannel(conn), scbk=pd_scbk, flags=pd_flags)
    pd_cap = PDCapabilities(
        [(getattr(Capability, name), compliance, count) for name, compliance, count in profile.caps]
    )
    pd = PeripheralDevice(
        pd_info, pd_cap, log_level=LogLevel.Info, command_handler=_handle_command
    )
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
