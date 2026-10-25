"""Peripheral Device driver for the cve-replay profile (vulnerable libosdp v2.4.0).

Runs as the ``pd`` container's entrypoint under the docker-compose.vuln.yml
override. This driver is deliberately SEPARATE from ``lab/osdp/pd_driver.py``: the
v2.4.0 build exposes the OLD raw C-extension API (a dict-based ``pd_info``, a
manual ``refresh()`` loop, and a channel chosen by ``channel_type`` string), which
is incompatible with the fixed image's 3.0.8 ``osdp/*.py`` package (RESEARCH
Pitfall 2). It does only enough to bring up Secure Channel on the SCBK-D key so the
CVE-2024-52288 core behaviour is present; the actual replay attack is Phase 4.

Transport is a named pipe (fifo) on a shared volume, not TCP: the v2.4.0 C-ext API
offers no user-defined channel (only uart/msgq/fifo/unix_bus), so the inline TCP
attacker cannot sit on this bus in Phase 2. The PD is the fifo server - it creates
the pipes - so it must come up before the CP connects.
"""

from __future__ import annotations

import os
import sys
import time

import osdp

PD_ADDRESS = 101
EXPECTED_SCENARIO = "cve-replay"
ONLINE_TIMEOUT_SECONDS = 30.0
REFRESH_INTERVAL_SECONDS = 0.02

# The shared-volume fifo the CP connects to; the PD (server) creates <device>-0/-1.
BUS_DEVICE = "/busvol/pd_bus"

# OSDP specification default Secure Channel Base Key (SCBK-D), bytes 0x30..0x3F.
# Same value as lab/osdp/scenarios.SCBK_D, duplicated here on purpose: the vuln
# drivers are kept separate from lab/osdp/* (RESEARCH Pitfall 2). It is the spec
# default, not a vendor production key (SAFE-03).
SCBK_D = bytes(range(0x30, 0x40))

# The single lock-state sentinel every door-open attack proves itself against (D-05),
# mirrored here from lab/osdp/pd_driver.py's fixed-profile sentinel so the fifo bus
# exposes the same oracle: fired unconditionally on every output command, regardless
# of control_code - the oracle is the sentinel's appearance itself, not output
# semantics (Pitfall 2 - this is the only lab instrumentation Task 1 adds here).
_LOCK_STATE_SENTINEL = "interlock-lab: LOCK state=UNLOCKED"


def _require_scenario() -> None:
    """Fail closed unless LAB_SCENARIO is exactly cve-replay (ASVS V5)."""
    scenario = os.environ.get("LAB_SCENARIO", "")
    if scenario != EXPECTED_SCENARIO:
        print(
            f"interlock-lab: vuln PD serves only {EXPECTED_SCENARIO!r}, "
            f"got LAB_SCENARIO={scenario!r}",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2)


def _card_read_event() -> dict[str, object]:
    """Build one 24-bit raw-Wiegand card-read event (old C-ext event schema)."""
    return {
        "event": osdp.EVENT_CARDREAD,
        "reader_no": 1,
        "format": osdp.CARD_FMT_RAW_WIEGAND,
        "direction": 0,
        "length": 24,
        "data": bytes([0x55, 0xAA, 0x0F]),
    }


def _handle_command(command: dict[str, object]) -> dict[str, object]:
    """Accept every command; fire the single D-05 lock-state sentinel on CMD_OUT.

    Mirrors the accept-everything command handler in ``lab/osdp/pd_driver.py``, adapted
    to the v2.4.0 C-ext API's dict-keyed command type (``osdp.CMD_OUTPUT``) rather than
    the fixed image's ``Command.Output`` enum. This is the only lab instrumentation
    this task adds to the vuln PD, nothing else new.
    """
    if command.get("command") == osdp.CMD_OUTPUT:
        print(_LOCK_STATE_SENTINEL, flush=True)
    return {"return_code": 0}


def main() -> None:
    """Bring up the vulnerable PD with SC on SCBK-D, notify one card read, then idle."""
    _require_scenario()
    print(f"interlock-lab: PD starting scenario={EXPECTED_SCENARIO}", flush=True)

    pd_info = {
        "address": PD_ADDRESS,
        "flags": 0,
        "scbk": SCBK_D,
        "channel_type": "fifo",
        "channel_speed": 115200,
        "channel_device": BUS_DEVICE,
        "version": 1,
        "model": 1,
        "vendor_code": 0xCAFEBABE,
        "serial_number": 0xDEADBEAF,
        "firmware_version": 0x0000F00D,
    }
    pd_cap = [
        {"function_code": osdp.CAP_OUTPUT_CONTROL, "compliance_level": 1, "num_items": 1},
        {"function_code": osdp.CAP_READER_LED_CONTROL, "compliance_level": 2, "num_items": 1},
        {"function_code": osdp.CAP_READER_AUDIBLE_OUTPUT, "compliance_level": 1, "num_items": 1},
        {"function_code": osdp.CAP_READER_TEXT_OUTPUT, "compliance_level": 1, "num_items": 1},
    ]

    pd = osdp.PeripheralDevice(pd_info, capabilities=pd_cap)
    pd.set_loglevel(osdp.LOG_INFO)
    pd.set_command_callback(_handle_command)
    print(f"interlock-lab: libosdp version={pd.get_version()}", flush=True)
    print(f"interlock-lab: PD listening on fifo {BUS_DEVICE}", flush=True)

    deadline = time.monotonic() + ONLINE_TIMEOUT_SECONDS
    notified = False
    while True:
        pd.refresh()
        if not notified and pd.is_online() and pd.is_sc_active():
            print(f"interlock-lab: PD session online={pd.is_online()}", flush=True)
            pd.notify_event(_card_read_event())
            print("interlock-lab: PD notified card read", flush=True)
            notified = True
        if not notified and time.monotonic() > deadline:
            # Keep refreshing so the bus stays live even if SC lagged; report once.
            print(f"interlock-lab: PD online={pd.is_online()} sc={pd.is_sc_active()}", flush=True)
            deadline = time.monotonic() + ONLINE_TIMEOUT_SECONDS
        time.sleep(REFRESH_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
