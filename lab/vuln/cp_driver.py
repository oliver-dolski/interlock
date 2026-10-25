"""Control Panel driver for the cve-replay profile (vulnerable libosdp v2.4.0).

Runs as the ``cp`` container's entrypoint under the docker-compose.vuln.yml
override. Like its PD sibling, it targets the OLD raw C-extension API of the
v2.4.0 build (dict-based ``pd_info`` list, manual ``refresh()`` loop, ``status`` /
``sc_status`` bitmasks, event callback) and is kept SEPARATE from
``lab/osdp/cp_driver.py`` (RESEARCH Pitfall 2). It holds the SCBK-D key so Secure
Channel comes up on the vulnerable core, confirming the CVE-2024-52288 bus is live;
the replay attack itself belongs to Phase 4.

The CP is the fifo client. The PD (server) creates the pipes, so the CP retries
constructing the ControlPanel until the fifos exist, absorbing the compose
start-order race (RESEARCH Pitfall 5).
"""

from __future__ import annotations

import os
import sys
import time

import osdp

PD_ADDRESS = 101
PD_OFFSET = 0
EXPECTED_SCENARIO = "cve-replay"
CONSTRUCT_RETRIES = 30
CONSTRUCT_BACKOFF_SECONDS = 1.0
ONLINE_TIMEOUT_SECONDS = 60.0
REFRESH_INTERVAL_SECONDS = 0.02

# Must match the PD's fifo device on the shared volume.
BUS_DEVICE = "/busvol/cp_bus"

# OSDP specification default Secure Channel Base Key (SCBK-D), bytes 0x30..0x3F.
# Same value as lab/osdp/scenarios.SCBK_D; duplicated so the vuln drivers stay
# separate from lab/osdp/* (RESEARCH Pitfall 2). Spec default, not a vendor key
# (SAFE-03).
SCBK_D = bytes(range(0x30, 0x40))

_card_reads = 0


def _require_scenario() -> None:
    """Fail closed unless LAB_SCENARIO is exactly cve-replay (ASVS V5)."""
    scenario = os.environ.get("LAB_SCENARIO", "")
    if scenario != EXPECTED_SCENARIO:
        print(
            f"interlock-lab: vuln CP serves only {EXPECTED_SCENARIO!r}, "
            f"got LAB_SCENARIO={scenario!r}",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2)


def _on_event(address: int, event: dict[str, object]) -> None:
    """Count every card-read the PD delivers (including CVE-replayed ones)."""
    global _card_reads
    if event.get("event") == osdp.EVENT_CARDREAD:
        _card_reads += 1


def _build_control_panel() -> osdp.ControlPanel:
    """Construct the ControlPanel, retrying until the PD has created the fifos."""
    pd_info = [
        {
            "address": PD_ADDRESS,
            "flags": 0,
            "scbk": SCBK_D,
            "channel_type": "fifo",
            "channel_speed": 115200,
            "channel_device": BUS_DEVICE,
        }
    ]
    last_error: OSError | None = None
    for _attempt in range(CONSTRUCT_RETRIES):
        try:
            return osdp.ControlPanel(pd_info)
        except OSError as exc:  # the C-ext raises PermissionError until the fifos exist
            last_error = exc
            time.sleep(CONSTRUCT_BACKOFF_SECONDS)
    raise ConnectionError(
        f"could not open the cve-replay bus at {BUS_DEVICE}"
    ) from last_error


def main() -> None:
    """Bring up the vulnerable CP, report PD online, SC active, and the first event."""
    _require_scenario()
    print(f"interlock-lab: CP starting scenario={EXPECTED_SCENARIO}", flush=True)

    cp = _build_control_panel()
    cp.set_loglevel(osdp.LOG_INFO)
    cp.set_event_callback(_on_event)
    print(f"interlock-lab: libosdp version={cp.get_version()}", flush=True)

    online_reported = False
    sc_reported = False
    unlocks_sent = 0
    deadline = time.monotonic() + ONLINE_TIMEOUT_SECONDS
    while True:
        cp.refresh()

        if not online_reported and (cp.status() & (1 << PD_OFFSET)):
            print(f"interlock-lab: PD {PD_ADDRESS} online", flush=True)
            online_reported = True

        sc_up = bool(cp.sc_status() & (1 << PD_OFFSET))
        if not sc_reported and sc_up:
            print("interlock-lab: cve-replay SC active", flush=True)
            sc_reported = True

        # The controller authorises a door-open on every valid card read by issuing a secure
        # CMD_OUT. The first (genuine) card read is baseline lock-state sentinel #1; the
        # CVE-2024-52288 replay re-delivers that secure card read to this vulnerable CP, which then
        # authorises a SECOND unlock (sentinel #2) off a credential it never saw live.
        if sc_up and _card_reads > unlocks_sent:
            if unlocks_sent == 0:
                print("interlock-lab: event received", flush=True)
            ok = cp.send_command(
                PD_OFFSET,
                {"command": osdp.CMD_OUTPUT, "output_no": 0, "control_code": 2, "timer_count": 0},
            )
            print(
                f"interlock-lab: CP authorised unlock on card read ok={ok}",
                flush=True,
            )
            unlocks_sent += 1

        if not online_reported and time.monotonic() > deadline:
            print(
                f"interlock-lab: CP waiting online status={cp.status()} "
                f"sc_status={cp.sc_status()}",
                flush=True,
            )
            deadline = time.monotonic() + ONLINE_TIMEOUT_SECONDS

        time.sleep(REFRESH_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
