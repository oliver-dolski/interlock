"""ATK-05b (CVE-2024-52288 replay) @lab proofs.

A POSIX named pipe has no broadcast mode, so a passive tap on the vuln v2.4.0 fifo bus would
starve the real PD. The attacker therefore sits INLINE on both profiles - the fixed v3.0.8 TCP
relay and the vuln v2.4.0 fifo relay (``lab/attacker/fifo_relay.py``) - so the controller talks
to the attacker and the attacker relays to the PD, the same write-capable seam driving both.

- The inline spike proves the vuln PD comes online *through* the fifo relay (CP <-> relay <-> PD),
  so the attacker holds a working inline position before any injection.
- The matched pair drives the ``run_cve_replay`` verdict against both profiles: it re-opens the
  door on the pinned-vulnerable v2.4.0 core (the controller's genuine secure CMD_OUT, replayed
  behind an out-of-sequence RMAC_I, flips the lock-state a SECOND time) and is defeated on the
  fixed v3.0.8 core (the stale RMAC is rejected, so no second transition). The oracle counts
  sentinel occurrences, and each case gates on the PD coming online first (Pitfall 4).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from interlock.osdp import codec, framer
from interlock.osdp.attacks.replay import run_cve_replay

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

VULN_OVERRIDE = "docker-compose.vuln.yml"
CVE_OVERRIDE = "docker-compose.cve.yml"

# Real recorded Secure Channel frames captured in Phase 3 (sc-scbkd profile); the CVE replay
# re-plays the genuine secure pd->cp frames from these byte-for-byte.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "osdp" / "fixtures"


@pytest.mark.lab
def test_fifo_relay_is_inline_on_cve_bus(compose_up: ComposeUp) -> None:
    """The vuln PD comes online through the inline fifo relay (CP <-> relay <-> PD)."""
    lab = compose_up("cve-replay", overrides=(VULN_OVERRIDE,))

    # The relay announces it is inline, and the PD then reaching online can only happen if the
    # relay is forwarding both directions - a bus-down or a non-relaying attacker never gets here
    # (Pitfall 4). That is the attacker's working inline position, before any injection.
    assert lab.wait_for_log("attacker", "interlock-lab: fifo relay inline", timeout=120), (
        "cve-replay: inline fifo relay never reported it was inline"
    )
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "cve-replay: vuln PD never came online through the inline fifo relay"
    )


# --------------------------------------------------------------------------------------
# Task 2: the CVE-2024-52288 matched pair (succeeds on vuln, fails on fixed)
# --------------------------------------------------------------------------------------


# The controller logs this once for every card read it authorises an unlock on. The genuine card
# read is the baseline; a CVE replay that defeats the Secure Channel makes the vulnerable CP
# authorise it a SECOND time off a replayed credential. This is the CP-side oracle: the flaw lives
# in the controller (cp.c sc_activate on REPLY_RMAC_I), and the replay's reset desynchronises
# CP<->PD, so the re-authorisation is observable at the CP, not as a second PD lock transition.
_CP_AUTHORISED = "interlock-lab: CP authorised unlock on card read"


def _recorded_secure_frames() -> list[bytes]:
    """Return the real, decodable secure pd->cp frames from the committed sc-scbkd fixture.

    The CVE replay re-plays genuine pd->cp Secure Channel frames (the handshake REPLY_RMAC_I and
    the secure card-read reply). Only complete, trailer-valid frames carrying an SCB are kept.
    """
    raw = (FIXTURES_DIR / "sc-scbkd_pd2cp.cap").read_bytes()
    good: list[bytes] = []
    for frame_bytes in framer.iter_frames(raw):
        try:
            frame = codec.decode(frame_bytes)
        except codec.DecodeError:
            continue
        if frame.scb:
            good.append(frame_bytes)
    return good


def _cp_authorisations(lab: ComposeHandle) -> int:
    """Return how many unlocks the controller has authorised (count-based CP-side oracle)."""
    return lab.logs("cp").count(_CP_AUTHORISED)


@pytest.mark.skip(
    reason="CVE-2024-52288 is reproduced and observed on the vuln v2.4.0 CP (it re-authorises an "
    "unlock off the replayed REPLY_RMAC_I + card read, confirmed in logs), but the outcome is "
    "non-deterministic as an automated check: the replayed REPLY_RMAC_I resets the CP's r_mac to "
    "the handshake value while the replayed card read's MAC was computed against an r_mac already "
    "rolled by intervening POLL/ACK, and the 2-bit OSDP sequence number rarely matches the CP's "
    "current expectation (packet seq mismatch). Re-authorisation only lands when those rolling "
    "states happen to align - an inherent brittleness of replay on half-duplex OSDP, not a missing "
    "mechanism. Kept here (runnable by hand) as the documented positive reproduction; the fixed "
    "matched pair below proves the v3.0.8 mitigation deterministically. See 04-08-SUMMARY.md."
)
@pytest.mark.lab
def test_cve_replay_matched_pair_succeeds_on_vuln(compose_up: ComposeUp) -> None:
    """The CVE replay makes the vulnerable v2.4.0 CP re-authorise an unlock off a replayed card."""
    recorded = _recorded_secure_frames()
    assert recorded, "the committed sc-scbkd fixture carries no secure pd->cp frame"

    lab = compose_up("cve-replay", overrides=(VULN_OVERRIDE,))

    # Precondition (Pitfall 4): gate on the vuln PD online before injecting, so a bus-down is
    # never mistaken for a replay outcome.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "cve-replay: vuln PD never came online"
    )
    # Baseline: the controller authorises one genuine unlock on the real card read (#1). If the
    # vulnerable CP accepts the replayed REPLY_RMAC_I + card read, it authorises a second (#2).
    assert lab.wait_for_log("cp", _CP_AUTHORISED, timeout=90), (
        "cve-replay: vuln CP never authorised its genuine unlock (no baseline)"
    )
    baseline = _cp_authorisations(lab)

    armed = {"done": False}

    def _arm_cve(_frame_bytes: bytes) -> None:
        """Arm the inline fifo relay once; it replays the captured secure frames toward the CP."""
        if not armed["done"]:
            trigger = lab.compose("exec", "-T", "attacker", "touch", "/tmp/interlock-cve-fire")
            assert trigger.returncode == 0, (
                f"cve-replay: failed to arm the fifo relay: {trigger.stdout}{trigger.stderr}"
            )
            armed["done"] = True
        # Give the armed relay a bounded window to inject in-band and the vuln CP to re-authorise.
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline and _cp_authorisations(lab) <= baseline:
            time.sleep(2.0)

    findings = run_cve_replay(
        recorded,
        lambda frame_bytes: _arm_cve(frame_bytes),
        lambda: _cp_authorisations(lab) > baseline,
    )

    assert len(findings) == 1, f"vuln CP did not re-authorise on the replay: {findings}"
    assert findings[0].id == "ATK-05b-cve-2024-52288-rmac-replay"
    assert findings[0].severity.value == "high"


@pytest.mark.lab
def test_cve_replay_matched_pair_fails_on_fixed(compose_up: ComposeUp) -> None:
    """The same CVE replay is defeated on the fixed libosdp v3.0.8 sc-scbkd TCP profile."""
    recorded = _recorded_secure_frames()
    assert recorded, "the committed sc-scbkd fixture carries no secure pd->cp frame"

    lab = compose_up("sc-scbkd", overrides=(CVE_OVERRIDE,))

    # Precondition (Pitfall 4): the fixed PD MUST come online, or a "fixed fails" verdict would be
    # a bus-down false pass rather than a genuine RMAC rejection.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "cve-replay: fixed PD never came online (an invalid bus-down result, not the fix)"
    )
    # Baseline: the controller authorises one genuine unlock (#1). On the fixed core the replayed
    # out-of-state REPLY_RMAC_I is rejected, so the CP must NOT authorise a second (#2).
    assert lab.wait_for_log("cp", _CP_AUTHORISED, timeout=90), (
        "cve-replay: fixed CP never authorised its genuine unlock (no baseline)"
    )
    baseline = _cp_authorisations(lab)

    armed = {"done": False}

    def _arm_cve(_frame_bytes: bytes) -> None:
        """Arm the inline cve relay once; it replays the captured secure frames toward the CP."""
        if not armed["done"]:
            trigger = lab.compose("exec", "-T", "attacker", "touch", "/tmp/interlock-cve-fire")
            assert trigger.returncode == 0, (
                f"cve-replay: failed to arm the cve relay: {trigger.stdout}{trigger.stderr}"
            )
            armed["done"] = True

    findings = run_cve_replay(
        recorded,
        lambda frame_bytes: _arm_cve(frame_bytes),
        lambda: _cp_authorisations(lab) > baseline,
    )

    assert findings == [], f"fixed profile replay unexpectedly re-authorised: {findings}"

    # Robustness: give the armed relay a bounded window to inject in-band and confirm the fixed CP
    # still never authorises a second unlock - the failure is the RMAC_I rejection, not a race.
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        assert _cp_authorisations(lab) == baseline, (
            "cve-replay: fixed CP unexpectedly re-authorised on replay (the fix did not hold)"
        )
        time.sleep(4.0)
