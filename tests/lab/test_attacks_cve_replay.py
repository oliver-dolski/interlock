"""ATK-05b (CVE-2024-52288 replay) @lab proofs.

A POSIX named pipe has no broadcast mode, so a passive tap on the vuln v2.4.0 fifo bus would
starve the real PD. The attacker therefore sits INLINE on both profiles - the fixed v3.0.8 TCP
relay and the vuln v2.4.0 fifo relay (``lab/attacker/fifo_relay.py``) - so the controller talks
to the attacker and the attacker relays to the PD, the same write-capable seam driving both.

- The inline spike proves the vuln PD comes online *through* the fifo relay (CP <-> relay <-> PD),
  so the attacker holds a working inline position before any injection.
- The matched pair drives the ``run_cve_replay`` verdict against both profiles. The inline relay
  captures the live Secure Channel frames and replays them in-band, aligned to the CP's expected
  2-bit OSDP sequence (04-10), so the result is deterministic: on the pinned-vulnerable v2.4.0
  core the aligned ``REPLY_RMAC_I`` rewinds the CP's r_mac and the CP authorises a SECOND unlock
  off the replayed card read, and on the fixed v3.0.8 core the out-of-state ``REPLY_RMAC_I`` is
  rejected ("Out of order REPLY_RMAC_I") so no second unlock follows. The oracle is the CP-side
  re-authorisation count (the flaw lives in the controller, and the replay desynchronises CP<->PD
  so there is no second PD lock transition to watch), and each case gates on the PD coming online
  first (Pitfall 4).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

from interlock.osdp.attacks.replay import run_cve_replay

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

VULN_OVERRIDE = "docker-compose.vuln.yml"
CVE_OVERRIDE = "docker-compose.cve.yml"


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

# The fixed v3.0.8 core's actual rejection line (libosdp osdp_cp.c): the aligned, RMAC_I-first
# replay reaches the real CVE fix path (not a sequence or CCRYPT mismatch), and the controller
# rejects the out-of-state REPLY_RMAC_I here. This is what makes the fixed pass a proof of the
# RMAC_I mitigation rather than an accidental seq/CCRYPT rejection.
_RMAC_I_REJECTED = "Out of order REPLY_RMAC_I"

# The inline relay performs the real byte replay in-band; run_cve_replay needs one non-empty
# element so it issues exactly one inject() call (the arm + wait), not the wire frames themselves.
_ARM_TOKEN = b"arm-inline-relay"


def _cp_authorisations(lab: ComposeHandle) -> int:
    """Return how many unlocks the controller has authorised (count-based CP-side oracle)."""
    return lab.logs("cp").count(_CP_AUTHORISED)


@pytest.mark.lab
def test_cve_replay_matched_pair_succeeds_on_vuln(compose_up: ComposeUp) -> None:
    """The CVE replay makes the vulnerable v2.4.0 CP re-authorise an unlock off a replayed card."""
    lab = compose_up("cve-replay", overrides=(VULN_OVERRIDE,))

    # Precondition (Pitfall 4): gate on the vuln PD online before injecting, so a bus-down is
    # never mistaken for a replay outcome.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "cve-replay: vuln PD never came online"
    )
    # Baseline: the controller authorises one genuine unlock on the real card read (#1). If the
    # vulnerable CP accepts the aligned REPLY_RMAC_I + replayed card read, it authorises a second.
    assert lab.wait_for_log("cp", _CP_AUTHORISED, timeout=90), (
        "cve-replay: vuln CP never authorised its genuine unlock (no baseline)"
    )
    baseline = _cp_authorisations(lab)

    armed = {"done": False}

    def _arm_cve(_token: bytes) -> None:
        """Arm the inline fifo relay once, then wait (bounded) for the second authorisation.

        Arming lets the relay replay the live-captured secure frames in-band, aligned to the CP's
        expected sequence; the one bounded wait replaces the old per-frame 30s loop.
        """
        if not armed["done"]:
            trigger = lab.compose("exec", "-T", "attacker", "touch", "/tmp/interlock-cve-fire")
            assert trigger.returncode == 0, (
                f"cve-replay: failed to arm the fifo relay: {trigger.stdout}{trigger.stderr}"
            )
            armed["done"] = True
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline and _cp_authorisations(lab) <= baseline:
            time.sleep(2.0)

    findings = run_cve_replay(
        [_ARM_TOKEN],
        _arm_cve,
        lambda: _cp_authorisations(lab) > baseline,
    )

    assert len(findings) == 1, f"vuln CP did not re-authorise on the aligned replay: {findings}"
    assert findings[0].id == "ATK-05b-cve-2024-52288-rmac-replay"
    assert findings[0].severity.value == "high"
    assert _cp_authorisations(lab) > baseline, (
        "cve-replay: vuln CP authorisation count did not increase after the replay"
    )


@pytest.mark.lab
def test_cve_replay_matched_pair_fails_on_fixed(compose_up: ComposeUp) -> None:
    """The same CVE replay is defeated on the fixed libosdp v3.0.8 sc-scbkd TCP profile."""
    lab = compose_up("sc-scbkd", overrides=(CVE_OVERRIDE,))

    # Precondition (Pitfall 4): the fixed PD MUST come online, or a "fixed fails" verdict would be
    # a bus-down false pass rather than a genuine RMAC rejection.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "cve-replay: fixed PD never came online (an invalid bus-down result, not the fix)"
    )
    # Baseline: the controller authorises one genuine unlock (#1). On the fixed core the aligned,
    # out-of-state REPLY_RMAC_I is rejected, so the CP must NOT authorise a second (#2).
    assert lab.wait_for_log("cp", _CP_AUTHORISED, timeout=90), (
        "cve-replay: fixed CP never authorised its genuine unlock (no baseline)"
    )
    baseline = _cp_authorisations(lab)

    armed = {"done": False}

    def _arm_cve(_token: bytes) -> None:
        """Arm the inline cve relay once, then wait (bounded) for the RMAC_I rejection.

        The aligned, RMAC_I-first replay reaches the fixed core's real CVE fix path; the wait ends
        as soon as the controller logs the out-of-state rejection (or a second unlock, which would
        mean the fix did not hold).
        """
        if not armed["done"]:
            trigger = lab.compose("exec", "-T", "attacker", "touch", "/tmp/interlock-cve-fire")
            assert trigger.returncode == 0, (
                f"cve-replay: failed to arm the cve relay: {trigger.stdout}{trigger.stderr}"
            )
            armed["done"] = True
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            logs = lab.logs("cp")
            if _RMAC_I_REJECTED in logs or logs.count(_CP_AUTHORISED) > baseline:
                return
            time.sleep(2.0)

    findings = run_cve_replay(
        [_ARM_TOKEN],
        _arm_cve,
        lambda: _cp_authorisations(lab) > baseline,
    )

    assert findings == [], f"fixed profile replay unexpectedly re-authorised: {findings}"

    # The fix holds for the RIGHT reason: the fixed CP reached and rejected the out-of-state
    # REPLY_RMAC_I (the actual v3.0.8 fix path), not merely a sequence or CCRYPT mismatch.
    assert _RMAC_I_REJECTED in lab.logs("cp"), (
        "cve-replay: fixed CP never logged the out-of-state REPLY_RMAC_I rejection "
        "(the aligned replay did not reach the real fix path)"
    )

    # Robustness: give the armed relay a bounded window and confirm the fixed CP still never
    # authorises a second unlock - the failure is the RMAC_I rejection, not a race.
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        assert _cp_authorisations(lab) == baseline, (
            "cve-replay: fixed CP unexpectedly re-authorised on replay (the fix did not hold)"
        )
        time.sleep(4.0)
