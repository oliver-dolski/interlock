"""Scenario selection tests: the fast allow-list contract and the per-profile SC state.

The first test is Docker-free and runs under ``-m "not lab"``: it is the assumption-delta
invariant guard that every declared scenario round-trips through ``scenarios.get()`` and that
bad input is rejected. The rest are ``@pytest.mark.lab`` integration tests that bring each
fixed profile up and assert its Secure Channel state in the LibOSDP logs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# The drivers import ``scenarios`` as a top-level module (their working dir is lab/osdp); make
# it importable on the host for the Docker-free contract test below.
_LAB_OSDP = Path(__file__).resolve().parents[2] / "lab" / "osdp"
if str(_LAB_OSDP) not in sys.path:
    sys.path.insert(0, str(_LAB_OSDP))

import scenarios

if TYPE_CHECKING:
    from conftest import ComposeUp


def test_every_scenario_round_trips() -> None:
    """Every declared scenario is selectable via get(); bad input is rejected exactly."""
    for scenario in scenarios.Scenario:
        profile = scenarios.get(scenario.value)
        assert isinstance(profile, scenarios.Profile)

    # Unknown, wrong-case, and whitespace-padded values are all rejected (no case-folding,
    # no coercion) so selection fails closed instead of defaulting to a scenario.
    for bad in ("nope", "CLEARTEXT", " cleartext "):
        with pytest.raises(KeyError):
            scenarios.get(bad)


@pytest.mark.lab
@pytest.mark.parametrize("scenario", ["cleartext", "sc-scbkd", "downgrade"])
def test_fixed_profile_secure_channel_state(compose_up: ComposeUp, scenario: str) -> None:
    """Each fixed profile comes up in its expected Secure Channel state (LAB-02)."""
    lab = compose_up(scenario)
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180)

    if scenario == "cleartext":
        cp_logs = lab.logs("cp")
        assert "Online; Without SC" in cp_logs
        assert "SC Active" not in cp_logs
    elif scenario == "sc-scbkd":
        # The PD logs the SCBK-D line because it runs install mode and derives the default key.
        assert lab.wait_for_log("pd", "SC Active with SCBK-D", timeout=60)
        assert "Online; With SC" in lab.logs("cp")
    elif scenario == "downgrade":
        # SC negotiation comes up on an explicit key, but the CP never enters enforced-secure
        # (no EnforceSecure), which is what lets a later MITM force clear-text.
        assert lab.wait_for_log("cp", "Online; With SC", timeout=60)
        cp_logs = lab.logs("cp")
        assert "ENFORCE_SECURE" not in cp_logs
        assert "SCBK-D" not in cp_logs
