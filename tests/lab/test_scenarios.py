"""Scenario selection tests: the fast allow-list contract and the per-profile SC state.

The first test is Docker-free and runs under ``-m "not lab"``: it is the assumption-delta
invariant guard that every declared scenario round-trips through ``scenarios.get()`` and that
bad input is rejected. The rest are ``@pytest.mark.lab`` integration tests that bring each
fixed profile up and assert its Secure Channel state in the LibOSDP logs.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# The drivers import ``scenarios`` as a top-level module (their working dir is lab/osdp); make
# it importable on the host for the Docker-free contract test below.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_LAB_OSDP = _REPO_ROOT / "lab" / "osdp"
if str(_LAB_OSDP) not in sys.path:
    sys.path.insert(0, str(_LAB_OSDP))

import scenarios

if TYPE_CHECKING:
    from conftest import ComposeUp

COMPOSE_FILE = _REPO_ROOT / "docker-compose.yml"
VULN_OVERRIDE = "docker-compose.vuln.yml"
# libosdp logs its version as "libosdp-<major>.<minor>.<patch>"; the vuln image must be < 3.0.0
# so the CVE-2024-52288 core behaviour (fixed in 3.0.0) is present.
_VERSION_RE = re.compile(r"libosdp version=libosdp-(\d+)\.(\d+)\.(\d+)")


def test_every_scenario_round_trips() -> None:
    """Every declared scenario is selectable via get(); bad input is rejected exactly."""
    # All four LAB_SCENARIO values - including cve-replay - round-trip through the contract.
    assert set(scenarios.valid_values()) == {"cleartext", "sc-scbkd", "downgrade", "cve-replay"}
    for scenario in scenarios.Scenario:
        profile = scenarios.get(scenario.value)
        assert isinstance(profile, scenarios.Profile)

    # Unknown, wrong-case, and whitespace-padded values are all rejected (no case-folding,
    # no coercion) so selection fails closed instead of defaulting to a scenario.
    for bad in ("nope", "CLEARTEXT", " cleartext "):
        with pytest.raises(KeyError):
            scenarios.get(bad)


def _rendered_override_config() -> dict:
    """Return the base+vuln-override compose config as parsed JSON."""
    result = subprocess.run(
        [
            "docker", "compose",
            "-f", str(COMPOSE_FILE),
            "-f", str(_REPO_ROOT / VULN_OVERRIDE),
            "config", "--format", "json",
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


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


@pytest.mark.lab
def test_cve_replay_profile_vulnerable_and_contained(compose_up: ComposeUp) -> None:
    """cve-replay brings the pinned-vulnerable (<3.0.0) bus up with SC active, still contained."""
    # SAFE-01 under the override: the merged config keeps labnet internal and publishes no port.
    config = _rendered_override_config()
    assert config.get("networks", {}).get("labnet", {}).get("internal") is True
    for name, service in config.get("services", {}).items():
        assert not service.get("ports"), f"service {name} publishes host ports under the override"

    lab = compose_up("cve-replay", overrides=(VULN_OVERRIDE,))

    # The bus is live and Secure Channel is active on the vulnerable core.
    assert lab.wait_for_log("cp", "interlock-lab: cve-replay SC active", timeout=180)
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=60)
    assert "SC Active" in lab.logs("pd")  # the LibOSDP core SC-active log line

    # The running libosdp must be < 3.0.0, so CVE-2024-52288 (fixed in 3.0.0) is present.
    match = _VERSION_RE.search(lab.logs("cp"))
    assert match is not None, "CP did not report a libosdp version"
    version = tuple(int(part) for part in match.groups())
    assert version < (3, 0, 0), f"expected a pre-3.0.0 vulnerable libosdp, got {version}"
