"""Live @lab proof of ATK-07 command fuzzing against the running cleartext lab (D-05).

Brings the cleartext profile up under the docker-compose.tap.yml override (which mounts
./src into the attacker container so interlock is importable there) and, once the lab is fully
up, runs the deterministic nine-member sweep from inside the attacker container against the PD
over TCP. Asserts the fuzzer completes and classifies the PD response: it prints a finding
count (any crash / hang / desync would be reported with its mutation name and seed), and the
PD stays online through the sweep (the robust-parser true negative).

The sweep is driven in-container via ``docker compose exec`` exactly as the capture-reading
tests use exec, so no published port is added and SAFE-01 containment is unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# Run the deterministic nine-member sweep against the PD from inside the attacker container.
_RUN_SWEEP = (
    "from interlock.osdp.attacks.fuzz import fuzz_lab\n"
    "findings = fuzz_lab(('pd', 10000))\n"
    "print('FINDINGS=' + str(len(findings)))\n"
    "[print('FINDING ' + f.id) for f in findings]\n"
)


def _run_sweep(lab: ComposeHandle) -> str:
    """Run the fuzz sweep inside the attacker container and return its stdout."""
    result = lab.compose(
        "exec", "-T", "-e", "PYTHONPATH=/app/src", "attacker", "python", "-c", _RUN_SWEEP
    )
    assert result.returncode == 0, f"fuzz sweep failed: {result.stdout}{result.stderr}"
    return result.stdout


@pytest.mark.lab
def test_fuzz_sweep_completes_and_classifies_the_cleartext_pd(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext", overrides=("docker-compose.tap.yml",))

    # Precondition: the lab is fully up (PD online + a card-read event has transited).
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "PD never came online under the tap override"
    )
    assert lab.wait_for_log("cp", "interlock-lab: event received", timeout=90), (
        "card-read event never observed under the tap override"
    )

    output = _run_sweep(lab)

    # The fuzzer completed and classified the PD response (a finding count is printed).
    assert "FINDINGS=" in output, output
    count = int(output.split("FINDINGS=", 1)[1].splitlines()[0])
    assert count >= 0

    # The PD stayed online through the sweep (robust-parser true negative).
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=30), (
        "PD dropped offline during the fuzz sweep"
    )
