"""Live @lab proof of ATK-07 command fuzzing against the running cleartext lab (D-05).

Brings the cleartext profile up under the docker-compose.fuzz.yml override: the CP idles so
the lab PD's single accept() is free, and the attacker idles with ./src mounted read-only so
interlock is importable there. Once the PD logs that it is listening, the deterministic
nine-member sweep runs from inside the attacker container over ONE persistent connection to
the PD.

What is asserted, and why each can fail:

- ``BASELINE=ok``: the PD answered a valid sequence-0 CMD_POLL on the fuzzer's connection
  before the first mutation (``FuzzBaselineError`` otherwise, printed as ``BASELINE=failed``).
- ``FINDINGS=0`` exactly: LibOSDP 3.0.8 survives all nine corruptions on the healthy lab, so
  any finding is a regression in the probe (the old per-call probe reported nine).
- the PD log holds at least one ``fuzz.LIBOSDP_REJECTION_MARKERS`` line, written during the
  sweep: the corruptions reached the PD parser, so the zero is not a sweep that never landed.

The sweep is driven in-container via ``docker compose exec``, so no published port is added
and SAFE-01 containment is unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from interlock.osdp.attacks.fuzz import LIBOSDP_REJECTION_MARKERS

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# Run the deterministic nine-member sweep against the PD from inside the attacker container.
_RUN_SWEEP = (
    "from interlock.osdp.attacks.fuzz import FuzzBaselineError, fuzz_lab\n"
    "try:\n"
    "    findings = fuzz_lab(('pd', 10000))\n"
    "except FuzzBaselineError as exc:\n"
    "    print('BASELINE=failed ' + str(exc))\n"
    "    raise SystemExit(0)\n"
    "print('BASELINE=ok')\n"
    "print('FINDINGS=' + str(len(findings)))\n"
    "[print('FINDING ' + f.id) for f in findings]\n"
)


def _run_sweep(lab: ComposeHandle) -> str:
    """Run the fuzz sweep inside the attacker container and return its stdout."""
    result = lab.compose(
        "exec", "-T", "-e", "PYTHONPATH=/app/src", "attacker", "python", "-c", _RUN_SWEEP
    )
    assert result.returncode == 0, f"fuzz sweep failed: {result.stdout}{result.stderr}"
    print(result.stdout)
    return result.stdout


@pytest.mark.lab
def test_fuzz_sweep_reports_the_healthy_cleartext_pd_clean(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext", overrides=("docker-compose.fuzz.yml",))

    # Precondition: the PD is about to accept() (the CP is idle, so no session exists yet).
    assert lab.wait_for_log("pd", "interlock-lab: PD listening on 0.0.0.0:10000", timeout=120), (
        "PD never reached listen() under the fuzz override"
    )

    output = _run_sweep(lab)

    assert "BASELINE=ok" in output, output
    assert "FINDINGS=" in output, output
    count = int(output.split("FINDINGS=", 1)[1].splitlines()[0])
    assert count == 0, f"healthy LibOSDP PD reported as failing:\n{output}"

    pd_log = lab.logs("pd").lower()
    assert any(marker in pd_log for marker in LIBOSDP_REJECTION_MARKERS), (
        "no LibOSDP parser-rejection line in the PD log: the corruptions never reached the "
        f"parser, so the clean sweep proves nothing\n{pd_log[-4000:]}"
    )
