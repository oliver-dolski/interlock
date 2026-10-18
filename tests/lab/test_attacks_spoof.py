"""Live @lab proof of ATK-08 unlock spoofing against the running cleartext lab (D-05).

Brings the cleartext profile up under ``docker-compose.spoof.yml`` (interlock's inline
unlock-spoof rewrite relay in the attacker position, disarmed until a trigger file exists so
the PD stays observably locked until the test explicitly arms it). Drives ``run_spoof`` exactly
as the CLI/report layer would: ``lock_state_probe`` reads the PD's own log for the single D-05
lock-state sentinel, and ``inject`` arms the live rewrite (``docker compose exec ... touch``)
then blocks until the sentinel appears. Asserts the CRITICAL Finding the locked->unlocked
transition produces.

Adds no published port: the lock state is read via ``docker compose logs``, exactly as the
Wave-0 spike test does, so SAFE-01 containment is unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from interlock.osdp.attacks.spoof import run_spoof

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# The single D-05 lock-state sentinel (lab/osdp/pd_driver.py).
_SENTINEL = "interlock-lab: LOCK state=UNLOCKED"


def _lock_state_probe(lab: ComposeHandle) -> bool:
    """Return True if the lock-state sentinel is currently present in the PD's logs."""
    return _SENTINEL in lab.logs("pd")


def _inject(lab: ComposeHandle) -> None:
    """Arm the live unlock-spoof trigger, then block until the rewrite lands.

    The attacker's injection stays disarmed until this trigger file exists (spoof.py's
    ``_TRIGGER_PATH``), so the PD is observably still locked beforehand - this is what makes
    the transition attributable to this call rather than a startup race.
    """
    armed = lab.compose("exec", "-T", "attacker", "touch", "/tmp/interlock-spoof-fire")
    assert armed.returncode == 0, f"failed to arm the spoof trigger: {armed.stdout}{armed.stderr}"
    lab.wait_for_log("pd", _SENTINEL, timeout=120)


@pytest.mark.lab
def test_spoof_unlock_flips_the_lock_state_signal(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext", overrides=("docker-compose.spoof.yml",))

    # Precondition: the CP must reach PD online under the spoof override.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "PD never came online under the spoof override"
    )

    findings = run_spoof(lambda: _inject(lab), lambda: _lock_state_probe(lab))

    assert len(findings) == 1, findings
    assert findings[0].id == "ATK-08-spoof-unlock"
    assert findings[0].severity.value == "critical"
