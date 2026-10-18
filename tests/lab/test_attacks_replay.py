"""Live @lab proof of ATK-05a clear-text card-presentation replay (D-05).

``capture_card_exchange`` is exercised against the committed clear-text fixture
(``tests/osdp/fixtures/cleartext_pd2cp.cap``, captured in Phase 3) to produce a genuinely
non-empty, real captured card-read exchange - proving the host-level "exact captured bytes"
contract is driven from real data, not synthetic frames.

Brings the cleartext lab up under ``docker-compose.replay.yml`` (interlock's inline replay
relay in the attacker position, disarmed until a trigger file exists, reusing
``spoof.unlock_transform`` per Task 3's read_first note). Drives ``run_replay`` exactly as the
CLI/report layer would: ``lock_state_probe`` reads the PD's own log for the single D-05
lock-state sentinel, and ``inject`` arms the live relay then blocks until the sentinel appears.
Asserts the CRITICAL Finding the locked->unlocked transition produces.

Adds no published port: the lock state is read via ``docker compose logs``, so SAFE-01
containment is unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from interlock.osdp import codec, framer
from interlock.osdp.attacks.replay import capture_card_exchange, run_replay
from interlock.osdp.transport import Direction

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# The single D-05 lock-state sentinel (lab/osdp/pd_driver.py).
_SENTINEL = "interlock-lab: LOCK state=UNLOCKED"

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "osdp" / "fixtures"


def _captured_card_exchange() -> list[bytes]:
    """Return the real captured card-read frame(s) from the committed cleartext fixture."""
    raw = (FIXTURES_DIR / "cleartext_pd2cp.cap").read_bytes()
    frames = [(Direction.pd_to_cp, codec.decode(f)) for f in framer.iter_frames(raw)]
    return capture_card_exchange(frames)


def _lock_state_probe(lab: ComposeHandle) -> bool:
    """Return True if the lock-state sentinel is currently present in the PD's logs."""
    return _SENTINEL in lab.logs("pd")


def _inject(lab: ComposeHandle, _frame_bytes: bytes) -> None:
    """Arm the live replay trigger (idempotent), then block until the rewrite lands.

    The attacker's injection stays disarmed until this trigger file exists (replay.py's
    ``_TRIGGER_PATH``), so the PD is observably still locked beforehand. Called once per
    captured frame per ``run_replay``'s contract; redundant calls are harmless since
    ``wait_for_log`` returns immediately once the sentinel is already present.
    """
    armed = lab.compose("exec", "-T", "attacker", "touch", "/tmp/interlock-replay-fire")
    assert armed.returncode == 0, f"failed to arm the replay trigger: {armed.stdout}{armed.stderr}"
    lab.wait_for_log("pd", _SENTINEL, timeout=120)


@pytest.mark.lab
def test_replay_of_captured_card_exchange_confirms_the_door_open(compose_up: ComposeUp) -> None:
    captured = _captured_card_exchange()
    assert captured, "the committed cleartext fixture carries no REPLY_RAW card-event frame"

    lab = compose_up("cleartext", overrides=("docker-compose.replay.yml",))

    # Precondition: the CP must reach PD online under the replay override.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "PD never came online under the replay override"
    )

    findings = run_replay(
        captured,
        lambda frame_bytes: _inject(lab, frame_bytes),
        lambda: _lock_state_probe(lab),
    )

    assert len(findings) == 1, findings
    assert findings[0].id == "ATK-05a-replay-card-exchange"
    assert findings[0].severity.value == "critical"
