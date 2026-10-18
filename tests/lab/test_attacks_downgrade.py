"""Live @lab proof of ATK-03 Secure Channel downgrade (D-05 wire-grounded).

The downgrade is proven by a before/after pair against the ``downgrade`` lab profile (a CP
that does not enforce Secure Channel, so it only negotiates SC because the PD advertises
CommunicationSecurity):

1. **baseline** - bring the profile up under ``docker-compose.tap.yml`` (interlock's read-only
   TCPTap), capture the untouched session, and assert ``detect_state(baseline).secure``.
2. **attacked** - bring the same profile up under ``docker-compose.downgrade.yml`` (interlock's
   inline downgrade rewrite relay strips CommunicationSecurity from every REPLY_PDCAP in
   flight), capture the forwarded session, and assert ``detect_state(attacked).clear_text``.

``run_downgrade`` then folds the pair into one HIGH Finding. Both overrides add no published
port and keep captures in-container (read out via docker compose exec), so SAFE-01 is unchanged.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from interlock.osdp import secure_channel
from interlock.osdp.attacks.downgrade import run_downgrade
from interlock.osdp.attacks.sniff import decode_chunks
from interlock.osdp.transport import Direction

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# Read an in-container capture as base64 so binary survives the text pipe.
_READ_CAPTURE = (
    "import base64, os, sys\n"
    "p = sys.argv[1]\n"
    "data = open(p, 'rb').read() if os.path.exists(p) else b''\n"
    "sys.stdout.write(base64.b64encode(data).decode())\n"
)


def _read_capture(lab: ComposeHandle, path: str) -> bytes:
    """Return the bytes of an attacker capture file, read via docker compose exec."""
    result = lab.compose("exec", "-T", "attacker", "python", "-c", _READ_CAPTURE, path)
    assert result.returncode == 0, f"reading {path} failed: {result.stdout}{result.stderr}"
    return base64.b64decode(result.stdout.strip())


def _capture_session(lab: ComposeHandle) -> list[tuple[Direction, object]]:
    """Gate on the full bring-up, read both per-direction captures, and decode them."""
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "PD never came online under the override"
    )
    assert lab.wait_for_log("cp", "interlock-lab: event received", timeout=90), (
        "card-read event never observed under the override"
    )
    cp2pd = _read_capture(lab, "/app/capture/cp2pd.cap")
    pd2cp = _read_capture(lab, "/app/capture/pd2cp.cap")
    assert cp2pd, "cp->pd capture is empty"
    assert pd2cp, "pd->cp capture is empty"
    return decode_chunks([(Direction.cp_to_pd, cp2pd), (Direction.pd_to_cp, pd2cp)])


@pytest.mark.lab
def test_downgrade_forces_clear_text_on_the_downgrade_profile(compose_up: ComposeUp) -> None:
    # Baseline: untouched downgrade profile is Secure Channel on the wire.
    baseline_lab = compose_up("downgrade", overrides=("docker-compose.tap.yml",))
    baseline = _capture_session(baseline_lab)
    assert secure_channel.detect_state(baseline).secure, (
        "the downgrade profile baseline was not secure to begin with"
    )

    # Attacked: the inline rewrite strips CommunicationSecurity, so the CP stays clear-text.
    attacked_lab = compose_up("downgrade", overrides=("docker-compose.downgrade.yml",))
    attacked = _capture_session(attacked_lab)
    assert secure_channel.detect_state(attacked).clear_text, (
        "the attacked session was not forced to clear-text"
    )

    # The before/after pair proves the downgrade.
    findings = run_downgrade(baseline, attacked)
    assert len(findings) == 1, findings
    assert findings[0].id == "ATK-03-downgrade"
    assert findings[0].severity.value == "high"
