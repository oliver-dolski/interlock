"""Live @lab proof of ATK-02 enumeration against the running lab (D-05 wire-grounded).

Brings a profile up under the docker-compose.tap.yml override (interlock's own read-only
TCPTap in the attacker position), gates on PD-online and the card-read event sentinel so the
full bring-up (including the plaintext REPLY_PDID / REPLY_PDCAP the CP solicits) has transited
the tap, reads both per-direction captures out of the attacker container via docker compose
exec, and folds them through the same ``run_enumerate`` the CLI uses. Asserts the live
enumeration lists PD 101 with its advertised base capabilities.

Flagged-assumption note (ATK-02 specless edge probe): the lab PD advertises
``CommunicationSecurity`` in BOTH profiles on the wire (LibOSDP auto-advertises it), so the
downgrade case asserts that capability is present rather than claiming a cleartext/downgrade
difference the wire does not carry. Everything asserted is a decoded wire reply.

Adds no published port: captures are read via ``docker compose exec`` exactly as the sniff
@lab test does, so SAFE-01 containment is unchanged.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from interlock.osdp.attacks.enumerate import run_enumerate
from interlock.osdp.attacks.sniff import decode_chunks
from interlock.osdp.transport import Direction

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# Lab PD address under every profile (lab/osdp/pd_driver.py), masked of the reply flag.
_PD_ADDRESS = 101
_BASE_CAP_NAMES = ("OutputControl", "LEDControl", "AudibleControl", "TextOutput")

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


def _enumerate_live(lab: ComposeHandle) -> object:
    """Gate on the full bring-up, read both captures, and return the Finding for PD 101."""
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "PD never came online under the tap override"
    )
    assert lab.wait_for_log("cp", "interlock-lab: event received", timeout=90), (
        "card-read event never observed under the tap override"
    )

    cp2pd = _read_capture(lab, "/app/capture/cp2pd.cap")
    pd2cp = _read_capture(lab, "/app/capture/pd2cp.cap")
    assert cp2pd, "cp->pd capture is empty"
    assert pd2cp, "pd->cp capture is empty"

    frames = decode_chunks([(Direction.cp_to_pd, cp2pd), (Direction.pd_to_cp, pd2cp)])
    findings = run_enumerate(frames)

    expected_id = f"ATK-02-enumerate-pd-{_PD_ADDRESS}"
    matches = [f for f in findings if f.id == expected_id]
    assert len(matches) == 1, f"expected one Finding for PD {_PD_ADDRESS}, got {findings}"
    return matches[0]


@pytest.mark.lab
def test_enumerate_lists_pd_101_with_base_caps_on_cleartext(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext", overrides=("docker-compose.tap.yml",))
    finding = _enumerate_live(lab)
    for name in _BASE_CAP_NAMES:
        assert name in finding.evidence, finding.evidence


@pytest.mark.lab
def test_enumerate_shows_communication_security_on_downgrade(compose_up: ComposeUp) -> None:
    lab = compose_up("downgrade", overrides=("docker-compose.tap.yml",))
    finding = _enumerate_live(lab)
    for name in _BASE_CAP_NAMES:
        assert name in finding.evidence, finding.evidence
    assert "CommunicationSecurity" in finding.evidence, finding.evidence
