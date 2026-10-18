"""Live @lab proof of ATK-01 sniff against the running cleartext lab (D-05 wire-grounded).

Brings the cleartext profile up under the docker-compose.tap.yml override (interlock's
own read-only TCPTap in the attacker position), gates on PD-online and the card-read
event sentinel so the full exchange has transited the tap, reads both per-direction
captures out of the attacker container via docker compose exec, drives them through the
same sniff collector (decode_chunks) and run_sniff the CLI uses, and asserts the live
topology lists PD 101 with CMD_POLL/REPLY_ACK and a clear-text Secure Channel posture.

Adds no published port: the capture is read via ``docker compose exec`` exactly as
test_osdp_tap.py does, so SAFE-01 containment is unchanged.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from interlock.osdp import constants
from interlock.osdp.attacks.sniff import decode_chunks, run_sniff
from interlock.osdp.transport import Direction

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# Lab PD address under every profile (lab/osdp/pd_driver.py), masked of the reply flag.
_PD_ADDRESS = 101

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


@pytest.mark.lab
def test_sniff_decodes_the_live_cleartext_lab(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext", overrides=("docker-compose.tap.yml",))

    # Precondition: the lab must reach PD online and emit the card-read event under the
    # tap override, so the full exchange transited the tap before we read the captures.
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

    # Drive the exact collector + fold the CLI uses.
    frames = decode_chunks(
        [(Direction.cp_to_pd, cp2pd), (Direction.pd_to_cp, pd2cp)]
    )
    findings = run_sniff(frames)

    expected_id = f"ATK-01-sniff-pd-{_PD_ADDRESS}"
    matches = [f for f in findings if f.id == expected_id]
    assert len(matches) == 1, f"expected one Finding for PD {_PD_ADDRESS}, got {findings}"
    finding = matches[0]

    poll_name = constants.COMMAND_CODES[constants.CMD_POLL]
    ack_name = constants.REPLY_CODES[constants.REPLY_ACK]
    assert poll_name in finding.evidence, finding.evidence
    assert ack_name in finding.evidence, finding.evidence
    assert "clear-text" in finding.evidence, finding.evidence
