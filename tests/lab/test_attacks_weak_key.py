"""Live @lab proof of ATK-06 weak-key testing against the running sc-scbkd lab (D-05).

Brings the sc-scbkd profile up under the docker-compose.tap.yml override (interlock's own
read-only TCPTap in the attacker position), gates on PD-online and the card-read event
sentinel so the Secure Channel handshake has transited the tap, reads both per-direction
captures out of the attacker container via docker compose exec, drives them through the same
collector (decode_chunks) and run_weak_key the CLI uses, and asserts the live sc-scbkd
session flags SCBK-D as the key in use.

Adds no published port: the capture is read via ``docker compose exec`` exactly as
test_attacks_sniff.py does, so SAFE-01 containment is unchanged.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from interlock.osdp.attacks.sniff import decode_chunks
from interlock.osdp.attacks.weak_key import WEAK_KEYS, run_weak_key
from interlock.osdp.constants import SCBK_D
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


def test_weak_keys_dictionary_excludes_the_downgrade_key() -> None:
    """Guard (no lab needed): WEAK_KEYS ships only the spec default SCBK-D (SAFE-03)."""
    assert WEAK_KEYS == {"SCBK-D": SCBK_D}
    assert bytes(range(0x10, 0x20)) not in WEAK_KEYS.values()


@pytest.mark.lab
def test_weak_key_flags_scbk_d_on_the_live_sc_scbkd_lab(compose_up: ComposeUp) -> None:
    lab = compose_up("sc-scbkd", overrides=("docker-compose.tap.yml",))

    # Precondition: the lab must reach PD online and emit the card-read event under the
    # tap override, so the full Secure Channel handshake transited the tap before we read.
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

    # Drive the exact collector + sweep the CLI uses.
    frames = decode_chunks([(Direction.cp_to_pd, cp2pd), (Direction.pd_to_cp, pd2cp)])
    findings = run_weak_key(frames)

    matches = [f for f in findings if f.id == "ATK-06-weak-key"]
    assert len(matches) == 1, f"expected one weak-key Finding, got {findings}"
    finding = matches[0]
    assert "SCBK-D" in finding.title, finding.title
    assert SCBK_D.hex() in finding.evidence, finding.evidence
