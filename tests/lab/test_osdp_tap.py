"""Live tap: interlock's own TCP tap observes the lab per direction (OSDP-02, SC3).

This brings each TCP-tappable profile (cleartext, sc-scbkd, downgrade) up under the
docker-compose.tap.yml override, which swaps the Phase 2 proxy for interlock's
read-only TCPTap. The tap writes one capture file per direction inside the attacker
container. After the full exchange has transited the tap (PD online plus the
card-read event), this reads both per-direction captures out via docker compose
exec, frames and decodes them, asserts the expected codes appear in each direction,
and writes the committed per-direction fixtures that plan 03-04 and the round-trip
oracle consume.

The sc-scbkd profile additionally proves the Secure Channel handshake was observed:
CMD_CHLNG must appear cp->pd and REPLY_CCRYPT pd->cp (both share byte 0x76, told
apart only by direction), so 03-04 has a real handshake vector to work from.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from interlock.osdp import codec, constants, framer

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "osdp" / "fixtures"

# Read an in-container capture as base64 so binary survives the text pipe; prints an
# empty string if the file does not exist yet rather than raising.
_READ_CAPTURE = (
    "import base64, os, sys\n"
    "p = sys.argv[1]\n"
    "data = open(p, 'rb').read() if os.path.exists(p) else b''\n"
    "sys.stdout.write(base64.b64encode(data).decode())\n"
)

# Keep the committed fixtures small but representative: enough frames to include the
# startup handshake and steady-state polling, not the whole unbounded session.
_MAX_FIXTURE_FRAMES = 80


def _read_capture(lab: ComposeHandle, path: str) -> bytes:
    """Return the bytes of an attacker capture file, read via docker compose exec."""
    result = lab.compose("exec", "-T", "attacker", "python", "-c", _READ_CAPTURE, path)
    assert result.returncode == 0, f"reading {path} failed: {result.stdout}{result.stderr}"
    return base64.b64decode(result.stdout.strip())


def _decoded_codes(raw: bytes) -> list[int]:
    """Frame ``raw`` and return the decoded code byte of every trailer-valid frame."""
    return [codec.decode(frame).code for frame in framer.iter_frames(raw)]


def _bounded_fixture(raw: bytes) -> bytes:
    """Return a bounded concatenation of the leading trailer-valid frames in ``raw``."""
    frames = list(framer.iter_frames(raw))[:_MAX_FIXTURE_FRAMES]
    return b"".join(frames)


# scenario -> (codes required cp->pd, codes required pd->cp)
_EXPECTED = {
    "cleartext": ((constants.CMD_POLL,), (constants.REPLY_ACK,)),
    "sc-scbkd": (
        (constants.CMD_POLL, constants.CMD_CHLNG),
        (constants.REPLY_ACK, constants.REPLY_CCRYPT),
    ),
    "downgrade": ((constants.CMD_POLL,), (constants.REPLY_ACK,)),
}


@pytest.mark.lab
@pytest.mark.parametrize("scenario", ["cleartext", "sc-scbkd", "downgrade"])
def test_tap_observes_both_directions(compose_up: ComposeUp, scenario: str) -> None:
    lab = compose_up(scenario, overrides=("docker-compose.tap.yml",))

    # Precondition: the lab must reach PD online under the tap override, which means
    # the full exchange (including the SC handshake under sc-scbkd) transited the tap.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        f"{scenario}: PD never came online under the tap override"
    )
    assert lab.wait_for_log("cp", "interlock-lab: event received", timeout=90), (
        f"{scenario}: card-read event never observed under the tap override"
    )

    cp2pd = _read_capture(lab, "/app/capture/cp2pd.cap")
    pd2cp = _read_capture(lab, "/app/capture/pd2cp.cap")
    assert cp2pd, f"{scenario}: cp->pd capture is empty"
    assert pd2cp, f"{scenario}: pd->cp capture is empty"

    cp_codes = _decoded_codes(cp2pd)
    pd_codes = _decoded_codes(pd2cp)
    assert cp_codes, f"{scenario}: no trailer-valid frames decoded cp->pd"
    assert pd_codes, f"{scenario}: no trailer-valid frames decoded pd->cp"

    expected_cp, expected_pd = _EXPECTED[scenario]
    for code in expected_cp:
        assert code in cp_codes, f"{scenario}: expected code {code:#04x} not seen cp->pd"
    for code in expected_pd:
        assert code in pd_codes, f"{scenario}: expected code {code:#04x} not seen pd->cp"

    # Write the committed per-direction fixtures for the round-trip oracle and 03-04.
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    cp_fixture = _bounded_fixture(cp2pd)
    pd_fixture = _bounded_fixture(pd2cp)
    assert cp_fixture, f"{scenario}: no frames to write for the cp->pd fixture"
    assert pd_fixture, f"{scenario}: no frames to write for the pd->cp fixture"
    (FIXTURES_DIR / f"{scenario}_cp2pd.cap").write_bytes(cp_fixture)
    (FIXTURES_DIR / f"{scenario}_pd2cp.cap").write_bytes(pd_fixture)
