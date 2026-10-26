"""Wave-0 spike (A3): does CMD_KEYSET appear on the live sc-scbkd install-mode wire?

ATK-04 recovers the SCBK that a PD enrols via ``CMD_KEYSET`` (0x75). On the lab's
``sc-scbkd`` profile the PD runs install mode and the Secure Channel is protected by
the known spec default SCBK-D, so an enrolment exchange observed on that bus would be
recoverable. This spike brings the sc-scbkd profile up under the tap override, gates
on PD-online (so the full install-mode exchange has transited the tap), reads the
per-direction captures, and determines whether a ``CMD_KEYSET`` frame ever crosses the
bus cp->pd. The answer decides Task 2's shape:

- CMD_KEYSET present -> the committed KEYSET fixtures under ``tests/osdp/fixtures/``
  (read-only golden inputs, never written by this @lab run) back the host unit's
  recovery + SCBK-D confirmation against a real frame.
- CMD_KEYSET absent  -> the lab's high-level ControlPanel/PeripheralDevice API does not
  drive enrolment on the wire, so ATK-04 must inject CMD_KEYSET via the active-trigger
  seam; the host unit proves the SCBK-D session-key derivation and the no-KEYSET -> []
  true negative instead.

Either outcome is a passing spike: the only failure is the lab never reaching PD-online
(the spike could not observe the install-mode bus at all). The determination is also
printed so it is visible in the test log.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from interlock.osdp import codec, constants, framer

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# Read an in-container capture as base64 so binary survives the text pipe; prints an
# empty string if the file does not exist yet rather than raising. (Same reader as
# tests/lab/test_osdp_tap.py, which reads those captures under the tap override.)
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


def _decoded_codes(raw: bytes) -> list[int]:
    """Frame ``raw`` and return the decoded code byte of every trailer-valid frame."""
    codes: list[int] = []
    for frame in framer.iter_frames(raw):
        try:
            codes.append(codec.decode(frame).code)
        except codec.DecodeError:
            pass  # trailer-valid but structurally malformed; skip, never crash
    return codes


@pytest.mark.lab
def test_spike_cmd_keyset_on_the_install_mode_wire(compose_up: ComposeUp) -> None:
    lab = compose_up("sc-scbkd", overrides=("docker-compose.tap.yml",))

    # Precondition: the install-mode bus must reach PD online under the tap override,
    # which means the full exchange (including the SCBK-D handshake) transited the tap.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "sc-scbkd: PD never came online under the tap override; the spike could not "
        "observe the install-mode bus"
    )
    assert lab.wait_for_log("cp", "interlock-lab: event received", timeout=90), (
        "sc-scbkd: card-read event never observed under the tap override"
    )

    cp2pd = _read_capture(lab, "/app/capture/cp2pd.cap")
    assert cp2pd, "sc-scbkd: cp->pd capture is empty"
    cp_codes = _decoded_codes(cp2pd)
    assert cp_codes, "sc-scbkd: no trailer-valid frames decoded cp->pd"

    # Sanity: install-mode Secure Channel is really up on this bus (the CHLNG handshake
    # the SCBK-D recovery relies on is present), so an absent CMD_KEYSET is a real
    # determination about enrolment, not a dead bus.
    assert constants.CMD_CHLNG in cp_codes, (
        "sc-scbkd: no CMD_CHLNG cp->pd - the install-mode Secure Channel handshake was "
        "not observed, so the CMD_KEYSET determination would be meaningless"
    )

    keyset_present = constants.CMD_KEYSET in cp_codes
    print(
        f"interlock-spike: CMD_KEYSET (0x75) present on the sc-scbkd wire cp->pd = "
        f"{keyset_present}; codes seen = {sorted(set(cp_codes))}"
    )

    if keyset_present:
        # The high-level API drove enrolment on the wire: the pd->cp side carries the
        # CCRYPT (for uses_scbk_d confirmation) and the REPLY_RMAC_I whose R-MAC is the
        # command IV the SCBK-D session-key recovery decrypts the KEYSET payload with.
        # The committed keyset fixtures are read-only golden inputs; this run reads the
        # live bus to confirm both directions carry the enrolment, never writes them.
        pd2cp = _read_capture(lab, "/app/capture/pd2cp.cap")
        assert pd2cp, "sc-scbkd: CMD_KEYSET seen but pd->cp capture is empty"
    else:
        # Determination recorded: the lab's high-level ControlPanel/PeripheralDevice API
        # does NOT auto-enrol over the wire, so ATK-04 uses the active-trigger path and the
        # host unit proves the SCBK-D session-key derivation on the committed handshake.
        assert constants.CMD_KEYSET not in cp_codes


@pytest.mark.lab
def test_keyset_recovers_scbk_d_on_the_live_sc_scbkd_lab(compose_up: ComposeUp) -> None:
    """ATK-04 recovers the enrolled SCBK-D from the live install-mode KEYSET exchange."""
    from interlock.osdp.attacks.keyset import run_keyset
    from interlock.osdp.attacks.sniff import decode_chunks
    from interlock.osdp.constants import SCBK_D
    from interlock.osdp.transport import Direction

    lab = compose_up("sc-scbkd", overrides=("docker-compose.tap.yml",))

    # Precondition: the install-mode exchange (handshake + KEYSET) must transit the tap.
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

    # Drive the exact collector the CLI observe path uses, then recover.
    frames = decode_chunks(
        [(Direction.cp_to_pd, cp2pd), (Direction.pd_to_cp, pd2cp)], max_frames=400
    )
    findings = run_keyset(frames)

    matches = [f for f in findings if f.id == "ATK-04-keyset"]
    assert len(matches) == 1, f"expected one KEYSET Finding, got {findings}"
    assert SCBK_D.hex() in matches[0].evidence, matches[0].evidence
