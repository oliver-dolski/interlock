"""Host proof of ATK-02 enumeration over the committed Phase 3 fixtures (no Docker).

Loads the clear-text per-direction vectors committed by 03-02 (which carry the
``REPLY_PDID`` / ``REPLY_PDCAP`` the lab CP solicits at bring-up), frames and decodes
them, and asserts ``run_enumerate`` lists the PD at address 101 with its advertised
base capabilities. Also pins the flagged edges and the prohibitions: an empty capture
lists no device, a capability is never reported without a ``REPLY_PDCAP`` backing it,
and the active sweep crafts CMD_ID/CMD_CAP via ``codec.encode`` with the reply flag
cleared. A crafted downgrade-style ``REPLY_PDCAP`` (built via ``codec.encode`` and
decoded back off the wire) proves ``CommunicationSecurity`` is decoded from the triple.

Flagged-assumption note (ATK-02 specless edge probe): on the committed fixtures the lab
PD advertises ``CommunicationSecurity`` in BOTH the cleartext and downgrade captures,
because LibOSDP auto-advertises that capability regardless of the configured key. The
tests therefore assert what the wire actually carries and never fabricate a cleartext /
downgrade difference that is not on the wire.
"""

from __future__ import annotations

from pathlib import Path

from interlock.osdp import codec, constants, framer
from interlock.osdp.attacks.enumerate import (
    CAPABILITY_CODES,
    parse_pdcap,
    run_enumerate,
    sweep_addresses,
)
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Lab PD address under every profile (lab/osdp/pd_driver.py); masked of the reply flag.
_PD_ADDRESS = 101

# The four capabilities the lab configures on the PD (lab/osdp/scenarios.py _BASE_CAPS).
_BASE_CAP_NAMES = ("OutputControl", "LEDControl", "AudibleControl", "TextOutput")


def _load_session(profile: str) -> list[tuple[Direction, OsdpFrame]]:
    """Frame and decode both per-direction vectors of ``profile`` into tagged pairs."""
    session: list[tuple[Direction, OsdpFrame]] = []
    for direction, suffix in (
        (Direction.cp_to_pd, "cp2pd"),
        (Direction.pd_to_cp, "pd2cp"),
    ):
        raw = (FIXTURES_DIR / f"{profile}_{suffix}.cap").read_bytes()
        assert raw, f"{profile}_{suffix}.cap is empty; regenerate it from the lab"
        session.extend((direction, codec.decode(frame)) for frame in framer.iter_frames(raw))
    return session


def _pd_finding(findings: list) -> object:
    """Return the single Finding emitted for the lab PD at address 101."""
    expected_id = f"ATK-02-enumerate-pd-{_PD_ADDRESS}"
    matches = [f for f in findings if f.id == expected_id]
    assert len(matches) == 1, f"expected exactly one Finding for PD {_PD_ADDRESS}, got {findings}"
    return matches[0]


def _crafted_pdcap_frame(triples: list[tuple[int, int, int]]) -> OsdpFrame:
    """Build a REPLY_PDCAP reply from ``triples``, round-tripped through codec.encode/decode."""
    data = bytes(byte for triple in triples for byte in triple)
    frame = OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=constants.PKT_CONTROL_CRC | 0x01,
        scb=b"",
        code=constants.REPLY_PDCAP,
        data=data,
        use_crc=True,
    )
    return codec.decode(next(iter(framer.iter_frames(codec.encode(frame)))))


def test_enumerate_lists_pd_101_with_its_base_caps() -> None:
    """The clear-text fixtures enumerate PD 101 with its four configured base caps."""
    findings = run_enumerate(_load_session("cleartext"))
    finding = _pd_finding(findings)
    assert str(_PD_ADDRESS) in finding.evidence, finding.evidence
    for name in _BASE_CAP_NAMES:
        assert name in finding.evidence, f"missing {name} in {finding.evidence}"


def test_enumerate_reports_decoded_pd_identity() -> None:
    """PD 101's REPLY_PDID identity (vendor/serial) is decoded onto the Finding, not invented."""
    findings = run_enumerate(_load_session("cleartext"))
    finding = _pd_finding(findings)
    # Vendor code and serial are the exact wire bytes from cleartext_pd2cp.cap REPLY_PDID.
    assert "vendor=0xbebafe" in finding.evidence, finding.evidence
    assert "serial=0xafbeadde" in finding.evidence, finding.evidence


def test_empty_capture_lists_no_device() -> None:
    """Flagged-assumption negative: an empty capture enumerates no device (true negative)."""
    assert run_enumerate([]) == []


def test_capability_requires_a_pdcap_backing_it() -> None:
    """A PD seen only via REPLY_PDID lists no capability - none is invented (prohibition)."""
    pdid = codec.decode(
        next(
            iter(
                framer.iter_frames(
                    codec.encode(
                        OsdpFrame(
                            had_mark=True,
                            address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
                            control=constants.PKT_CONTROL_CRC,
                            scb=b"",
                            code=constants.REPLY_PDID,
                            data=bytes.fromhex("bebafe0101afbeaddeaddead"),
                            use_crc=True,
                        )
                    )
                )
            )
        )
    )
    finding = _pd_finding(run_enumerate([(Direction.pd_to_cp, pdid)]))
    assert "none observed (no REPLY_PDCAP)" in finding.evidence, finding.evidence


def test_crafted_downgrade_pdcap_shows_communication_security() -> None:
    """A crafted REPLY_PDCAP carrying CommunicationSecurity decodes to that advertised cap."""
    triples = [
        (0x02, 1, 1),  # OutputControl
        (0x04, 2, 1),  # LEDControl
        (0x05, 1, 1),  # AudibleControl
        (0x06, 1, 1),  # TextOutput
        (0x09, 1, 1),  # CommunicationSecurity, advertised with support (count=1)
    ]
    frame = _crafted_pdcap_frame(triples)
    finding = _pd_finding(run_enumerate([(Direction.pd_to_cp, frame)]))
    assert "CommunicationSecurity(compliance=1,count=1)" in finding.evidence, finding.evidence
    for name in _BASE_CAP_NAMES:
        assert name in finding.evidence, finding.evidence


def test_parse_pdcap_decodes_each_wire_triple() -> None:
    """parse_pdcap decodes the committed REPLY_PDCAP payload into its (func,comp,count) triples."""
    payload = bytes.fromhex("0201010402010501010601010801000901000a0001")
    caps = parse_pdcap(payload)
    assert [c.function_code for c in caps] == [0x02, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A]
    # Function codes resolve to the pyosdp-style names the lab PD driver uses.
    assert caps[0].name == CAPABILITY_CODES[0x02] == "OutputControl"
    # A trailing partial triple (2 stray bytes) is dropped, never fabricated into a cap.
    assert len(parse_pdcap(payload + b"\x0b\x01")) == len(caps)


def test_active_sweep_crafts_id_and_cap_via_codec_encode() -> None:
    """The active sweep injects valid cp->pd CMD_ID/CMD_CAP (reply flag cleared) and enumerates."""
    sent: list[OsdpFrame] = []
    pdcap_reply = codec.encode(
        _crafted_pdcap_frame([(0x02, 1, 1), (0x04, 2, 1), (0x05, 1, 1), (0x06, 1, 1)])
    )

    def fake_pd(frame_bytes: bytes) -> bytes:
        command = codec.decode(next(iter(framer.iter_frames(frame_bytes))))
        sent.append(command)
        # Only the PD at address 101 answers, and only to CMD_CAP (with its REPLY_PDCAP).
        if command.address == _PD_ADDRESS and command.code == constants.CMD_CAP:
            return pdcap_reply
        return b""

    frames = sweep_addresses(fake_pd, addresses=range(100, 103))
    finding = _pd_finding(run_enumerate(frames))
    for name in _BASE_CAP_NAMES:
        assert name in finding.evidence, finding.evidence

    # Every injected frame is a valid cp->pd command: a known command code, built via the
    # codec, with the reply flag cleared and the address inside the swept range.
    assert sent, "the sweep injected no frames"
    for command in sent:
        assert command.code in (constants.CMD_ID, constants.CMD_CAP), command.code
        assert not command.address & constants.ADDR_REPLY_FLAG, "reply flag set on a cp->pd command"
        assert 100 <= command.address <= 102, command.address


def test_active_sweep_survives_a_garbage_reply() -> None:
    """A garbage (non-frame) reply from the injector is skipped, never crashing the sweep."""
    frames = sweep_addresses(lambda _frame: b"\x00\xffnot a frame", addresses=range(100, 102))
    assert frames == []
    assert run_enumerate(frames) == []
