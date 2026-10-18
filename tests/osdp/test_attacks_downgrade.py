"""Host proof of ATK-03 Secure Channel downgrade (no Docker).

Two halves, both Docker-free (no ``lab`` marker):

- the in-path transform: a crafted ``REPLY_PDCAP`` carrying CommunicationSecurity is
  stripped of exactly that capability and re-encodes to a valid frame; a reply without it,
  a non-PDCAP frame, and the cp->pd direction all pass through untouched; the stateful
  ``downgrade_transform`` strips a ``REPLY_PDCAP`` even when it is split across two reads.
- the verdict: ``run_downgrade`` emits a HIGH Finding only for a secure baseline (that
  advertised CommunicationSecurity) forced to clear-text, and returns ``[]`` (inconclusive)
  for a baseline that was never secure, had nothing to strip, or an attacked session that
  stayed secure - the flagged-assumption guard against a false downgrade success.
"""

from __future__ import annotations

from interlock.osdp import codec, constants
from interlock.osdp.attacks.downgrade import (
    downgrade_transform,
    run_downgrade,
    strip_communication_security,
    strip_sc_capability,
)
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction

# Lab PD address under every profile (lab/osdp/pd_driver.py).
_PD_ADDRESS = 101

# The lab's four base caps plus CommunicationSecurity (0x09), as (func, compliance, count).
_CAPS_WITH_SC = [
    (0x02, 1, 1),  # OutputControl
    (0x04, 2, 1),  # LEDControl
    (0x05, 1, 1),  # AudibleControl
    (0x06, 1, 1),  # TextOutput
    (0x09, 1, 1),  # CommunicationSecurity - the one the downgrade strips
]
_BASE_CAP_CODES = (0x02, 0x04, 0x05, 0x06)


def _pdcap_frame(triples: list[tuple[int, int, int]]) -> OsdpFrame:
    """Build a pd->cp REPLY_PDCAP OsdpFrame carrying ``triples`` (reply flag set)."""
    data = bytes(byte for triple in triples for byte in triple)
    return OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=constants.PKT_CONTROL_CRC | 0x01,
        scb=b"",
        code=constants.REPLY_PDCAP,
        data=data,
        use_crc=True,
    )


def _pdcap_bytes(triples: list[tuple[int, int, int]]) -> bytes:
    """Return the encoded wire bytes of a REPLY_PDCAP carrying ``triples``."""
    return codec.encode(_pdcap_frame(triples))


def _cap_codes(frame: OsdpFrame) -> list[int]:
    """Return the function codes of the capability triples in a REPLY_PDCAP payload."""
    body_len = len(frame.data) - (len(frame.data) % 3)
    return [frame.data[i] for i in range(0, body_len, 3)]


def _secure_marker() -> tuple[Direction, OsdpFrame]:
    """Return a frame that marks the session as Secure Channel (SCB bit + an SCS code)."""
    frame = OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=constants.PKT_CONTROL_CRC | constants.PKT_CONTROL_SCB,
        scb=bytes([0x03, constants.SCS_16, 0x00]),
        code=constants.REPLY_CCRYPT,
        data=b"",
        use_crc=True,
    )
    return (Direction.pd_to_cp, frame)


def _clear_text_session() -> list[tuple[Direction, OsdpFrame]]:
    """Return a minimal clear-text POLL/ACK session (no SCB, no SCS)."""
    poll = OsdpFrame(
        had_mark=True, address=_PD_ADDRESS, control=0x05, scb=b"", code=constants.CMD_POLL,
        data=b"", use_crc=True,
    )
    ack = OsdpFrame(
        had_mark=True, address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG, control=0x05, scb=b"",
        code=constants.REPLY_ACK, data=b"", use_crc=True,
    )
    return [(Direction.cp_to_pd, poll), (Direction.pd_to_cp, ack)]


# --------------------------------------------------------------------------------------
# The in-path transform.
# --------------------------------------------------------------------------------------


def test_strip_removes_communication_security_and_re_encodes_valid() -> None:
    """A REPLY_PDCAP with CommunicationSecurity is stripped of it and stays wire-valid."""
    out = strip_sc_capability(Direction.pd_to_cp, _pdcap_bytes(_CAPS_WITH_SC))
    frame = codec.decode(out)  # re-encoded frame must decode (valid trailer/length)
    codes = _cap_codes(frame)
    assert 0x09 not in codes, "CommunicationSecurity still present after strip"
    for code in _BASE_CAP_CODES:
        assert code in codes, f"strip dropped a base capability 0x{code:02x}: {codes}"


def test_strip_on_frame_helper_keeps_base_caps() -> None:
    """strip_communication_security drops only 0x09, preserving the other triples in order."""
    stripped = strip_communication_security(_pdcap_frame(_CAPS_WITH_SC))
    assert 0x09 not in _cap_codes(stripped)
    assert _cap_codes(stripped) == list(_BASE_CAP_CODES)


def test_reply_without_communication_security_passes_through_unchanged() -> None:
    """A REPLY_PDCAP that never advertised 0x09 is re-encoded unchanged (nothing to strip)."""
    base_only = [(0x02, 1, 1), (0x04, 2, 1), (0x05, 1, 1), (0x06, 1, 1)]
    original = _pdcap_bytes(base_only)
    out = strip_sc_capability(Direction.pd_to_cp, original)
    assert _cap_codes(codec.decode(out)) == list(_BASE_CAP_CODES)


def test_non_pdcap_frame_passes_through_byte_identically() -> None:
    """A non-PDCAP pd->cp frame is forwarded byte-for-byte (only REPLY_PDCAP is rewritten)."""
    ack = codec.encode(
        OsdpFrame(
            had_mark=True, address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG, control=0x05,
            scb=b"", code=constants.REPLY_ACK, data=b"", use_crc=True,
        )
    )
    assert strip_sc_capability(Direction.pd_to_cp, ack) == ack


def test_cp_to_pd_direction_is_never_rewritten() -> None:
    """Only pd->cp REPLY_PDCAP is rewritten; the same bytes seen cp->pd pass through."""
    pdcap = _pdcap_bytes(_CAPS_WITH_SC)
    assert strip_sc_capability(Direction.cp_to_pd, pdcap) == pdcap


def test_transform_buffers_a_pdcap_split_across_two_chunks() -> None:
    """downgrade_transform strips a REPLY_PDCAP even when it arrives in two reads."""
    pdcap = _pdcap_bytes(_CAPS_WITH_SC)
    split = len(pdcap) // 2
    transform = downgrade_transform()
    first = transform(Direction.pd_to_cp, pdcap[:split])
    second = transform(Direction.pd_to_cp, pdcap[split:])
    forwarded = first + second
    frame = codec.decode(forwarded)
    assert 0x09 not in _cap_codes(frame), "CommunicationSecurity still present after strip"
    for code in _BASE_CAP_CODES:
        assert code in _cap_codes(frame)


# --------------------------------------------------------------------------------------
# The before/after verdict.
# --------------------------------------------------------------------------------------


def test_run_downgrade_flags_secure_baseline_forced_to_clear_text() -> None:
    """A secure baseline advertising CommunicationSecurity, flipped to clear-text, is HIGH."""
    baseline = [_secure_marker(), (Direction.pd_to_cp, _pdcap_frame(_CAPS_WITH_SC))]
    attacked = _clear_text_session()
    findings = run_downgrade(baseline, attacked)
    assert len(findings) == 1, findings
    assert findings[0].id == "ATK-03-downgrade"
    assert findings[0].severity.value == "high"


def test_run_downgrade_inconclusive_when_baseline_not_secure() -> None:
    """A baseline that was already clear-text never yields a success Finding."""
    baseline = _clear_text_session()
    attacked = _clear_text_session()
    assert run_downgrade(baseline, attacked) == [], (
        "baseline-not-secure returned a success Finding"
    )


def test_run_downgrade_inconclusive_when_nothing_to_strip() -> None:
    """A secure baseline that advertised no CommunicationSecurity is inconclusive, not success."""
    base_only = [(0x02, 1, 1), (0x04, 2, 1), (0x05, 1, 1), (0x06, 1, 1)]
    baseline = [_secure_marker(), (Direction.pd_to_cp, _pdcap_frame(base_only))]
    attacked = _clear_text_session()
    assert run_downgrade(baseline, attacked) == []


def test_run_downgrade_inconclusive_when_attacked_still_secure() -> None:
    """If the attacked session stayed Secure Channel, no downgrade is reported."""
    baseline = [_secure_marker(), (Direction.pd_to_cp, _pdcap_frame(_CAPS_WITH_SC))]
    attacked = [_secure_marker()]
    assert run_downgrade(baseline, attacked) == []
