"""Host round-trip proof: decode then encode is byte-identical (OSDP-01, SC1).

The anchor test loads the real frame captured from the running cleartext lab
(committed under fixtures/) and asserts encode(decode(raw)) == raw. The crafted
cases pin the three byte-identity hazards (MARK, raw control, opaque payload) and
the fail-closed contract, all Docker-free.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from interlock.osdp import framer
from interlock.osdp.codec import DecodeError, OsdpFrame, decode, encode

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cleartext_sample.cap"

# A built, verified POLL frame (RESEARCH): SOM=53 ADDR=65 LEN=0008 CTRL=05(seq1|CRC)
# CODE=60(POLL) CRC=51a3, no SCB, no MARK.
POLL_NO_MARK = b"\x53\x65\x08\x00\x05\x60\x51\xa3"
POLL_WITH_MARK = b"\xff" + POLL_NO_MARK


def test_committed_fixture_round_trips_byte_identically() -> None:
    """The real captured lab frame decodes and re-encodes to the exact same bytes."""
    raw = FIXTURE.read_bytes()
    assert raw, "fixture is empty; regenerate it from the cleartext lab"
    # The fixture holds one frame slice; it must be a single trailer-valid frame.
    frames = list(framer.iter_frames(raw))
    assert frames == [raw], "fixture should be exactly one trailer-valid frame"
    assert encode(decode(raw)) == raw


def test_poll_frame_round_trips_without_mark() -> None:
    """A frame without a leading MARK re-encodes without one."""
    frame = decode(POLL_NO_MARK)
    assert frame.had_mark is False
    assert frame.address == 0x65
    assert frame.control == 0x05
    assert frame.code == 0x60
    assert frame.use_crc is True
    assert frame.scb == b""
    assert encode(frame) == POLL_NO_MARK


def test_poll_frame_round_trips_with_mark() -> None:
    """The same frame carrying a leading MARK re-encodes with the MARK preserved."""
    frame = decode(POLL_WITH_MARK)
    assert frame.had_mark is True
    assert encode(frame) == POLL_WITH_MARK


def test_control_byte_is_preserved_verbatim() -> None:
    """encode re-emits the raw control byte without recomputing it from fields."""
    # An odd sequence/flag combination that no field-based recomputation would reproduce.
    frame = OsdpFrame(
        had_mark=False,
        address=0x01,
        control=0x06,  # seq=2, CRC set, SCB clear
        scb=b"",
        code=0x60,
        data=b"",
        use_crc=True,
    )
    encoded = encode(frame)
    assert encoded[4] == 0x06
    assert decode(encoded).control == 0x06


def test_opaque_payload_round_trips_without_interpretation() -> None:
    """Arbitrary payload bytes survive a round-trip untouched (opaque copy)."""
    frame = OsdpFrame(
        had_mark=True,
        address=0x80,
        control=0x0D,  # seq=1, CRC set, SCB set
        scb=b"\x02\x17",
        code=0x76,
        data=b"\xde\xad\xbe\xef\x80\x00",
        use_crc=True,
    )
    assert decode(encode(frame)) == frame
    assert encode(decode(encode(frame))) == encode(frame)


def test_truncated_frame_fails_closed() -> None:
    """A frame cut before its trailer raises DecodeError, not IndexError or a hang."""
    truncated = POLL_NO_MARK[:-3]
    with pytest.raises(DecodeError):
        decode(truncated)


def test_bad_som_fails_closed() -> None:
    """A buffer that does not start with SOM raises DecodeError."""
    with pytest.raises(DecodeError):
        decode(b"\x00\x65\x08\x00\x05\x60\x51\xa3")


def test_overlong_declared_length_fails_closed() -> None:
    """A declared LEN larger than the buffer raises DecodeError (no over-read)."""
    overlong = b"\x53\x65\xff\x00\x05\x60\x51\xa3"
    with pytest.raises(DecodeError):
        decode(overlong)
