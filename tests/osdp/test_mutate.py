"""Mutation catalogue proof plus the decoder fail-closed resilience sweep (OSDP-01, SC2).

Two things are proven here, all Docker-free (no ``lab`` marker):

- Each ``Mutation`` member produces bytes carrying its specific named defect, built
  from a known-good frame so exactly one byte or field differs.
- ``codec.decode`` is resilient against the full malformed corpus: fed every mutated
  frame plus standalone truncated and over-length inputs it never raises an unhandled
  exception and never hangs (threat T-3-06 / DoS). Structurally broken inputs raise a
  typed ``DecodeError``; the semantically malformed but well-formed frames (bad_crc,
  illegal_seq, unknown_code) decode cleanly, which is the deliberate 03-01 contract:
  ``decode`` is structural and does not validate the trailer, sequence, or code byte.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from interlock.osdp import codec, constants
from interlock.osdp.mutate import Mutation, mutate

_KNOWN_CODES = frozenset(constants.COMMAND_CODES) | frozenset(constants.REPLY_CODES)

# Known-good base frames spanning the byte-identity hazards: a CRC frame, the same with a
# leading MARK, and a one-byte-checksum frame. control 0x05 = CRC bit set, sequence 1.
_BASE_FRAMES: dict[str, codec.OsdpFrame] = {
    "crc": codec.OsdpFrame(
        had_mark=False, address=0x65, control=0x05, scb=b"", code=0x60, data=b"\x01\x02", use_crc=True
    ),
    "crc_mark": codec.OsdpFrame(
        had_mark=True, address=0x65, control=0x05, scb=b"", code=0x60, data=b"\x01\x02", use_crc=True
    ),
    "checksum": codec.OsdpFrame(
        had_mark=False, address=0x65, control=0x01, scb=b"", code=0x60, data=b"", use_crc=False
    ),
}

# Mutations that break frame structure, so decode must reject them with a typed DecodeError.
_STRUCTURAL = {
    Mutation.wrong_length,
    Mutation.truncated,
    Mutation.scb_inconsistent,
    Mutation.bad_som,
    Mutation.oversized,
}
# Mutations that stay structurally well formed, so decode returns a frame (03-01 contract).
_SEMANTIC = {Mutation.bad_crc, Mutation.illegal_seq, Mutation.unknown_code, Mutation.inject_rmac}


def _good() -> bytes:
    return codec.encode(_BASE_FRAMES["crc"])


def _layout(raw: bytes) -> tuple[int, int]:
    """Return ``(start, trailer_len)``: the SOM offset and trailer size of ``raw``."""
    start = 1 if raw[:1] == bytes([constants.MARK]) else 0
    control = raw[start + 4]
    trailer_len = 2 if control & constants.PKT_CONTROL_CRC else 1
    return start, trailer_len


def _declared_length(raw: bytes) -> int:
    start, _ = _layout(raw)
    return raw[start + 2] | (raw[start + 3] << 8)


def _decode_outcome(raw: bytes, timeout: float = 5.0) -> dict[str, Any]:
    """Run ``codec.decode`` in a bounded thread, proving it returns (no hang).

    Returns ``{"frame": OsdpFrame}`` on success or ``{"exc": Exception}`` on failure;
    a thread still alive after ``timeout`` fails the test as a hang.
    """
    result: dict[str, Any] = {}

    def run() -> None:
        try:
            result["frame"] = codec.decode(raw)
        except Exception as exc:  # noqa: BLE001 - catch broadly on purpose: the test asserts decode raises only DecodeError
            result["exc"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    assert not worker.is_alive(), "codec.decode did not return within the timeout (possible hang)"
    return result


# --------------------------------------------------------------------------------------
# Every mutation changes the frame, for every base shape.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("base_name", list(_BASE_FRAMES))
@pytest.mark.parametrize("how", list(Mutation))
def test_every_mutation_changes_the_frame(base_name: str, how: Mutation) -> None:
    """Each mutation on each base frame returns bytes that differ from the good frame."""
    good = codec.encode(_BASE_FRAMES[base_name])
    assert mutate(good, how) != good


# --------------------------------------------------------------------------------------
# Per-dimension defect assertions.
# --------------------------------------------------------------------------------------


def test_bad_crc_trailer_is_not_the_real_crc() -> None:
    good = _good()
    bad = mutate(good, Mutation.bad_crc)
    # The body is untouched, so the correct trailer is unchanged; only the trailer bytes differ.
    assert bad[:-2] == good[:-2]
    assert bad[-2:] != codec.crc16_le(bad[:-2])


def test_wrong_length_declares_a_length_other_than_the_real_length() -> None:
    good = _good()
    bad = mutate(good, Mutation.wrong_length)
    start, _ = _layout(bad)
    assert _declared_length(bad) != len(bad) - start


def test_illegal_seq_changes_the_sequence_bits() -> None:
    good = _good()
    bad = mutate(good, Mutation.illegal_seq)
    good_seq = codec.decode(good).control & constants.PKT_CONTROL_SQN
    bad_seq = codec.decode(bad).control & constants.PKT_CONTROL_SQN
    assert bad_seq != good_seq
    # The base frame carries sequence 1; the mutation drives it to the illegal reset value 0.
    assert bad_seq == 0


def test_truncated_is_shorter_than_the_good_frame() -> None:
    good = _good()
    bad = mutate(good, Mutation.truncated)
    assert len(bad) < len(good)


def test_scb_inconsistent_sets_the_scb_bit_without_scb_bytes() -> None:
    good = _good()
    bad = mutate(good, Mutation.scb_inconsistent)
    start, _ = _layout(bad)
    assert bad[start + 4] & constants.PKT_CONTROL_SCB


def test_bad_som_yields_a_som_position_byte_other_than_0x53() -> None:
    good = _good()
    bad = mutate(good, Mutation.bad_som)
    start, _ = _layout(bad)
    assert bad[start] != constants.SOM


def test_oversized_declares_a_length_beyond_any_sane_buffer() -> None:
    good = _good()
    bad = mutate(good, Mutation.oversized)
    # LibOSDP OSDP_PACKET_BUF_SIZE is 128/256 at v3.0.8; anything past that is oversized.
    assert _declared_length(bad) > 256


def test_unknown_code_is_outside_the_known_tables() -> None:
    good = _good()
    bad = mutate(good, Mutation.unknown_code)
    assert codec.decode(bad).code not in _KNOWN_CODES


def test_inject_rmac_restamps_the_code_as_out_of_sequence_rmac() -> None:
    good = _good()
    bad = mutate(good, Mutation.inject_rmac)
    # The base is a POLL; the mutation re-stamps it as REPLY_RMAC_I (0x78), the CVE-2024-52288 shape.
    assert codec.decode(bad).code == constants.REPLY_RMAC_I


# --------------------------------------------------------------------------------------
# Decoder fail-closed resilience sweep.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("base_name", list(_BASE_FRAMES))
@pytest.mark.parametrize("how", list(Mutation))
def test_decode_is_resilient_against_every_mutation(base_name: str, how: Mutation) -> None:
    """Fed any mutated frame, decode returns promptly and raises only a typed DecodeError."""
    good = codec.encode(_BASE_FRAMES[base_name])
    outcome = _decode_outcome(mutate(good, how))
    if "exc" in outcome:
        assert isinstance(outcome["exc"], codec.DecodeError), (
            f"{how.value} on {base_name} raised {type(outcome['exc']).__name__}, not DecodeError"
        )
    else:
        assert isinstance(outcome["frame"], codec.OsdpFrame)


@pytest.mark.parametrize("how", sorted(_STRUCTURAL))
def test_structural_mutations_fail_closed_with_decode_error(how: Mutation) -> None:
    """Structurally broken mutations raise DecodeError rather than decoding."""
    with pytest.raises(codec.DecodeError):
        codec.decode(mutate(_good(), how))


@pytest.mark.parametrize("how", sorted(_SEMANTIC))
def test_semantic_mutations_decode_by_the_structural_contract(how: Mutation) -> None:
    """Well-formed-but-hostile mutations decode cleanly (decode is structural, per 03-01)."""
    frame = codec.decode(mutate(_good(), how))
    assert isinstance(frame, codec.OsdpFrame)


def test_decode_fails_closed_on_standalone_truncated_input() -> None:
    """A buffer too short to hold a header raises DecodeError, not IndexError."""
    truncated = bytes([constants.SOM, 0x00])
    outcome = _decode_outcome(truncated)
    assert isinstance(outcome.get("exc"), codec.DecodeError)


def test_decode_fails_closed_on_standalone_over_length_input() -> None:
    """A frame whose declared LEN exceeds the buffer raises DecodeError, not an over-read."""
    # SOM, addr, LEN=0x20 (32) little-endian, control (checksum), code, one trailer byte: 7 bytes.
    over_length = bytes([constants.SOM, 0x00, 0x20, 0x00, 0x04, constants.CMD_POLL, 0x00])
    outcome = _decode_outcome(over_length)
    assert isinstance(outcome.get("exc"), codec.DecodeError)


# --------------------------------------------------------------------------------------
# Fail-closed dispatch: an unknown Mutation value is rejected, never silently passed through.
# --------------------------------------------------------------------------------------


def test_unknown_mutation_value_is_rejected() -> None:
    good = _good()
    with pytest.raises(KeyError):
        mutate(good, "not_a_mutation")  # type: ignore[arg-type]
