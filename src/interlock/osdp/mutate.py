"""Deterministic OSDP frame mutator: one named corruption per call, host-side only.

This is the malformed / out-of-sequence building block for OSDP-01 Success
Criterion 2. ``mutate(good, how)`` takes a known-good frame (as produced by
``codec.encode``) and returns a copy broken along exactly one named dimension, so
a fuzzer or a test can reason about precisely which byte or field changed. Every
mutation is deterministic (same input, same output) and reversible in the sense
that the single changed byte or field is obvious.

This module GENERATES bytes only. It opens no socket, pty, or serial port and
sends nothing anywhere. Phase 3 deliberately exposes no path that places a
crafted frame on a live bus or target; active injection and the physical-mode
flag are deferred to Phase 4 behind SAFE-02 / ATK-07 (threat T-3-05). The
dual-use boundary is held here by doing no I/O at all (AST- and grep-enforced by
the tests).

Two families of mutation:

- Structural corruptions (bad_crc, wrong_length, truncated, bad_som, oversized)
  edit the raw wire bytes so the frame no longer parses. wrong_length, truncated,
  bad_som, and oversized break the frame structure, so feeding them back into
  ``codec.decode`` raises a typed ``DecodeError``.
- Semantic corruptions (illegal_seq, scb_inconsistent, unknown_code,
  inject_rmac) rebuild a structurally valid frame (recomputed LEN and trailer)
  carrying exactly one illegal field. scb_inconsistent still trips the decoder
  (its SCB claim is structural). The other three are, by the deliberate 03-01
  contract, decoded successfully: ``codec.decode`` is structural and does not
  validate the trailer, the sequence number, or the code byte, so a frame that is
  well formed but hostile in content (bad CRC, illegal sequence, out-of-sequence
  RMAC) round-trips cleanly. That is the point of these three: they model the
  frames a live reader must reject at a higher layer, not ones the parser rejects.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from enum import Enum

from interlock.osdp import codec, constants

# Far beyond any sane OSDP receive buffer; LibOSDP OSDP_PACKET_BUF_SIZE is 128/256 at v3.0.8,
# so a declared LEN of 0xFFFF is unambiguously oversized and cannot fit a real frame.
_OVERSIZED_LEN = 0xFFFF

# The union of every known command and reply code; unknown_code picks a byte outside it.
_KNOWN_CODES = frozenset(constants.COMMAND_CODES) | frozenset(constants.REPLY_CODES)


class Mutation(str, Enum):
    """The named catalogue of frame corruptions, one member per malformed dimension.

    Mirrors the str-Enum style of ``lab/osdp/scenarios.Scenario`` so a member's
    value is its own wire-free name, usable as a CLI argument or test parameter.
    """

    bad_crc = "bad_crc"
    wrong_length = "wrong_length"
    illegal_seq = "illegal_seq"
    truncated = "truncated"
    scb_inconsistent = "scb_inconsistent"
    bad_som = "bad_som"
    oversized = "oversized"
    unknown_code = "unknown_code"
    inject_rmac = "inject_rmac"


def _layout(good: bytes) -> tuple[int, int]:
    """Return ``(start, trailer_len)`` for ``good``: the SOM offset and trailer size.

    ``start`` is 1 when a leading MARK is present, else 0. ``trailer_len`` is 2 for
    a CRC frame (control CRC bit set) and 1 for a checksum frame.
    """
    start = 1 if good[:1] == bytes([constants.MARK]) else 0
    control = good[start + 4]
    trailer_len = 2 if control & constants.PKT_CONTROL_CRC else 1
    return start, trailer_len


def _pick_unknown_code(exclude: int) -> int:
    """Return the lowest byte value that is neither a known code nor ``exclude``."""
    for candidate in range(256):
        if candidate not in _KNOWN_CODES and candidate != exclude:
            return candidate
    raise AssertionError("no unknown code byte available")  # unreachable: 256 > known + 1


def _bad_crc(good: bytes) -> bytes:
    """Flip the final trailer byte so it is no longer the real CRC/checksum of the body."""
    corrupted = bytearray(good)
    corrupted[-1] ^= 0xFF
    return bytes(corrupted)


def _wrong_length(good: bytes) -> bytes:
    """Set the declared LEN to one greater than the true frame length."""
    start, _ = _layout(good)
    declared = (good[start + 2] | (good[start + 3] << 8)) + 1
    corrupted = bytearray(good)
    corrupted[start + 2] = declared & 0xFF
    corrupted[start + 3] = (declared >> 8) & 0xFF
    return bytes(corrupted)


def _truncated(good: bytes) -> bytes:
    """Stop the bytes before the trailer; the declared LEN now exceeds the buffer."""
    _, trailer_len = _layout(good)
    return good[: len(good) - trailer_len]


def _bad_som(good: bytes) -> bytes:
    """Overwrite the SOM byte so it is no longer 0x53."""
    start, _ = _layout(good)
    corrupted = bytearray(good)
    corrupted[start] = 0x00
    return bytes(corrupted)


def _oversized(good: bytes) -> bytes:
    """Set the declared LEN far beyond any sane OSDP buffer bound."""
    start, _ = _layout(good)
    corrupted = bytearray(good)
    corrupted[start + 2] = _OVERSIZED_LEN & 0xFF
    corrupted[start + 3] = (_OVERSIZED_LEN >> 8) & 0xFF
    return bytes(corrupted)


def _illegal_seq(good: bytes) -> bytes:
    """Flip the low sequence bit; a seq-1 frame becomes seq 0, the illegal mid-session reset.

    Rebuilds a structurally valid frame (correct LEN and trailer) whose only defect
    is the sequence number, so the illegal sequence is the single reversible change.
    """
    frame = codec.decode(good)
    return codec.encode(replace(frame, control=frame.control ^ 0x01))


def _scb_inconsistent(good: bytes) -> bytes:
    """Set the Secure Control Block bit in the control byte while carrying no SCB bytes."""
    frame = codec.decode(good)
    return codec.encode(replace(frame, control=frame.control | constants.PKT_CONTROL_SCB, scb=b""))


def _unknown_code(good: bytes) -> bytes:
    """Re-stamp the code byte with a value outside the known CMD_/REPLY_ tables."""
    frame = codec.decode(good)
    return codec.encode(replace(frame, code=_pick_unknown_code(frame.code)))


def _inject_rmac(good: bytes) -> bytes:
    """Re-stamp the frame as an out-of-sequence REPLY_RMAC_I (0x78), the CVE-2024-52288 shape.

    If the frame is already an RMAC_I reply, use REPLY_CCRYPT (0x76) instead so the
    result always differs from the input. Crafted bytes only; nothing is sent.
    """
    frame = codec.decode(good)
    code = constants.REPLY_RMAC_I if frame.code != constants.REPLY_RMAC_I else constants.REPLY_CCRYPT
    return codec.encode(replace(frame, code=code))


_DISPATCH: dict[Mutation, Callable[[bytes], bytes]] = {
    Mutation.bad_crc: _bad_crc,
    Mutation.wrong_length: _wrong_length,
    Mutation.illegal_seq: _illegal_seq,
    Mutation.truncated: _truncated,
    Mutation.scb_inconsistent: _scb_inconsistent,
    Mutation.bad_som: _bad_som,
    Mutation.oversized: _oversized,
    Mutation.unknown_code: _unknown_code,
    Mutation.inject_rmac: _inject_rmac,
}


def mutate(good: bytes, how: Mutation) -> bytes:
    """Return ``good`` corrupted along the single dimension ``how``.

    ``good`` is a known-good frame built by ``codec.encode``. Dispatch is by exact
    ``Mutation`` member; an unknown value fails closed by raising ``KeyError``
    (mirroring ``scenarios.get``), never silently returning ``good`` unchanged.
    """
    try:
        handler = _DISPATCH[how]
    except KeyError:
        raise KeyError(f"unknown mutation: {how!r}") from None
    return handler(good)
