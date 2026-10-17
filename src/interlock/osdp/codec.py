"""Byte-exact OSDP frame codec: decode to fields, encode back identically.

This is the heart of OSDP-01 success criterion 1: a frame captured from the lab
must decode to an ``OsdpFrame`` and re-encode byte-for-byte identically. Three
hazards drive the design, all proven by the round-trip tests:

- the optional leading MARK (0xFF) is conditional on the wire, so ``had_mark``
  records whether it was there and encode re-attaches it only then;
- the raw control byte (sequence + CRC/SCB bits) is kept verbatim, never
  recomputed from fields, so unusual sequences survive a round-trip;
- the payload (for Secure Channel frames, ciphertext + MAC) is copied opaquely,
  so SC frames round-trip without any key.

decode fails closed: truncated, over-length, or bad-SOM input raises a typed
``DecodeError`` rather than crashing, over-reading, or looping. It bounds-checks
the declared LEN against the real buffer before slicing, so attacker-controlled
length bytes cannot drive an over-read (threat T-3-01).
"""

from __future__ import annotations

from dataclasses import dataclass

from interlock.osdp import constants

# Smallest legal frame: SOM ADDR LEN_LSB LEN_MSB CONTROL CODE + 1-byte checksum trailer.
_MIN_FRAME_LEN = 7


class DecodeError(Exception):
    """Raised when a byte buffer is not a well-formed OSDP frame.

    decode raises this (and only this) for every malformed input - truncated,
    over-length, missing SOM, or an inconsistent SCB - so callers can fail closed
    on one exception type instead of guarding against IndexError or hangs.
    """


def crc16(buf: bytes, seed: int = 0x1D0F) -> int:
    """Return the OSDP CRC-16/AUG-CCITT of ``buf`` (poly 0x1021, init 0x1D0F).

    Ported verbatim from LibOSDP ``crc16_itu_t`` in src/osdp_common.c @ v3.0.8.
    The byte-swap form plus the AUG-CCITT check value (crc16(b"123456789") ==
    0xE5CC) prove this is AUG-CCITT, not the reflected variant the C name hints at.
    """
    for byte in buf:
        seed = ((seed >> 8) | (seed << 8)) & 0xFFFF
        seed ^= byte
        seed ^= (seed & 0xFF) >> 4
        seed = (seed ^ (seed << 12)) & 0xFFFF
        seed = (seed ^ ((seed & 0xFF) << 5)) & 0xFFFF
    return seed


def crc16_le(buf: bytes) -> bytes:
    """Return the CRC-16 of ``buf`` as two little-endian bytes (LSB first).

    LibOSDP appends the trailer LSB first (src/osdp_common.c @ v3.0.8).
    """
    value = crc16(buf)
    return bytes([value & 0xFF, (value >> 8) & 0xFF])


def checksum(buf: bytes) -> bytes:
    """Return the one-byte two's-complement checksum trailer for ``buf``.

    Used when the control byte's CRC bit is clear. VERIFIED: src/osdp_phy.c @
    v3.0.8 (``~(0xff & whole_checksum) + 1``).
    """
    return bytes([(~(sum(buf) & 0xFF) + 1) & 0xFF])


@dataclass(frozen=True)
class OsdpFrame:
    """A decoded OSDP frame, holding exactly what byte-identical re-encode needs.

    ``control`` is the raw control byte, never recomputed. ``scb`` is the Secure
    Control Block bytes (b"" when absent). ``data`` is the opaque payload after the
    code byte (for SC frames, ciphertext + MAC). ``use_crc`` is derived from the
    control CRC bit and selects the trailer on encode.
    """

    had_mark: bool
    address: int
    control: int
    scb: bytes
    code: int
    data: bytes
    use_crc: bool


def decode(raw: bytes) -> OsdpFrame:
    """Decode one OSDP frame from ``raw``, failing closed on malformed input.

    ``raw`` is a single frame slice (optionally MARK-prefixed), as yielded by the
    framer. The declared LEN is bounds-checked against ``len(raw)`` before any
    slice, so truncated or over-length input raises ``DecodeError`` instead of
    over-reading.
    """
    if len(raw) < 1:
        raise DecodeError("empty buffer")

    had_mark = raw[0] == constants.MARK
    start = 1 if had_mark else 0

    # Need SOM ADDR LEN_LSB LEN_MSB CONTROL before anything can be sliced.
    if len(raw) - start < 5:
        raise DecodeError("buffer too short for an OSDP header")
    if raw[start] != constants.SOM:
        raise DecodeError(f"expected SOM 0x53 at offset {start}, got {raw[start]:#04x}")

    address = raw[start + 1]
    length = raw[start + 2] | (raw[start + 3] << 8)
    control = raw[start + 4]

    if length < _MIN_FRAME_LEN:
        raise DecodeError(f"declared length {length} is below the minimum frame size")
    # LEN counts SOM..trailer inclusive and excludes MARK; the slice must actually hold it.
    if start + length > len(raw):
        raise DecodeError(
            f"declared length {length} exceeds available {len(raw) - start} bytes (truncated)"
        )

    use_crc = bool(control & constants.PKT_CONTROL_CRC)
    has_scb = bool(control & constants.PKT_CONTROL_SCB)
    trailer_len = 2 if use_crc else 1

    # Everything between the control byte and the trailer: [SCB] CODE [DATA].
    payload = raw[start + 5 : start + length - trailer_len]
    if len(payload) < 1:
        raise DecodeError("no room for a code byte between control and trailer")

    if has_scb:
        scb_len = payload[0]
        if scb_len < 1 or scb_len > len(payload) - 1:
            raise DecodeError(f"SCB length {scb_len} is inconsistent with the payload")
        scb = payload[:scb_len]
        rest = payload[scb_len:]
    else:
        scb = b""
        rest = payload

    code = rest[0]
    data = rest[1:]

    return OsdpFrame(
        had_mark=had_mark,
        address=address,
        control=control,
        scb=scb,
        code=code,
        data=data,
        use_crc=use_crc,
    )


def encode(frame: OsdpFrame) -> bytes:
    """Encode ``frame`` back to wire bytes, identical to the frame it was decoded from.

    LEN and the trailer are recomputed over the exact SOM..data span; the MARK is
    re-attached only when ``had_mark`` is set. The control byte is emitted verbatim.
    """
    body = frame.scb + bytes([frame.code]) + frame.data
    trailer_len = 2 if frame.use_crc else 1
    # Total length from SOM to end of trailer inclusive: SOM ADDR LEN(2) CONTROL + body + trailer.
    length = 5 + len(body) + trailer_len
    header = bytes(
        [
            constants.SOM,
            frame.address & 0xFF,
            length & 0xFF,
            (length >> 8) & 0xFF,
            frame.control & 0xFF,
        ]
    )
    without_trailer = header + body
    trailer = crc16_le(without_trailer) if frame.use_crc else checksum(without_trailer)
    out = without_trailer + trailer
    return bytes([constants.MARK]) + out if frame.had_mark else out
