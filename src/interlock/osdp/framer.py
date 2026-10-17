"""Stream framer: resync on SOM and cut complete OSDP frames out of a byte buffer.

A tap hands the codec a chunked byte stream (the same shape the Phase 2 attacker
``pump`` loop produces). This framer buffers that stream, resynchronizes on the
SOM marker, honors an optional leading MARK, reads the little-endian LEN, and
yields each complete SOM..trailer slice.

It validates the trailer (CRC-16 or checksum) before yielding, so bytes that do
not begin a trailer-valid frame are skipped one at a time. That keeps an
interleaved capture (both directions appended to one file in Phase 2) recoverable:
junk and half-frames are stepped over instead of derailing the whole stream.
"""

from __future__ import annotations

from collections.abc import Iterator

from interlock.osdp import codec, constants

# A frame must hold SOM ADDR LEN_LSB LEN_MSB CONTROL CODE + a 1-byte trailer at least.
_MIN_FRAME_LEN = 7


def _valid_trailer(frame: bytes) -> bool:
    """Return True if ``frame`` (SOM..trailer, no MARK) carries a correct trailer."""
    control = frame[4]
    if control & constants.PKT_CONTROL_CRC:
        return codec.crc16_le(frame[:-2]) == frame[-2:]
    return codec.checksum(frame[:-1]) == frame[-1:]


def iter_frames(buffer: bytes) -> Iterator[bytes]:
    """Yield each complete, trailer-valid OSDP frame slice found in ``buffer``.

    Each yielded slice includes the leading MARK when the frame carried one, so it
    round-trips through ``codec.decode``/``codec.encode`` byte-identically. Bytes
    that do not begin a valid frame are skipped, so resync survives interleaving.
    """
    i = 0
    n = len(buffer)
    while i < n:
        had_mark = buffer[i] == constants.MARK and i + 1 < n and buffer[i + 1] == constants.SOM
        som = i + 1 if had_mark else i

        if buffer[som] != constants.SOM:
            i += 1
            continue
        # Need the 5-byte header to read the declared length.
        if som + 5 > n:
            break

        length = buffer[som + 2] | (buffer[som + 3] << 8)
        if length < _MIN_FRAME_LEN:
            i += 1
            continue
        if som + length > n:
            # Could be a real frame split across reads, or a false SOM; step on and rescan.
            i += 1
            continue

        frame = buffer[som : som + length]
        if not _valid_trailer(frame):
            i += 1
            continue

        yield buffer[i : som + length]
        i = som + length
