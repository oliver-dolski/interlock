"""Pty tap round-trip: bytes relayed across os.openpty are observed per direction.

This is the host-local (no Docker, no ``lab`` marker) proof for the pty transport
(OSDP-02, SC3). A PtyTap sits between two os.openpty pairs; the CP and PD endpoints
attach to the slave device paths via pyserial (kept on the host per 03-01; the raw
os.read/os.write fallback is the tap's own raw-mode slaves if pyserial is absent).
Known-good frames built with codec.encode - one without a MARK (cp->pd) and one with
a MARK (pd->cp) - are sent from each side. The test asserts the receiving endpoint
gets the exact bytes, the tap observed them tagged with the right direction, and
codec.decode recovers the original frames from what the tap saw.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

from interlock.osdp import framer
from interlock.osdp.codec import OsdpFrame, decode, encode
from interlock.osdp.transport import Direction, PtyTap, open_serial_endpoint

if TYPE_CHECKING:
    import serial

# A plain POLL (cp->pd), no SCB, no MARK.
POLL = OsdpFrame(
    had_mark=False, address=0x65, control=0x05, scb=b"", code=0x60, data=b"", use_crc=True
)
# An ACK reply (pd->cp), reply direction bit set, carrying a leading MARK.
ACK = OsdpFrame(
    had_mark=True, address=0xE5, control=0x06, scb=b"", code=0x40, data=b"", use_crc=True
)


def _read_exact(port: serial.Serial, count: int, *, timeout: float = 3.0) -> bytes:
    """Read exactly ``count`` bytes from ``port`` or as many as arrive before timeout."""
    deadline = time.monotonic() + timeout
    buffer = bytearray()
    while len(buffer) < count and time.monotonic() < deadline:
        chunk = port.read(count - len(buffer))
        if chunk:
            buffer.extend(chunk)
    return bytes(buffer)


def test_pty_tap_relays_and_observes_both_directions() -> None:
    observed: dict[Direction, bytearray] = {
        Direction.cp_to_pd: bytearray(),
        Direction.pd_to_cp: bytearray(),
    }
    lock = threading.Lock()

    def record(direction: Direction, data: bytes) -> None:
        with lock:
            observed[direction].extend(data)

    tap = PtyTap(on_bytes=record)
    cp = open_serial_endpoint(tap.cp_path)
    pd = open_serial_endpoint(tap.pd_path)
    try:
        tap.start()

        cp_frame = encode(POLL)  # no MARK
        pd_frame = encode(ACK)  # with MARK

        # CP -> PD: the PD endpoint must receive the exact bytes the CP sent.
        cp.write(cp_frame)
        cp.flush()
        assert _read_exact(pd, len(cp_frame)) == cp_frame

        # PD -> CP: and the reverse, with the MARK-carrying frame.
        pd.write(pd_frame)
        pd.flush()
        assert _read_exact(cp, len(pd_frame)) == pd_frame

        # The relay emits each chunk before forwarding it, so once the receiving
        # endpoint has the bytes the tap has already recorded them.
        with lock:
            cp_seen = bytes(observed[Direction.cp_to_pd])
            pd_seen = bytes(observed[Direction.pd_to_cp])
    finally:
        cp.close()
        pd.close()
        tap.close()

    assert cp_seen == cp_frame, "tap did not observe the cp->pd bytes faithfully"
    assert pd_seen == pd_frame, "tap did not observe the pd->cp bytes faithfully"

    # The codec recovers the original frames from exactly what the tap observed.
    assert list(framer.iter_frames(cp_seen)) == [cp_frame]
    assert list(framer.iter_frames(pd_seen)) == [pd_frame]
    assert decode(cp_seen) == POLL
    assert decode(pd_seen) == ACK
    # The MARK hazard is exercised across the two directions.
    assert decode(cp_seen).had_mark is False
    assert decode(pd_seen).had_mark is True
