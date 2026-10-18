"""Write-capable MITM seam: the rewrite pumps rewrite / drop / pass bytes through.

This is the host-local (no Docker, no ``lab`` marker) proof for the Phase 4 active
transport seam. Each test runs one rewrite pump over a loopback pair - a socket pair
for ``_pump_socket_rewrite`` and an os.pipe pair for ``_pump_fd_rewrite`` - feeds it a
known byte stream, and asserts exactly what the far side receives:

- a pass-through transform forwards the input byte-identically (parity with the
  read-only pump),
- a ``b""`` transform drops every chunk (nothing is forwarded),
- a modifying transform forwards the modified bytes.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from collections.abc import Callable

from interlock.osdp.transport import (
    Direction,
    _pump_fd_rewrite,
    _pump_socket_rewrite,
)

SENT = b"\xff\x53\x07\x00\x04\x60\x1a\x2b"  # a MARK + a short OSDP-shaped frame


def _drain(sock: socket.socket, *, timeout: float = 3.0) -> bytes:
    """Read from ``sock`` until the peer signals EOF, returning everything received."""
    sock.settimeout(timeout)
    out = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


def _run_socket_pump(transform: Callable[[Direction, bytes], bytes], sent: bytes) -> bytes:
    """Run ``_pump_socket_rewrite`` over loopback pairs and return the forwarded bytes."""
    src_feed, src = socket.socketpair()
    dst, dst_recv = socket.socketpair()
    thread = threading.Thread(
        target=_pump_socket_rewrite,
        args=(src, dst, Direction.cp_to_pd, transform),
        daemon=True,
    )
    thread.start()
    try:
        src_feed.sendall(sent)
        src_feed.close()  # EOF: the pump drains, then breaks
        thread.join(timeout=3.0)
        dst.shutdown(socket.SHUT_WR)  # signal EOF to the receiving side
        return _drain(dst_recv)
    finally:
        for sock in (src_feed, src, dst, dst_recv):
            try:
                sock.close()
            except OSError:
                pass


def test_socket_rewrite_passes_through_byte_identically() -> None:
    forwarded = _run_socket_pump(lambda direction, data: data, SENT)
    assert forwarded == SENT


def test_socket_rewrite_drops_on_empty_return() -> None:
    forwarded = _run_socket_pump(lambda direction, data: b"", SENT)
    assert forwarded == b""


def test_socket_rewrite_forwards_modified_bytes() -> None:
    modified = SENT.replace(b"\x60", b"\x6e")  # rewrite the code byte
    forwarded = _run_socket_pump(lambda direction, data: data.replace(b"\x60", b"\x6e"), SENT)
    assert forwarded == modified


def test_socket_rewrite_tags_direction() -> None:
    seen: list[Direction] = []

    def transform(direction: Direction, data: bytes) -> bytes:
        seen.append(direction)
        return data

    forwarded = _run_socket_pump(transform, SENT)
    assert forwarded == SENT
    assert seen and all(direction is Direction.cp_to_pd for direction in seen)


def _readable(fd: int, timeout: float) -> bool:
    import select

    readable, _, _ = select.select([fd], [], [], timeout)
    return bool(readable)


def _run_fd_pump(transform: Callable[[Direction, bytes], bytes], sent: bytes) -> bytes:
    """Run ``_pump_fd_rewrite`` over os.pipe pairs and return the forwarded bytes."""
    src_r, src_w = os.pipe()  # the pump reads src_r; the test writes src_w
    dst_r, dst_w = os.pipe()  # the pump writes dst_w; the test reads dst_r
    stop = threading.Event()
    thread = threading.Thread(
        target=_pump_fd_rewrite,
        args=(src_r, dst_w, Direction.pd_to_cp, transform, stop),
        daemon=True,
    )
    thread.start()
    try:
        os.write(src_w, sent)
        expected = transform(Direction.pd_to_cp, sent)
        out = bytearray()
        deadline = time.monotonic() + 2.0
        # Read until the expected length arrives, or a short settle passes (drop -> none).
        while len(out) < len(expected) and time.monotonic() < deadline:
            if _readable(dst_r, 0.2):
                out.extend(os.read(dst_r, 4096))
        return bytes(out)
    finally:
        stop.set()
        thread.join(timeout=3.0)
        for fd in (src_r, src_w, dst_r, dst_w):
            try:
                os.close(fd)
            except OSError:
                pass


def test_fd_rewrite_forwards_modified_bytes() -> None:
    modified = SENT.replace(b"\x60", b"\x6e")
    forwarded = _run_fd_pump(lambda direction, data: data.replace(b"\x60", b"\x6e"), SENT)
    assert forwarded == modified


def test_fd_rewrite_passes_through_byte_identically() -> None:
    forwarded = _run_fd_pump(lambda direction, data: data, SENT)
    assert forwarded == SENT
