"""TCP transport for LibOSDP's user-defined channel.

LibOSDP ships no TCP channel; the transport is a user-supplied ``Channel``
subclass with ``read``/``write``/``flush``. ``TCPChannel`` adapts a connected
TCP socket to that contract. The socket is kept non-blocking on purpose:
LibOSDP services the channel from its refresh loop roughly every 20 ms, and a
blocking ``recv`` would stall that loop and drop the PD offline (RESEARCH
Pitfall 3).

``listen`` (PD side) and ``connect_with_retry`` (CP side) build the sockets the
channel wraps. The retry tolerates the compose start-order race where the CP
dials before the PD is listening (RESEARCH Pitfall 5).
"""

from __future__ import annotations

import socket
import time

from osdp import Channel

LAB_PORT = 10000


class TCPChannel(Channel):
    """Adapt a connected TCP socket to LibOSDP's non-blocking Channel contract."""

    def __init__(self, sock: socket.socket) -> None:
        super().__init__()
        self.sock = sock
        self.sock.setblocking(False)

    def read(self, max_bytes: int) -> bytes:
        """Return up to ``max_bytes`` without blocking; ``b""`` when nothing is ready."""
        try:
            return self.sock.recv(max_bytes)
        except BlockingIOError:
            return b""

    def write(self, buf: bytes) -> int:
        """Send what the socket accepts now; ``0`` when the send would block."""
        try:
            return self.sock.send(buf)
        except BlockingIOError:
            return 0

    def flush(self) -> None:
        """No-op: a TCP socket has no user-space buffer to flush."""


def listen(bind_host: str, port: int) -> socket.socket:
    """Accept one inbound connection and return the connected socket (PD side)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((bind_host, port))
        listener.listen(1)
        conn, _addr = listener.accept()
    finally:
        listener.close()
    return conn


def connect_with_retry(
    host: str,
    port: int,
    *,
    retries: int = 30,
    backoff: float = 1.0,
) -> socket.socket:
    """Connect to ``host:port``, retrying the compose start-order race (CP side)."""
    last_error: OSError | None = None
    for _attempt in range(retries):
        try:
            return socket.create_connection((host, port))
        except OSError as exc:
            last_error = exc
            time.sleep(backoff)
    raise ConnectionError(
        f"could not connect to {host}:{port} after {retries} attempts"
    ) from last_error
