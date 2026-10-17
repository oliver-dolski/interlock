"""Read-only OSDP transport taps over TCP and over a pty pair (OSDP-02).

This module gives the codec one byte stream shape across two transports: a TCP
relay for the lab and an os.openpty relay for serial fidelity. Both taps sit
inline on the cp<->pd path and are strictly read-only pass-through in Phase 3:
each direction's pump hands the observed bytes to an ``on_bytes(direction, data)``
callback as a copy, then forwards the exact bytes it read onward unchanged. No
rewrite, drop, delay, or injection path exists here - that MITM seam is the
``on_bytes`` callback itself and is only driven actively in Phase 4, behind its
own gate. Observing a copy keeps the live session unaffected (SAFE-01).

The module is standard-library only at import time so it runs in the minimal lab
image. pyserial is imported lazily inside ``open_serial_endpoint`` (and only for
type checking at module scope), and nothing here imports cryptography: the TCP tap
must run where neither is installed.
"""

from __future__ import annotations

import os
import queue
import select
import socket
import threading
import time
import tty
from collections.abc import Callable, Iterator
from enum import Enum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import serial  # type: ignore[import-untyped]  # pyserial ships no type stubs

# Relay defaults. Bind inside the internal labnet only; no host port is published
# by the tap itself (SAFE-01 is enforced by compose, but the tap adds no egress).
LISTEN_HOST = "0.0.0.0"
BUFFER_SIZE = 4096

# The observation seam. Phase 3 only reads through it; Phase 4 attaches rewrite here.
OnBytes = Callable[["Direction", bytes], None]


class Direction(str, Enum):
    """Which way a chunk of bytes was travelling on the cp<->pd path.

    Direction is kept distinct per chunk because it is what disambiguates the
    shared code byte 0x76 (CMD_CHLNG vs REPLY_CCRYPT) and the address reply bit
    0x80 for later Secure Channel work. Mirrors the Severity str-Enum idiom.
    """

    cp_to_pd = "cp->pd"
    pd_to_cp = "pd->cp"


class Tap(Protocol):
    """A read-only inline observation point on the cp<->pd byte path.

    ``observe`` yields each observed chunk tagged with its direction, as the bytes
    flow on the wire, for a single bridged session. Implementations forward the
    exact bytes onward unchanged; observation never alters in-flight traffic.
    """

    def observe(self) -> Iterator[tuple[Direction, bytes]]:
        """Yield (direction, raw bytes) for each chunk observed, in wire order."""
        ...


def _pump_socket(
    src: socket.socket,
    dst: socket.socket,
    direction: Direction,
    emit: OnBytes,
) -> None:
    """Relay bytes from ``src`` to ``dst`` unchanged, emitting a copy per chunk.

    Pass-through only: ``emit`` receives a copy of the bytes read, and the exact
    bytes read are forwarded to ``dst``. No transformation happens between the read
    and the forward (read-only, Phase 3).
    """
    while True:
        try:
            data = src.recv(BUFFER_SIZE)
        except OSError:
            break
        if not data:
            break
        emit(direction, bytes(data))  # observe a copy; the live session is unaffected
        try:
            dst.sendall(data)  # forward the exact bytes read, unchanged
        except OSError:
            break


def _pump_fd(
    src_fd: int,
    dst_fd: int,
    direction: Direction,
    emit: OnBytes,
    stop: threading.Event,
) -> None:
    """Relay bytes between pty master fds unchanged, emitting a copy per chunk.

    The os.read/os.write analogue of ``_pump_socket`` for the pty tap; the same
    read-only pass-through contract holds. ``select`` with a short timeout keeps the
    read interruptible so ``stop`` lets the relay exit cleanly before its fds are
    closed (closing a pty fd under a blocked os.read hangs on macOS).
    """
    while not stop.is_set():
        try:
            readable, _, _ = select.select([src_fd], [], [], 0.2)
        except OSError:
            break
        if not readable:
            continue
        try:
            data = os.read(src_fd, BUFFER_SIZE)
        except OSError:
            break
        if not data:
            break
        emit(direction, bytes(data))  # observe a copy
        try:
            os.write(dst_fd, data)  # forward the exact bytes read, unchanged
        except OSError:
            break


class TCPTap:
    """Inline TCP tap: listen where the CP dials, relay to the upstream PD.

    Reuses the Phase 2 attacker-proxy shape: a SO_REUSEADDR listener, an upstream
    connect that retries with backoff to absorb the compose start-order race, and
    one pass-through pump thread per direction. Each pump tags its chunks with the
    Direction and hands them to ``on_bytes`` before forwarding the identical bytes.
    """

    def __init__(
        self,
        listen_port: int,
        upstream: tuple[str, int],
        on_bytes: OnBytes | None = None,
    ) -> None:
        self.listen_port = listen_port
        self.upstream = upstream
        self._on_bytes = on_bytes

    def _connect_upstream(self, *, retries: int = 30, backoff: float = 1.0) -> socket.socket:
        """Connect to the upstream PD, retrying the compose start-order race."""
        host, port = self.upstream
        last_error: OSError | None = None
        for _attempt in range(retries):
            try:
                return socket.create_connection((host, port))
            except OSError as exc:
                last_error = exc
                time.sleep(backoff)
        raise ConnectionError(
            f"could not connect to upstream {host}:{port} after {retries} attempts"
        ) from last_error

    def _listen(self) -> socket.socket:
        """Open the SO_REUSEADDR listener the CP connects to."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, self.listen_port))
        listener.listen(1)
        return listener

    def _bridge(self, cp_sock: socket.socket, emit: OnBytes) -> None:
        """Connect upstream and pump both directions between CP and PD until closed."""
        pd_sock = self._connect_upstream()
        upstream_thread = threading.Thread(
            target=_pump_socket,
            args=(cp_sock, pd_sock, Direction.cp_to_pd, emit),
            daemon=True,
        )
        upstream_thread.start()
        _pump_socket(pd_sock, cp_sock, Direction.pd_to_cp, emit)
        upstream_thread.join()
        cp_sock.close()
        pd_sock.close()

    def serve_forever(self) -> None:
        """Accept CP connections and bridge each to the upstream PD, forever.

        Uses the ``on_bytes`` callback given at construction. This is the entrypoint
        the capture runner drives inside the lab.
        """
        if self._on_bytes is None:
            raise ValueError("serve_forever requires an on_bytes callback")
        listener = self._listen()
        while True:
            cp_sock, _addr = listener.accept()
            self._bridge(cp_sock, self._on_bytes)

    def observe(self) -> Iterator[tuple[Direction, bytes]]:
        """Yield observed (direction, bytes) for one bridged CP<->PD session.

        Use either ``observe`` or the ``on_bytes`` callback with ``serve_forever``
        for a given tap, not both: each relay consumes its sockets once.
        """
        sink: queue.Queue[tuple[Direction, bytes] | None] = queue.Queue()

        def run() -> None:
            try:
                listener = self._listen()
                cp_sock, _addr = listener.accept()
                self._bridge(cp_sock, lambda direction, data: sink.put((direction, data)))
            finally:
                sink.put(None)

        threading.Thread(target=run, daemon=True).start()
        while (item := sink.get()) is not None:
            yield item


class PtyTap:
    """Inline pty tap: relay bytes between two os.openpty pairs, read-only.

    The tap owns the master end of a CP-side pair and a PD-side pair; endpoints
    attach to the slave device paths (``cp_path`` / ``pd_path``) via pyserial or
    raw os.read/os.write. The relay is the same two-direction pass-through shape as
    the TCP tap, over master fds instead of sockets.
    """

    def __init__(self, on_bytes: OnBytes | None = None) -> None:
        self._on_bytes = on_bytes
        self._master_cp, self._slave_cp = os.openpty()
        self._master_pd, self._slave_pd = os.openpty()
        # Put both slaves in raw mode: a pty defaults to a cooked line discipline that
        # mangles binary (CR<->NL translation, XON/XOFF flow control on 0x11/0x13,
        # canonical buffering), which would corrupt OSDP frames. Raw mode makes the
        # relay a faithful byte pipe in both directions, including the raw-fd fallback.
        tty.setraw(self._slave_cp)
        tty.setraw(self._slave_pd)
        # Slave device paths the CP and PD endpoints open; the tap holds the masters.
        self.cp_path = os.ttyname(self._slave_cp)
        self.pd_path = os.ttyname(self._slave_pd)
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def start(self) -> None:
        """Launch the two relay threads using the ``on_bytes`` callback (non-blocking)."""
        emit = self._on_bytes if self._on_bytes is not None else (lambda direction, data: None)
        self._threads = [
            threading.Thread(
                target=_pump_fd,
                args=(self._master_cp, self._master_pd, Direction.cp_to_pd, emit, self._stop),
                daemon=True,
            ),
            threading.Thread(
                target=_pump_fd,
                args=(self._master_pd, self._master_cp, Direction.pd_to_cp, emit, self._stop),
                daemon=True,
            ),
        ]
        for thread in self._threads:
            thread.start()

    def observe(self) -> Iterator[tuple[Direction, bytes]]:
        """Yield observed (direction, bytes) until both relay directions see EOF.

        Use either ``observe`` or the ``on_bytes`` callback with ``start`` for a
        given tap, not both: each relay consumes its master fds once.
        """
        sink: queue.Queue[tuple[Direction, bytes] | None] = queue.Queue()

        def relay(src_fd: int, dst_fd: int, direction: Direction) -> None:
            try:
                _pump_fd(src_fd, dst_fd, direction, lambda d, data: sink.put((d, data)), self._stop)
            finally:
                sink.put(None)

        self._threads = [
            threading.Thread(
                target=relay, args=(self._master_cp, self._master_pd, Direction.cp_to_pd), daemon=True
            ),
            threading.Thread(
                target=relay, args=(self._master_pd, self._master_cp, Direction.pd_to_cp), daemon=True
            ),
        ]
        for worker in self._threads:
            worker.start()
        remaining = len(self._threads)
        while remaining:
            item = sink.get()
            if item is None:
                remaining -= 1
                continue
            yield item

    def close(self) -> None:
        """Stop the relay threads, then close every pty fd; safe to call repeatedly.

        The threads are stopped and joined before any fd is closed, because closing a
        pty fd while a thread is blocked reading it hangs on macOS.
        """
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=2.0)
        for fd in (self._master_cp, self._slave_cp, self._master_pd, self._slave_pd):
            try:
                os.close(fd)
            except OSError:
                pass


def open_serial_endpoint(
    device_path: str,
    *,
    baudrate: int = 9600,
    timeout: float = 1.0,
) -> serial.Serial:
    """Return a pyserial Serial bound to ``device_path`` (pty slave or real port).

    pyserial is imported lazily here, never at module scope, so the stdlib-only TCP
    tap runs in the minimal lab image. If pyserial is unavailable (the 03-01 probe
    fallback), this raises a clear error and callers fall back to raw os.read/write.
    """
    try:
        import serial
    except ImportError as exc:  # pragma: no cover - pyserial resolved on host per 03-01
        raise RuntimeError(
            "pyserial is not available; use raw os.read/os.write on the pty slave instead"
        ) from exc
    return serial.Serial(device_path, baudrate=baudrate, timeout=timeout)
