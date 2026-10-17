"""Inline TCP relay for the OSDP lab's attacker position (LAB-03).

Runs as the ``attacker`` container's entrypoint. The attacker sits inline on the
``cp -> attacker -> pd`` path: the CP dials ``attacker:10000`` instead of the PD,
and the attacker forwards every byte to the real PD at ``ATTACKER_UPSTREAM``
(default ``pd:10000``). A unicast TCP stream is only observable from inside the
path, so this inline position - not a passive bridge sniffer - is what makes the
PD<->CP exchange visible to later phases.

In Phase 2 the relay is strictly pass-through plus capture: each direction's
``pump`` hands every chunk to ``sink`` before forwarding the identical bytes
onward. Nothing is altered, dropped, or injected - MITM rewrite/injection is
deferred to Phase 4 behind its own gate. The capture is appended to a fixed path
inside the attacker container; the path is used exactly as given, with no shell
expansion (threat T-2-05 / report.py T-01-02 pattern). There is no host mount and
no egress (labnet is internal), so observed traffic never leaves the lab.

The upstream connect retries with backoff so it does not race the PD listener on
compose startup (the same start-order tolerance the CP uses, RESEARCH Pitfall 5);
the relay depends only on the Python standard library, adding no new install
surface over the fixed image (threat T-2-SC).
"""

from __future__ import annotations

import os
import socket
import threading
import time
from collections.abc import Callable
from pathlib import Path

# Bind inside the internal labnet only; no host port is published (SAFE-01).
LISTEN_HOST = "0.0.0.0"
LAB_PORT = 10000
BUFFER_SIZE = 4096

# Fixed in-container capture path. No host mount: the capture stays inside the
# attacker container and never crosses the labnet boundary (threat T-2-05).
CAPTURE_PATH = Path("/app/capture/session.cap")

Sink = Callable[[bytes], None]


class Capture:
    """Thread-safe byte sink that appends observed traffic to a fixed file.

    Both pump directions share one ``Capture``; its lock serializes their
    appends so the capture is a faithful, interleaved record of the exchange.
    The file is truncated at startup so a run's capture reflects only that run.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        # Path used exactly as given; create parents, no shell expansion (T-2-05).
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(b"")

    def sink(self, data: bytes) -> None:
        """Append ``data`` to the capture file under the shared lock."""
        with self._lock, self.path.open("ab") as handle:
            handle.write(data)


def _upstream() -> tuple[str, int]:
    """Parse ``ATTACKER_UPSTREAM`` (``host:port``) with a ``pd:10000`` default."""
    raw = os.environ.get("ATTACKER_UPSTREAM", f"pd:{LAB_PORT}")
    host, _, port = raw.partition(":")
    return host, int(port) if port else LAB_PORT


def connect_upstream(
    host: str,
    port: int,
    *,
    retries: int = 30,
    backoff: float = 1.0,
) -> socket.socket:
    """Connect to the upstream PD, retrying the compose start-order race."""
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


def pump(src: socket.socket, dst: socket.socket, sink: Sink) -> None:
    """Relay bytes from ``src`` to ``dst`` unchanged, feeding each chunk to ``sink``.

    Pass-through only: the exact bytes read from ``src`` are forwarded to ``dst``.
    No rewriting, dropping, or injection happens here (prohibition for Phase 2).
    """
    while True:
        try:
            data = src.recv(BUFFER_SIZE)
        except OSError:
            break
        if not data:
            break
        sink(data)  # capture before forwarding; Phase 4 attaches rewrite/inject to this seam
        try:
            dst.sendall(data)
        except OSError:
            break


def bridge(cp_sock: socket.socket, host: str, port: int, sink: Sink) -> None:
    """Connect upstream to the PD and pump both directions between CP and PD."""
    pd_sock = connect_upstream(host, port)
    print(f"interlock-lab: attacker bridged cp<->pd via {host}:{port}", flush=True)
    upstream_thread = threading.Thread(
        target=pump, args=(cp_sock, pd_sock, sink), daemon=True
    )
    upstream_thread.start()
    pump(pd_sock, cp_sock, sink)
    cp_sock.close()
    pd_sock.close()


def main() -> None:
    """Listen for the CP, bridge it to the upstream PD, and capture the exchange."""
    host, port = _upstream()
    capture = Capture(CAPTURE_PATH)
    print(
        f"interlock-lab: attacker inline listening on {LISTEN_HOST}:{LAB_PORT} "
        f"upstream={host}:{port}",
        flush=True,
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LISTEN_HOST, LAB_PORT))
    listener.listen(1)

    while True:
        cp_sock, _addr = listener.accept()
        print("interlock-lab: attacker accepted cp connection", flush=True)
        bridge(cp_sock, host, port, capture.sink)


if __name__ == "__main__":
    main()
