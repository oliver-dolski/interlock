"""Inline fifo tap for the cve-replay lab's attacker position (ATK-05b Wave-0 spike).

Runs as the ``attacker`` container's entrypoint under the ``docker-compose.vuln.yml``
fifo-tap override, re-homing the attacker from the Phase 2 inline TCP proxy
(``proxy.py``, LAB-03) - idle on this profile since the vuln CP never dials it over
TCP - onto the cve-replay fifo bus the vulnerable libosdp v2.4.0 PD and CP already
share directly.

The vuln PD is the fifo server: per libosdp's own channel implementation
(``utils/src/channel.c``, ``channel_fifo_setup``), it creates two named pipes on the
shared ``osdp_bus`` volume - ``<BUS_DEVICE>-0`` (the CP writes, the PD reads: cp->pd)
and ``<BUS_DEVICE>-1`` (the PD writes, the CP reads: pd->cp) - and both sides open
each with ``O_RDWR`` so neither ``open()`` call blocks waiting for the other end
(POSIX fifo semantics: a read-only or write-only open blocks until a peer opens the
other direction; ``O_RDWR`` sidesteps that entirely).

A named pipe has no broadcast/sniff mode: whichever process's ``read()`` call
happens to run first consumes a given chunk of bytes, and no other reader sees it
again. Re-pointing either the real PD or CP through a true two-leg bridge the way
the TCP inline proxy does (listen/connect/bridge) would require changing
``cp_driver.py``'s hardcoded ``BUS_DEVICE``, which is out of this task's file scope
(``cp_driver.py`` is not among Task 1's files). This tap therefore opens the SAME two
pipes the real PD and CP already use and polls them at a deliberately low cadence -
well below the PD/CP's own 20ms refresh loop (``REFRESH_INTERVAL_SECONDS`` in both
``lab/vuln/pd_driver.py`` and ``lab/vuln/cp_driver.py``) - so it observes, and
necessarily consumes a small share of, live bus traffic without dominating the real
exchange's own much tighter polling loop. This is the wave-0 spike's accepted
tradeoff: it proves the attacker holds an inline tap/inject position on the fifo bus
(Task 1's bar - a non-empty capture), while a reliable, non-lossy injection mechanism
for the actual CVE-2024-52288 replay is Task 2's job.

No ports are published and no host mount is added (SAFE-01 unchanged); captures are
appended to fixed paths inside the attacker container only, read out via
``docker compose exec`` exactly like the TCP proxy's capture file (threat T-2-05 /
report.py T-01-02 pattern: paths used exactly as given, no shell expansion).
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

# Must match the PD's fifo device on the shared volume (lab/vuln/pd_driver.py,
# lab/vuln/cp_driver.py BUS_DEVICE).
BUS_DEVICE = "/busvol/osdp_bus"
FIFO_CP2PD = f"{BUS_DEVICE}-0"
FIFO_PD2CP = f"{BUS_DEVICE}-1"

BUFFER_SIZE = 4096
OPEN_RETRIES = 30
OPEN_BACKOFF_SECONDS = 1.0

# Deliberately slower than the PD/CP's own 20ms refresh loop so the tap is a
# low-frequency observer rather than a competing hot-loop reader (see module
# docstring's tradeoff note).
POLL_INTERVAL_SECONDS = 0.5

CAPTURE_DIR = Path("/app/capture")
CAPTURE_CP2PD = CAPTURE_DIR / "cp2pd.cap"
CAPTURE_PD2CP = CAPTURE_DIR / "pd2cp.cap"

Sink = Callable[[bytes], None]


class Capture:
    """Thread-safe byte sink that appends observed traffic to a fixed file.

    Mirrors ``lab/attacker/proxy.py``'s ``Capture``: one lock per file, the path is
    used exactly as given (no shell expansion), and the file is truncated at startup
    so a run's capture reflects only that run.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(b"")

    def sink(self, data: bytes) -> None:
        """Append ``data`` to the capture file under the shared lock."""
        with self._lock, self.path.open("ab") as handle:
            handle.write(data)


def _open_fifo(
    path: str,
    *,
    retries: int = OPEN_RETRIES,
    backoff: float = OPEN_BACKOFF_SECONDS,
) -> int:
    """Open ``path`` O_RDWR non-blocking, retrying until the PD (fifo server) creates it.

    ``O_RDWR`` avoids the open()-blocks-until-peer POSIX fifo semantics (mirrors
    libosdp's own ``channel_fifo_setup``); ``O_NONBLOCK`` makes every read/write on the
    returned fd non-blocking too, so the poll loop below never hangs.
    """
    last_error: OSError | None = None
    for _attempt in range(retries):
        try:
            return os.open(path, os.O_RDWR | os.O_NONBLOCK)
        except OSError as exc:
            last_error = exc
            time.sleep(backoff)
    raise ConnectionError(
        f"could not open fifo {path} after {retries} attempts"
    ) from last_error


def tap(fd: int, sink: Sink, *, label: str) -> None:
    """Poll ``fd`` at a low cadence, draining and capturing whatever is available.

    Read-only: nothing is written back onto the fifo. A FIFO has no broadcast mode
    (see module docstring), so this necessarily consumes its share of live traffic
    rather than echoing it onward; the low poll cadence keeps that share small
    relative to the real PD/CP's own tight refresh loop.
    """
    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        try:
            while True:
                try:
                    data = os.read(fd, BUFFER_SIZE)
                except BlockingIOError:
                    break
                if not data:
                    break
                sink(data)
        except OSError:
            print(f"interlock-lab: fifo tap {label} closed", flush=True)
            break


def main() -> None:
    """Attach to both cve-replay bus directions and capture traffic from each."""
    print("interlock-lab: fifo tap attaching to cve-replay bus", flush=True)

    cp2pd_fd = _open_fifo(FIFO_CP2PD)
    print(f"interlock-lab: fifo tap opened {FIFO_CP2PD}", flush=True)
    pd2cp_fd = _open_fifo(FIFO_PD2CP)
    print(f"interlock-lab: fifo tap opened {FIFO_PD2CP}", flush=True)

    cp2pd_capture = Capture(CAPTURE_CP2PD)
    pd2cp_capture = Capture(CAPTURE_PD2CP)

    pd2cp_thread = threading.Thread(
        target=tap,
        args=(pd2cp_fd, pd2cp_capture.sink),
        kwargs={"label": "pd2cp"},
        daemon=True,
    )
    pd2cp_thread.start()
    print("interlock-lab: fifo tap attached", flush=True)
    tap(cp2pd_fd, cp2pd_capture.sink, label="cp2pd")


if __name__ == "__main__":
    main()
