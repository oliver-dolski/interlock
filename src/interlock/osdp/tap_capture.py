"""Capture entrypoint: run interlock's read-only TCP tap inline in the lab (OSDP-02).

This runs in the attacker container (via the docker-compose.tap.yml override) in
place of the Phase 2 proxy. It constructs a ``TCPTap`` in the attacker position
(listen where the CP dials, forward to the upstream PD) and, for every observed
chunk, appends the bytes to one of two fixed in-container files, one per direction.
Splitting the directions keeps each capture a clean single-direction vector, so the
address reply bit 0x80 and the shared code byte 0x76 (CHLNG vs CCRYPT) stay
unambiguous (research Pitfall 6).

The tap is strictly read-only pass-through: the exact bytes read are forwarded
unchanged and only a copy is written to disk. There is no host mount and no
published port, so the captures stay in-container and nothing leaves the internal
labnet (SAFE-01). This module is standard-library only; the tap it drives is too.
"""

from __future__ import annotations

import os
from pathlib import Path

from interlock.osdp.transport import Direction, OnBytes, TCPTap

# Listen where the CP dials (the attacker position), same port as the base proxy.
LAB_PORT = 10000

# Fixed in-container capture paths, one per direction. No host mount: captures stay
# inside the attacker container and are read out via docker compose exec (SAFE-01).
CAPTURE_DIR = Path("/app/capture")
CP2PD_PATH = CAPTURE_DIR / "cp2pd.cap"
PD2CP_PATH = CAPTURE_DIR / "pd2cp.cap"


def build_writer(cp2pd_path: Path, pd2cp_path: Path) -> OnBytes:
    """Return an ``on_bytes`` callback that appends each direction to its own file.

    Both files are truncated at startup so a run's captures reflect only that run.
    Each direction is written by exactly one pump thread, so the two append streams
    never interleave and need no lock.
    """
    cp2pd_path.parent.mkdir(parents=True, exist_ok=True)
    cp2pd_path.write_bytes(b"")
    pd2cp_path.write_bytes(b"")
    handles = {
        Direction.cp_to_pd: cp2pd_path.open("ab"),
        Direction.pd_to_cp: pd2cp_path.open("ab"),
    }

    def on_bytes(direction: Direction, data: bytes) -> None:
        handle = handles[direction]
        handle.write(data)
        handle.flush()

    return on_bytes


def _upstream() -> tuple[str, int]:
    """Parse ``ATTACKER_UPSTREAM`` (``host:port``) with a ``pd:10000`` default."""
    raw = os.environ.get("ATTACKER_UPSTREAM", f"pd:{LAB_PORT}")
    host, _, port = raw.partition(":")
    return host, int(port) if port else LAB_PORT


def main() -> None:
    """Run the read-only TCP tap in the attacker position, capturing each direction."""
    upstream = _upstream()
    on_bytes = build_writer(CP2PD_PATH, PD2CP_PATH)
    print(
        f"interlock: tap-capture listening on 0.0.0.0:{LAB_PORT} "
        f"upstream={upstream[0]}:{upstream[1]}",
        flush=True,
    )
    tap = TCPTap(LAB_PORT, upstream, on_bytes)
    tap.serve_forever()


if __name__ == "__main__":
    main()
