"""ATK-05b (CVE-2024-52288 replay) @lab proofs.

Task 1 (wave-0 spike): brings the cve-replay profile up under
``docker-compose.vuln.yml``, which now re-homes the attacker from the idle Phase 2
TCP proxy onto the shared-volume fifo bus via ``lab/attacker/fifo_tap.py``. Gates on
the vuln PD actually coming online (Pitfall 4: a bus-down false pass is not a valid
result), then asserts the fifo tap captured a non-empty slice of live bus traffic -
proving the attacker holds an inline tap/inject position on the bus before the
CVE replay injection logic (Task 2) is built.

Task 2's matched-pair test (CVE replay succeeds on vuln, fails on fixed) is not yet
present; this file currently holds only the Task 1 spike.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

VULN_OVERRIDE = "docker-compose.vuln.yml"

# Read an in-container capture as base64 so binary survives the text pipe; prints an
# empty string if the file does not exist yet rather than raising (mirrors
# tests/lab/test_osdp_tap.py's _READ_CAPTURE idiom).
_READ_CAPTURE = (
    "import base64, os, sys\n"
    "p = sys.argv[1]\n"
    "data = open(p, 'rb').read() if os.path.exists(p) else b''\n"
    "sys.stdout.write(base64.b64encode(data).decode())\n"
)


def _read_capture(lab: ComposeHandle, path: str) -> bytes:
    """Return the bytes of an attacker capture file, read via docker compose exec."""
    result = lab.compose("exec", "-T", "attacker", "python", "-c", _READ_CAPTURE, path)
    assert result.returncode == 0, f"reading {path} failed: {result.stdout}{result.stderr}"
    return base64.b64decode(result.stdout.strip())


@pytest.mark.lab
def test_fifo_tap_observes_cve_replay_bus_traffic(compose_up: ComposeUp) -> None:
    """The re-homed attacker's fifo tap captures non-empty traffic on the cve-replay bus."""
    lab = compose_up("cve-replay", overrides=(VULN_OVERRIDE,))

    # Precondition (Pitfall 4): gate on the vuln PD actually coming online before judging
    # the tap, so a bus-down false pass is distinguished from a genuine empty capture.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "cve-replay: vuln PD never came online under the fifo-tap override"
    )

    cp2pd = _read_capture(lab, "/app/capture/cp2pd.cap")
    pd2cp = _read_capture(lab, "/app/capture/pd2cp.cap")
    assert cp2pd or pd2cp, (
        "cve-replay: fifo tap observed no traffic in either direction "
        "(expected at least one non-empty capture)"
    )
