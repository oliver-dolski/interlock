"""Live-lab proof: interlock's codec round-trips a real frame off the running bus (OSDP-01).

This is the tracer's end-to-end claim against the live cleartext lab: bring the
lab up, read the attacker's in-container capture out via ``docker compose exec``
(no host mount, SAFE-01), frame it with interlock's own framer, and assert the
first trailer-valid frame re-encodes byte-identically. It reuses the ``compose_up``
fixture from this directory's conftest and carries the ``lab`` marker.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from interlock.osdp import framer
from interlock.osdp.codec import decode, encode

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# Read the attacker's in-container capture out as base64 so raw bytes survive the pipe.
_READ_CAPTURE_B64 = (
    "import base64, os\n"
    "p = '/app/capture/session.cap'\n"
    "d = open(p, 'rb').read() if os.path.exists(p) else b''\n"
    "print(base64.b64encode(d).decode())\n"
)


def _read_capture(lab: ComposeHandle) -> bytes:
    """Return the attacker capture's raw bytes, read via docker compose exec."""
    result = lab.compose("exec", "-T", "attacker", "python", "-c", _READ_CAPTURE_B64)
    output = (result.stdout + result.stderr).strip()
    assert result.returncode == 0, f"reading attacker capture failed: {output!r}"
    return base64.b64decode(output.splitlines()[-1])


@pytest.mark.lab
def test_live_frame_round_trips_byte_identically(compose_up: ComposeUp) -> None:
    """A frame captured from the live cleartext lab re-encodes byte-for-byte identically."""
    lab = compose_up("cleartext")
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=240)
    # Let the exchange run past the card-read event so the capture holds full frames.
    lab.wait_for_log("cp", "interlock-lab: event received", timeout=60)

    capture = _read_capture(lab)
    assert capture, "attacker observed no traffic"

    frames = list(framer.iter_frames(capture))
    assert frames, "no trailer-valid OSDP frame found in the live capture"

    first = frames[0]
    assert encode(decode(first)) == first, "live frame did not re-encode byte-identically"
