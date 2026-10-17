"""Attacker tap: the inline attacker captures the live cp<->pd session (LAB-03).

With the attacker inline (plan 02-03), every byte of the exchange transits its
container. This test proves the capture is non-empty after a completed exchange,
and - the backstop truth - that traffic is observed from the start of the session
through to teardown, not merely sampled once mid-session: the capture is already
non-empty when the PD first comes online (the handshake had to transit the
attacker) and is still non-empty just before teardown.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from conftest import ComposeHandle, ComposeUp

# Read the attacker's in-container capture size without copying it out of the lab.
# Prints 0 if the file does not exist yet rather than raising.
_READ_CAPTURE_SIZE = (
    "import os\n"
    "p = '/app/capture/session.cap'\n"
    "print(os.path.getsize(p) if os.path.exists(p) else 0)\n"
)


def _capture_size(lab: ComposeHandle) -> int:
    """Return the attacker capture's byte count, read via docker compose exec."""
    result = lab.compose("exec", "-T", "attacker", "python", "-c", _READ_CAPTURE_SIZE)
    output = (result.stdout + result.stderr).strip()
    assert result.returncode == 0, f"reading attacker capture failed: {output!r}"
    last_line = output.splitlines()[-1] if output else ""
    assert last_line.isdigit(), f"unexpected capture-size output: {output!r}"
    return int(last_line)


@pytest.mark.lab
def test_capture_nonempty(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext")

    # The PD coming online means the Secure/clear-text handshake already flowed
    # through the attacker, so the capture must already hold the session's first
    # frames - this is the "early in the session" sample.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180)
    early = _capture_size(lab)
    assert early > 0, "attacker observed no traffic at the start of the session"

    # Let the exchange run through the card-read event, then sample again just
    # before teardown. The capture must still be non-empty and no smaller - the
    # attacker kept observing across the full exchange, not a single moment.
    assert lab.wait_for_log("cp", "interlock-lab: event received", timeout=60)
    before_teardown = _capture_size(lab)
    assert before_teardown > 0, "attacker capture empty before teardown"
    assert before_teardown >= early, "capture shrank; traffic was not observed continuously"
