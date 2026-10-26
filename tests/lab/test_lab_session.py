"""Live @lab proof that the assessment's lab driver drives the real lab (ASSESS-01).

Builds a real ``LabSession`` on the repo root, clears any leftover of an interrupted run, brings
the cleartext profile up under the docker-compose.tap.yml override (interlock's own read-only
TCPTap in the attacker position), gates on PD-online and the card-read event sentinel so the
full exchange has transited the tap, reads both per-direction captures out of the attacker
container through ``LabHandle.read_capture`` and decodes them with the sniff collector. After
the ``with`` block it asserts that no container of the project is left behind.

Uses its own compose project, interlock-assess, so it never collides with the interlock-lab
project the rest of this suite uses. Adds no published port: the capture is read via
``docker compose exec`` exactly as test_attacks_sniff.py does, so SAFE-01 containment is
unchanged.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from interlock.osdp import tap_capture
from interlock.osdp.attacks.sniff import decode_chunks
from interlock.osdp.lab_session import DEFAULT_PROJECT, LabSession
from interlock.osdp.transport import Direction

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.lab
def test_lab_session_drives_reads_and_tears_down_the_real_lab() -> None:
    session = LabSession(REPO_ROOT)
    session.reset()

    with session.scenario("cleartext", ("docker-compose.tap.yml",)) as lab:
        # Precondition: PD online and the card-read event under the tap override, so the
        # full exchange transited the tap before the captures are read.
        assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
            "PD never came online under the tap override"
        )
        assert lab.wait_for_log("cp", "interlock-lab: event received", timeout=90), (
            "card-read event never observed under the tap override"
        )
        cp2pd = lab.read_capture(tap_capture.CP2PD_PATH.as_posix())
        pd2cp = lab.read_capture(tap_capture.PD2CP_PATH.as_posix())

    assert cp2pd, "cp->pd capture is empty"
    assert pd2cp, "pd->cp capture is empty"
    frames = decode_chunks([(Direction.cp_to_pd, cp2pd), (Direction.pd_to_cp, pd2cp)])
    assert frames, "the live captures decoded to no OSDP frame"

    left = subprocess.run(
        [
            "docker", "ps", "-a", "-q",
            "--filter", f"label=com.docker.compose.project={DEFAULT_PROJECT}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert left.stdout.strip() == "", f"containers left behind: {left.stdout!r}"
