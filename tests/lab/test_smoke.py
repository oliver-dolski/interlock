"""Smoke test: the lab brings PD and CP online over TCP with no hardware (LAB-01)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from conftest import ComposeUp


@pytest.mark.lab
def test_cp_sees_pd_online(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext")
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180)
    assert lab.wait_for_log("cp", "interlock-lab: event received", timeout=60)
