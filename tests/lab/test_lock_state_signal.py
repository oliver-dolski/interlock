"""Wave-0 spike (D-05, A1): the single lab PD lock-state signal on CMD_OUT.

Confirms the lab's high-level ``osdp.PeripheralDevice`` command-callback surfaces an output
command (CMD_OUT) so ``lab/osdp/pd_driver.py`` can emit exactly one sentinel log line when it
processes one - the oracle the door-open attacks (ATK-05a replay, ATK-08 spoof) prove
themselves against (D-05).

Brings the cleartext lab up under ``docker-compose.lockstate.yml`` (a throwaway inline
Control Panel, in place of the production ``cp_driver.py``, that drives exactly one output
command once the PD is online), asserts the sentinel is absent before that command is driven,
then asserts it appears once the command is processed. No published port is added; this is the
one lab-internal spike Phase 4 performs (Pitfall 2 - nothing beyond the single signal).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from conftest import ComposeUp

# The single D-05 lock-state sentinel (lab/osdp/pd_driver.py) every door-open attack
# (ATK-05a, ATK-08) proves itself against.
_SENTINEL = "interlock-lab: LOCK state=UNLOCKED"


@pytest.mark.lab
def test_lock_state_signal_absent_then_present_on_cmd_out(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext", overrides=("docker-compose.lockstate.yml",))

    # Precondition: the spike CP must reach PD online before it drives the output command.
    assert lab.wait_for_log("cp", "interlock-lab: PD 101 online", timeout=180), (
        "spike CP never reached PD online"
    )

    # Baseline: no output command has been driven yet, so the sentinel must be absent.
    assert _SENTINEL not in lab.logs("pd"), (
        "lock-state sentinel present before any output command was driven"
    )

    # Driven: the spike CP sends exactly one CMD_OUT once online; the sentinel must appear.
    assert lab.wait_for_log("pd", _SENTINEL, timeout=60), (
        "lock-state sentinel never appeared after the output command was processed"
    )
