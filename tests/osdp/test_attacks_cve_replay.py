"""Host proof of ATK-05b CVE-2024-52288 Secure Channel replay (no Docker).

Covers the pure ``run_cve_replay`` verdict, mirroring ``test_attacks_replay``'s coverage of
``run_replay``:

- the recorded secure pd->cp frames (the handshake ``REPLY_RMAC_I`` desync primitive, then the
  secure card-read reply) are injected byte-for-byte, in order - never hand-built or mutated;
- a ``HIGH`` Finding is emitted only on an observed locked->unlocked transition;
- an empty recording performs no injection and returns ``[]`` (the flagged true negative);
- an already-unlocked baseline is inconclusive and never claimed as a success;
- an injection with no observed effect (the fixed v3.0.8 CP rejecting the out-of-state RMAC_I)
  returns ``[]`` - the matched-pair failure.
"""

from __future__ import annotations

from interlock.osdp import codec, constants
from interlock.osdp.attacks.replay import run_cve_replay
from interlock.osdp.codec import OsdpFrame

_PD_ADDRESS = 101


def _rmac_i_frame() -> bytes:
    """Return an encoded pd->cp REPLY_RMAC_I - the CVE-2024-52288 desync primitive to replay."""
    frame = OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=constants.PKT_CONTROL_CRC | constants.PKT_CONTROL_SCB | 0x01,
        scb=bytes([0x02, constants.SCS_14]),
        code=constants.REPLY_RMAC_I,
        data=bytes(16),
        use_crc=True,
    )
    return codec.encode(frame)


def _secure_reply(code: int = constants.REPLY_RAW) -> bytes:
    """Return an encoded pd->cp secure reply (the card-read reply the controller unlocks on)."""
    frame = OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=constants.PKT_CONTROL_CRC | constants.PKT_CONTROL_SCB | 0x01,
        scb=bytes([0x02, constants.SCS_18]),
        code=code,
        data=b"\x00\x01\x02\x03",
        use_crc=True,
    )
    return codec.encode(frame)


def test_run_cve_replay_flags_a_locked_to_unlocked_transition() -> None:
    injected: list[bytes] = []
    state = {"unlocked": False}
    recorded = [_rmac_i_frame(), _secure_reply()]

    def inject(frame_bytes: bytes) -> None:
        injected.append(frame_bytes)
        state["unlocked"] = True

    findings = run_cve_replay(recorded, inject, lambda: state["unlocked"])

    assert injected == list(recorded), (
        "the recorded secure frames must be replayed byte-for-byte, in order (RMAC_I desync first)"
    )
    assert len(findings) == 1
    assert findings[0].id == "ATK-05b-cve-2024-52288-rmac-replay"
    assert findings[0].severity.value == "high"
    assert "CVE-2024-52288" in findings[0].title


def test_run_cve_replay_replays_the_rmac_i_desync_first() -> None:
    """The first replayed frame is the REPLY_RMAC_I (0x78) that rewinds the CP's r_mac."""
    injected: list[bytes] = []
    recorded = [_rmac_i_frame(), _secure_reply()]

    run_cve_replay(recorded, injected.append, lambda: False)

    assert codec.decode(injected[0]).code == constants.REPLY_RMAC_I
    assert injected == list(recorded)


def test_run_cve_replay_empty_recording_performs_no_injection_and_returns_empty() -> None:
    calls: list[bytes] = []
    findings = run_cve_replay([], calls.append, lambda: False)
    assert findings == []
    assert calls == [], "an empty recording must never call inject"


def test_run_cve_replay_is_inconclusive_when_baseline_already_unlocked() -> None:
    calls: list[bytes] = []
    findings = run_cve_replay([_rmac_i_frame()], calls.append, lambda: True)
    assert findings == []
    assert calls == [], "inject must never run when the baseline is already unlocked"


def test_run_cve_replay_returns_empty_when_injection_has_no_effect() -> None:
    """The fixed v3.0.8 CP: the out-of-state RMAC_I is rejected, so the probe never transitions."""
    findings = run_cve_replay([_rmac_i_frame()], lambda frame: None, lambda: False)
    assert findings == []
