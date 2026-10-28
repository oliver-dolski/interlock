"""Host proof of ATK-08 CP/PD spoofing (no Docker).

Covers both crafted frames and the before/after verdict:

- ``craft_unlock`` produces a decodable, wire-valid ``CMD_OUT`` with the reply flag cleared.
- ``craft_card_event`` produces a decodable, wire-valid ``REPLY_RAW`` with the reply flag set.
- ``unlock_transform`` rewrites the first cp->pd ``CMD_POLL`` into the unlock, preserving the
  intercepted frame's own sequence number, and passes every other frame through unchanged
  (one-shot: later POLLs are untouched). It reports the injection once, through ``on_inject``,
  only after the relay says the forged frame was written; a failed write is never announced
  and re-arms the injection. ``announce_inject`` prints the line the assessment reads as proof
  of injection, and the announcing lab relays wire every forward back to the transform.
- ``run_spoof`` emits a CRITICAL Finding only on an observed locked->unlocked transition, and
  ``[]`` when the baseline was already unlocked (flagged-assumption guard).
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from interlock.osdp import codec, constants
from interlock.osdp.attacks import spoof
from interlock.osdp.attacks.spoof import craft_card_event, craft_unlock, run_spoof, unlock_transform
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction

_PD_ADDRESS = 101


def _poll(sequence: int) -> bytes:
    """Return an encoded cp->pd CMD_POLL with the given sequence number."""
    control = constants.PKT_CONTROL_CRC | (sequence & constants.PKT_CONTROL_SQN)
    return codec.encode(
        OsdpFrame(
            had_mark=True,
            address=_PD_ADDRESS,
            control=control,
            scb=b"",
            code=constants.CMD_POLL,
            data=b"",
            use_crc=True,
        )
    )


# --------------------------------------------------------------------------------------
# Crafted frames.
# --------------------------------------------------------------------------------------


def test_craft_unlock_is_a_decodable_cmd_out_with_reply_flag_cleared() -> None:
    frame = codec.decode(craft_unlock(_PD_ADDRESS, sequence=2))
    assert frame.code == constants.CMD_OUT
    assert frame.address & constants.ADDR_REPLY_FLAG == 0
    assert frame.address == _PD_ADDRESS
    assert frame.control & constants.PKT_CONTROL_SQN == 2
    assert len(frame.data) == 4, "CMD_OUT data must be output_no+control_code+timer(2)"


def test_craft_unlock_uses_permanent_on_control_code() -> None:
    frame = codec.decode(craft_unlock(_PD_ADDRESS, sequence=1))
    output_no, control_code, timer_lsb, timer_msb = frame.data
    assert output_no == 0
    assert control_code == 0x02, "control_code must be permanent ON (unlock)"
    assert (timer_lsb, timer_msb) == (0, 0)


def test_craft_card_event_is_a_decodable_reply_raw_with_reply_flag_set() -> None:
    card_bytes = bytes([0x55, 0xAA, 0x0F])
    frame = codec.decode(craft_card_event(_PD_ADDRESS, card_bytes, sequence=3))
    assert frame.code == constants.REPLY_RAW
    assert frame.address & constants.ADDR_REPLY_FLAG == constants.ADDR_REPLY_FLAG
    assert frame.address & ~constants.ADDR_REPLY_FLAG == _PD_ADDRESS
    assert frame.control & constants.PKT_CONTROL_SQN == 3
    # reader_no, format, bit_count(LE), then the raw card bytes verbatim.
    assert frame.data == bytes([1, 1, 24, 0]) + card_bytes


def test_craft_card_event_bit_count_matches_card_bytes_length() -> None:
    card_bytes = bytes(range(5))  # 5 bytes = 40 bits
    frame = codec.decode(craft_card_event(_PD_ADDRESS, card_bytes, sequence=1))
    bit_count = frame.data[2] | (frame.data[3] << 8)
    assert bit_count == 40
    assert frame.data[4:] == card_bytes


# --------------------------------------------------------------------------------------
# The in-path transform.
# --------------------------------------------------------------------------------------


def test_unlock_transform_rewrites_first_poll_preserving_sequence() -> None:
    transform = unlock_transform()
    poll = _poll(sequence=2)
    out = transform(Direction.cp_to_pd, poll)
    frame = codec.decode(out)
    assert frame.code == constants.CMD_OUT
    assert frame.address == _PD_ADDRESS
    assert frame.control & constants.PKT_CONTROL_SQN == 2


def test_unlock_transform_is_one_shot_later_polls_pass_through() -> None:
    transform = unlock_transform()
    first = _poll(sequence=2)
    second = _poll(sequence=3)
    transform(Direction.cp_to_pd, first)  # consumes the one-shot injection
    out = transform(Direction.cp_to_pd, second)
    assert out == second, "a poll after the one-shot injection must pass through unchanged"


def test_unlock_transform_never_rewrites_pd_to_cp_direction() -> None:
    transform = unlock_transform()
    ack = codec.encode(
        OsdpFrame(
            had_mark=True,
            address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
            control=0x05,
            scb=b"",
            code=constants.REPLY_ACK,
            data=b"",
            use_crc=True,
        )
    )
    assert transform(Direction.pd_to_cp, ack) == ack


def test_unlock_transform_buffers_a_poll_split_across_two_chunks() -> None:
    transform = unlock_transform()
    poll = _poll(sequence=1)
    split = len(poll) // 2
    first = transform(Direction.cp_to_pd, poll[:split])
    second = transform(Direction.cp_to_pd, poll[split:])
    forwarded = first + second
    frame = codec.decode(forwarded)
    assert frame.code == constants.CMD_OUT


def test_unlock_transform_reports_the_injected_sequence_once() -> None:
    calls: list[int] = []
    transform = unlock_transform(on_inject=calls.append)
    for sequence in (2, 3):
        out = transform(Direction.cp_to_pd, _poll(sequence=sequence))
        transform.forwarded(Direction.cp_to_pd, out, True)
    assert calls == [2], "on_inject must fire once, with the rewritten POLL's sequence"


def test_unlock_transform_announces_only_after_the_forged_frame_is_sent() -> None:
    # The sentinel is the assessment's proof that the forged frame reached the bus (WR-04).
    calls: list[int] = []
    transform = unlock_transform(on_inject=calls.append)
    out = transform(Direction.cp_to_pd, _poll(sequence=2))
    assert calls == [], "building the forged frame is not sending it"
    transform.forwarded(Direction.cp_to_pd, out, True)
    assert calls == [2]


def test_a_failed_send_is_not_announced_and_rearms_the_injection() -> None:
    calls: list[int] = []
    transform = unlock_transform(on_inject=calls.append)
    lost = transform(Direction.cp_to_pd, _poll(sequence=2))
    transform.forwarded(Direction.cp_to_pd, lost, False)
    assert calls == [], "a forged frame that never left must not read as injected"
    retry = transform(Direction.cp_to_pd, _poll(sequence=3))
    frame = codec.decode(retry)
    assert frame.code == constants.CMD_OUT
    assert frame.control & constants.PKT_CONTROL_SQN == 3
    transform.forwarded(Direction.cp_to_pd, retry, True)
    assert calls == [3]


def test_a_forward_in_the_other_direction_does_not_announce() -> None:
    calls: list[int] = []
    transform = unlock_transform(on_inject=calls.append)
    out = transform(Direction.cp_to_pd, _poll(sequence=2))
    transform.forwarded(Direction.pd_to_cp, b"\xff", True)
    assert calls == []
    transform.forwarded(Direction.cp_to_pd, out, True)
    assert calls == [2]


class _RecordingTap:
    """Stands in for ``TCPTap``: records what a lab relay serves instead of listening."""

    served: ClassVar[list[tuple[Any, Any]]] = []

    def __init__(self, port: int, upstream: tuple[str, int]) -> None:
        pass

    def serve_rewrite(self, transform: Any, on_forward: Any = None) -> None:
        self.served.append((transform, on_forward))


@pytest.mark.parametrize("module", ["spoof", "replay"])
def test_the_announcing_lab_relays_report_every_forward_to_the_transform(
    monkeypatch: pytest.MonkeyPatch, module: str
) -> None:
    from interlock.osdp.attacks import replay

    relay = {"spoof": spoof, "replay": replay}[module]
    monkeypatch.delenv("ATTACK_MODE", raising=False)
    monkeypatch.setattr(_RecordingTap, "served", [])
    monkeypatch.setattr(relay, "TCPTap", _RecordingTap)
    relay.main()
    [(transform, on_forward)] = _RecordingTap.served
    assert on_forward == transform.forwarded


def test_unlock_transform_reports_nothing_while_disarmed() -> None:
    calls: list[int] = []
    transform = unlock_transform(armed=lambda: False, on_inject=calls.append)
    poll = _poll(sequence=1)
    assert transform(Direction.cp_to_pd, poll) == poll
    assert calls == []


def test_announce_inject_prints_the_sentinel(capsys: pytest.CaptureFixture[str]) -> None:
    spoof.announce_inject(2)
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith(spoof.INJECT_SENTINEL)
    assert lines[0].endswith("seq=2")


# --------------------------------------------------------------------------------------
# The before/after verdict.
# --------------------------------------------------------------------------------------


def test_run_spoof_flags_a_locked_to_unlocked_transition() -> None:
    calls: list[str] = []
    state = {"unlocked": False}

    def inject() -> None:
        calls.append("inject")
        state["unlocked"] = True

    findings = run_spoof(inject, lambda: state["unlocked"])
    assert calls == ["inject"]
    assert len(findings) == 1
    assert findings[0].id == "ATK-08-spoof-unlock"
    assert findings[0].severity.value == "critical"


def test_run_spoof_is_inconclusive_when_baseline_already_unlocked() -> None:
    calls: list[str] = []

    def inject() -> None:
        calls.append("inject")

    findings = run_spoof(inject, lambda: True)
    assert findings == []
    assert calls == [], "inject must never run when the baseline is already unlocked"


def test_run_spoof_returns_empty_when_inject_has_no_effect() -> None:
    findings = run_spoof(lambda: None, lambda: False)
    assert findings == []
