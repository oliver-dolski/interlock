"""Host proof of ATK-05a clear-text card-presentation replay (no Docker).

Covers both halves:

- ``capture_card_exchange`` selects only the pd->cp ``REPLY_RAW`` (card-read) frames from a
  decoded session, re-encoded to their exact wire bytes; a session with none, or no frames at
  all, returns ``[]``.
- ``run_replay`` re-injects the captured bytes, in order, unmodified, and emits a Finding only
  on an observed locked->unlocked transition; an empty capture performs no injection and
  returns ``[]`` immediately (the flagged-assumption true negative), and an already-unlocked
  baseline is never claimed as a replay success.
"""

from __future__ import annotations

from interlock.osdp import codec, constants
from interlock.osdp.attacks.replay import capture_card_exchange, run_replay
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction

_PD_ADDRESS = 101


def _card_event_frame(card_bytes: bytes = bytes([0x55, 0xAA, 0x0F])) -> OsdpFrame:
    """Return a pd->cp REPLY_RAW frame carrying ``card_bytes``, matching the lab's wire layout."""
    bit_count = len(card_bytes) * 8
    header = bytes([1, 1, bit_count & 0xFF, (bit_count >> 8) & 0xFF])
    return OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=constants.PKT_CONTROL_CRC | 0x01,
        scb=b"",
        code=constants.REPLY_RAW,
        data=header + card_bytes,
        use_crc=True,
    )


def _ack_frame() -> OsdpFrame:
    """Return an ordinary pd->cp REPLY_ACK frame (not a card event)."""
    return OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=0x05,
        scb=b"",
        code=constants.REPLY_ACK,
        data=b"",
        use_crc=True,
    )


def _poll_frame() -> OsdpFrame:
    """Return an ordinary cp->pd CMD_POLL frame (wrong direction for a card event)."""
    return OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS,
        control=0x05,
        scb=b"",
        code=constants.CMD_POLL,
        data=b"",
        use_crc=True,
    )


# --------------------------------------------------------------------------------------
# capture_card_exchange
# --------------------------------------------------------------------------------------


def test_capture_card_exchange_selects_only_reply_raw_pd_to_cp() -> None:
    card = _card_event_frame()
    session = [
        (Direction.cp_to_pd, _poll_frame()),
        (Direction.pd_to_cp, _ack_frame()),
        (Direction.pd_to_cp, card),
    ]
    captured = capture_card_exchange(session)
    assert len(captured) == 1
    assert codec.decode(captured[0]).code == constants.REPLY_RAW
    assert captured[0] == codec.encode(card)


def test_capture_card_exchange_ignores_reply_raw_in_wrong_direction() -> None:
    """A REPLY_RAW code seen cp->pd (never legitimate) is not selected."""
    bogus = OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS,
        control=0x05,
        scb=b"",
        code=constants.REPLY_RAW,
        data=b"\x00",
        use_crc=True,
    )
    assert capture_card_exchange([(Direction.cp_to_pd, bogus)]) == []


def test_capture_card_exchange_empty_session_returns_empty_list() -> None:
    assert capture_card_exchange([]) == []


def test_capture_card_exchange_no_card_event_returns_empty_list() -> None:
    session = [(Direction.cp_to_pd, _poll_frame()), (Direction.pd_to_cp, _ack_frame())]
    assert capture_card_exchange(session) == []


def test_capture_card_exchange_selects_every_card_event_in_order() -> None:
    first = _card_event_frame(bytes([0x01, 0x02, 0x03]))
    second = _card_event_frame(bytes([0x04, 0x05, 0x06]))
    session = [(Direction.pd_to_cp, first), (Direction.pd_to_cp, second)]
    captured = capture_card_exchange(session)
    assert captured == [codec.encode(first), codec.encode(second)]


# --------------------------------------------------------------------------------------
# run_replay
# --------------------------------------------------------------------------------------


def test_run_replay_flags_a_locked_to_unlocked_transition() -> None:
    injected: list[bytes] = []
    state = {"unlocked": False}
    captured = [b"frame-one", b"frame-two"]

    def inject(frame_bytes: bytes) -> None:
        injected.append(frame_bytes)
        state["unlocked"] = True

    findings = run_replay(captured, inject, lambda: state["unlocked"])
    assert injected == captured, "every captured frame must be injected, in order, unmodified"
    assert len(findings) == 1
    assert findings[0].id == "ATK-05a-replay-card-exchange"
    assert findings[0].severity.value == "critical"


def test_run_replay_empty_capture_performs_no_injection_and_returns_empty() -> None:
    calls: list[bytes] = []
    findings = run_replay([], lambda frame: calls.append(frame), lambda: False)
    assert findings == []
    assert calls == [], "an empty capture must never call inject"


def test_run_replay_is_inconclusive_when_baseline_already_unlocked() -> None:
    calls: list[bytes] = []
    findings = run_replay([b"frame"], lambda frame: calls.append(frame), lambda: True)
    assert findings == []
    assert calls == [], "inject must never run when the baseline is already unlocked"


def test_run_replay_returns_empty_when_injection_has_no_effect() -> None:
    findings = run_replay([b"frame"], lambda frame: None, lambda: False)
    assert findings == []
