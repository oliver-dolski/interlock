"""Host proof of Secure Channel detection over the captured vectors (OSDP-03, SC4).

For each of the three TCP-tappable profiles this loads the two per-direction vectors
committed by 03-02, frames and decodes them into (Direction, OsdpFrame) sequences, and
asserts the detect_state verdict read purely from the wire:

- cleartext  -> clear-text (no SCB across the session, SCBK-D not confirmed)
- sc-scbkd   -> Secure Channel with SCBK-D confirmed (the handshake recomputes)
- downgrade  -> Secure Channel with SCBK-D NOT confirmed (explicit non-default key)

These three verdicts are the proof of OSDP-03 Success Criterion 4. The tests are
host-only (no lab marker, no Docker) and deterministic on the committed fixtures.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from interlock.osdp import codec, framer
from interlock.osdp.secure_channel import (
    aes_ecb,
    ccrypt_reply,
    challenge_random,
    detect_state,
    uses_scbk_d,
)
from interlock.osdp.transport import Direction

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_session(profile: str) -> list[tuple[Direction, codec.OsdpFrame]]:
    """Frame and decode both per-direction vectors of ``profile`` into tagged pairs."""
    session: list[tuple[Direction, codec.OsdpFrame]] = []
    for direction, suffix in (
        (Direction.cp_to_pd, "cp2pd"),
        (Direction.pd_to_cp, "pd2cp"),
    ):
        raw = (FIXTURES_DIR / f"{profile}_{suffix}.cap").read_bytes()
        assert raw, f"{profile}_{suffix}.cap is empty; regenerate it from the lab"
        session.extend((direction, codec.decode(frame)) for frame in framer.iter_frames(raw))
    return session


def _handshakes(
    session: list[tuple[Direction, codec.OsdpFrame]],
) -> tuple[list[bytes], list[tuple[bytes, bytes]]]:
    """Return (RND.A values from CHLNG, (RND.B, cryptogram) pairs from CCRYPT)."""
    challenge_randoms = [
        rnd_a
        for direction, frame in session
        if (rnd_a := challenge_random(direction, frame)) is not None
    ]
    replies = [
        reply
        for direction, frame in session
        if (reply := ccrypt_reply(direction, frame)) is not None
    ]
    return challenge_randoms, replies


def test_cleartext_session_reports_clear_text_state() -> None:
    """The cleartext vectors carry no SCB and no SCS code, so the verdict is clear-text."""
    state = detect_state(_load_session("cleartext"))
    assert state.secure is False
    assert state.clear_text is True
    assert state.scb_seen is False
    assert state.scs_codes == frozenset()
    assert state.scbk_d_confirmed is False


def test_sc_scbkd_session_reports_secure_channel_state_with_scbk_d() -> None:
    """The sc-scbkd vectors show Secure Channel and the handshake recomputes under SCBK-D."""
    state = detect_state(_load_session("sc-scbkd"))
    assert state.secure is True
    assert state.scb_seen is True
    assert state.scs_codes, "sc-scbkd must show SCS stage codes"
    assert state.scbk_d_confirmed is True


def test_downgrade_session_reports_secure_channel_state_without_scbk_d() -> None:
    """The downgrade vectors show Secure Channel but no handshake verifies under SCBK-D."""
    state = detect_state(_load_session("downgrade"))
    assert state.secure is True
    assert state.scb_seen is True
    assert state.scs_codes, "downgrade must show SCS stage codes"
    assert state.scbk_d_confirmed is False


def test_uses_scbk_d_true_on_the_sc_scbkd_handshake() -> None:
    """At least one extracted sc-scbkd handshake recomputes the PD cryptogram under SCBK-D."""
    challenge_randoms, replies = _handshakes(_load_session("sc-scbkd"))
    assert challenge_randoms and replies, "sc-scbkd must carry a plaintext handshake"
    assert any(
        uses_scbk_d(rnd_a, rnd_b, cryptogram)
        for rnd_a in challenge_randoms
        for rnd_b, cryptogram in replies
    )


def test_uses_scbk_d_false_on_the_downgrade_handshake() -> None:
    """No downgrade handshake verifies under SCBK-D (an explicit non-default key is used)."""
    challenge_randoms, replies = _handshakes(_load_session("downgrade"))
    assert challenge_randoms and replies, "downgrade must carry a plaintext handshake"
    assert not any(
        uses_scbk_d(rnd_a, rnd_b, cryptogram)
        for rnd_a in challenge_randoms
        for rnd_b, cryptogram in replies
    )


def test_aes_ecb_returns_one_block() -> None:
    """The AES wrapper returns a single 16-byte block for a 16-byte input."""
    from interlock.osdp.constants import SCBK_D

    assert len(aes_ecb(SCBK_D, b"\x00" * 16)) == 16


@pytest.mark.parametrize("profile", ["cleartext", "sc-scbkd", "downgrade"])
def test_detector_reads_only_decoded_frames(profile: str) -> None:
    """detect_state consumes only decoded wire frames, no lab or log input."""
    state = detect_state(_load_session(profile))
    # A clear-text session is exactly the one with no Secure Channel markers.
    assert state.clear_text == (not state.secure)
