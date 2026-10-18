"""Host proof of ATK-06 weak-key / SCBK-D testing over the committed handshakes (D-05).

Loads the sc-scbkd and downgrade per-direction fixtures (captured by 03-02), frames and
decodes them into (Direction, OsdpFrame) sequences, and asserts the weak-key sweep verdict
read purely from the wire:

- sc-scbkd  -> SCBK-D flagged (the handshake recomputes under the spec default)
- downgrade -> no weak key (an explicit non-default key 0x10..0x1F is in use)

Plus the flagged-assumption negative (an incomplete handshake yields no Finding) and the
SAFE-03 dictionary-content guard (DOWNGRADE_SCBK is never reachable from WEAK_KEYS). The
tests are host-only (no lab marker, no Docker) and deterministic on the committed fixtures.
"""

from __future__ import annotations

from pathlib import Path

from interlock.osdp import codec, framer
from interlock.osdp.attacks import weak_key
from interlock.osdp.attacks.weak_key import WEAK_KEYS, run_weak_key, which_weak_key
from interlock.osdp.constants import SCBK_D
from interlock.osdp.secure_channel import ccrypt_reply, challenge_random
from interlock.osdp.transport import Direction

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# The lab-arbitrary non-default key the downgrade profile uses (lab/osdp/scenarios.py):
# 0x10..0x1F. It is NEVER a shipped weak-key candidate (SAFE-03 / T-4-03).
_DOWNGRADE_SCBK = bytes(range(0x10, 0x20))


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


def _handshake_pairs(
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


def test_which_weak_key_flags_scbk_d_on_the_sc_scbkd_handshake() -> None:
    """At least one sc-scbkd handshake pair verifies under SCBK-D via which_weak_key."""
    challenge_randoms, replies = _handshake_pairs(_load_session("sc-scbkd"))
    assert challenge_randoms and replies, "sc-scbkd must carry a plaintext handshake"
    assert any(
        which_weak_key(rnd_a, rnd_b, cryptogram) == "SCBK-D"
        for rnd_a in challenge_randoms
        for rnd_b, cryptogram in replies
    )


def test_which_weak_key_returns_none_on_the_downgrade_handshake() -> None:
    """No downgrade handshake pair verifies under any shipped weak key."""
    challenge_randoms, replies = _handshake_pairs(_load_session("downgrade"))
    assert challenge_randoms and replies, "downgrade must carry a plaintext handshake"
    assert all(
        which_weak_key(rnd_a, rnd_b, cryptogram) is None
        for rnd_a in challenge_randoms
        for rnd_b, cryptogram in replies
    )


def test_run_weak_key_reports_scbk_d_on_sc_scbkd() -> None:
    """run_weak_key emits exactly one HIGH SCBK-D Finding for the sc-scbkd session."""
    findings = run_weak_key(_load_session("sc-scbkd"))
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding.id == "ATK-06-weak-key"
    assert finding.severity.value == "high"
    assert "SCBK-D" in finding.title
    assert SCBK_D.hex() in finding.evidence


def test_run_weak_key_reports_no_weak_key_on_downgrade() -> None:
    """The downgrade capture must NOT flag a weak key (explicit non-default key in use)."""
    assert run_weak_key(_load_session("downgrade")) == [], (
        "downgrade should not flag a weak key"
    )


def test_run_weak_key_returns_empty_on_an_incomplete_handshake() -> None:
    """An empty capture and a CHLNG-only capture (no CCRYPT) both yield no Finding."""
    assert run_weak_key([]) == []
    session = _load_session("sc-scbkd")
    only_chlng = [
        (direction, frame)
        for direction, frame in session
        if challenge_random(direction, frame) is not None
    ]
    assert only_chlng, "sc-scbkd must carry at least one CHLNG frame"
    assert run_weak_key(only_chlng) == []


def test_weak_keys_dictionary_ships_only_the_spec_default_scbk_d() -> None:
    """WEAK_KEYS is exactly {SCBK-D}; DOWNGRADE_SCBK is never reachable from it (SAFE-03)."""
    assert WEAK_KEYS == {"SCBK-D": SCBK_D}
    assert _DOWNGRADE_SCBK not in WEAK_KEYS.values()
    assert all(key == SCBK_D for key in WEAK_KEYS.values())


def test_recompute_cryptogram_uses_the_secure_channel_aes() -> None:
    """recompute_cryptogram matches secure_channel.uses_scbk_d on a verifying pair."""
    from interlock.osdp.secure_channel import uses_scbk_d

    challenge_randoms, replies = _handshake_pairs(_load_session("sc-scbkd"))
    verified = False
    for rnd_a in challenge_randoms:
        for rnd_b, cryptogram in replies:
            if uses_scbk_d(rnd_a, rnd_b, cryptogram):
                assert weak_key.recompute_cryptogram(SCBK_D, rnd_a, rnd_b) == cryptogram
                verified = True
    assert verified, "expected at least one sc-scbkd pair to verify under SCBK-D"
