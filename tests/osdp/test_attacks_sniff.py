"""Host proof of ATK-01 sniff over the committed Phase 3 fixtures (no Docker).

Loads the clear-text per-direction vectors committed by 03-02, frames and decodes
them into ``(Direction, OsdpFrame)`` pairs, and asserts ``run_sniff`` folds them
into the expected PD topology: address 101 with ``CMD_POLL`` (cp->pd) and
``REPLY_ACK`` (pd->cp) among the codes seen, and a clear-text Secure Channel
posture. Also pins the two flagged edges - empty input yields no Finding, and a
garbage byte chunk does not crash the collector. Code values come from
``interlock.osdp.constants`` by name; no bare 0x60/0x40 magic numbers in asserts.
"""

from __future__ import annotations

from pathlib import Path

from interlock.osdp import codec, constants, framer
from interlock.osdp.attacks.sniff import decode_chunks, run_sniff
from interlock.osdp.transport import Direction

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Lab PD address under every profile (lab/osdp/pd_driver.py); masked of the reply flag.
_PD_ADDRESS = 101


def _load_cleartext_session() -> list[tuple[Direction, codec.OsdpFrame]]:
    """Frame and decode both clear-text per-direction vectors into tagged pairs."""
    session: list[tuple[Direction, codec.OsdpFrame]] = []
    for direction, suffix in (
        (Direction.cp_to_pd, "cp2pd"),
        (Direction.pd_to_cp, "pd2cp"),
    ):
        raw = (FIXTURES_DIR / f"cleartext_{suffix}.cap").read_bytes()
        assert raw, f"cleartext_{suffix}.cap is empty; regenerate it from the lab"
        session.extend((direction, codec.decode(frame)) for frame in framer.iter_frames(raw))
    return session


def _pd_finding(findings: list) -> object:
    """Return the single Finding emitted for the lab PD at address 101."""
    expected_id = f"ATK-01-sniff-pd-{_PD_ADDRESS}"
    matches = [f for f in findings if f.id == expected_id]
    assert len(matches) == 1, f"expected exactly one Finding for PD {_PD_ADDRESS}, got {findings}"
    return matches[0]


def test_sniff_topology_lists_pd_101_with_poll_and_ack() -> None:
    """The clear-text fixtures fold into a topology listing PD 101 with POLL and ACK."""
    findings = run_sniff(_load_cleartext_session())
    finding = _pd_finding(findings)

    poll_name = constants.COMMAND_CODES[constants.CMD_POLL]
    ack_name = constants.REPLY_CODES[constants.REPLY_ACK]
    assert poll_name in finding.evidence, finding.evidence
    assert ack_name in finding.evidence, finding.evidence
    assert str(_PD_ADDRESS) in finding.evidence, finding.evidence


def test_sniff_reports_clear_text_posture_on_cleartext_fixtures() -> None:
    """The clear-text fixtures produce a Finding whose SC posture is clear-text."""
    findings = run_sniff(_load_cleartext_session())
    finding = _pd_finding(findings)
    assert "clear-text" in finding.evidence, finding.evidence


def test_empty_frame_sequence_yields_no_finding() -> None:
    """Flagged-assumption negative: an empty capture emits no spurious Finding."""
    assert run_sniff([]) == []


def test_garbage_chunk_does_not_crash_the_collector() -> None:
    """A malformed/garbage byte chunk is skipped by the DecodeError guard, no crash."""
    garbage = b"\x00\xff\x12not an osdp frame\x53\x99\x01"
    decoded = decode_chunks([(Direction.cp_to_pd, garbage)])
    assert decoded == []
    # And the full pipeline over garbage still yields no Finding.
    assert run_sniff(decoded) == []
