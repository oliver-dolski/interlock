"""Host proof of ATK-07 command fuzzing (no Docker).

Proves the determinism contract (D-06) without any live bus:

- ``fuzz_sweep`` calls ``inject`` exactly nine times for ``variants=0`` (one per ``Mutation``
  member, in enum order) and ``9 + variants`` times otherwise.
- a fixed seed reproduces the exact seeded-variant sequence; the nine deterministic members
  always run first, before any seeded draw.
- every injected frame comes from ``mutate.mutate`` over a ``codec.encode`` good frame
  (never hand-built malformed bytes).
- ``run_fuzz`` returns ``[]`` for a PD that stays live (true negative) and emits one Finding,
  carrying the mutation name and seed, for a corruption that knocks the PD out.
- ``fuzz_lab`` holds ONE persistent TCP connection: against a fake PD over real loopback TCP
  that, like lab/osdp/tcp_channel.listen, accepts exactly one connection and closes its
  listener, a healthy PD gives ``[]``; a silent PD or no listener at all raises
  ``FuzzBaselineError`` instead of returning nine "PD dead" findings.
"""

from __future__ import annotations

import socket
import threading

import pytest

from interlock.osdp import codec, constants, framer
from interlock.osdp.attacks.fuzz import (
    FuzzBaselineError,
    craft_poll,
    fuzz_lab,
    fuzz_sweep,
    iter_mutations,
    run_fuzz,
)
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.mutate import Mutation, mutate

_NINE = len(list(Mutation))


class _Counter:
    """A bare ``inject`` seam that records every frame it is handed, in order."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []

    @property
    def call_count(self) -> int:
        return len(self.frames)

    def __call__(self, frame_bytes: bytes) -> None:
        self.frames.append(frame_bytes)


def _good() -> bytes:
    return craft_poll()


# --------------------------------------------------------------------------------------
# Deterministic sweep count and order.
# --------------------------------------------------------------------------------------


def test_sweep_injects_exactly_nine_for_no_variants() -> None:
    """The deterministic sweep is exactly the nine Mutation members when variants=0."""
    inject = _Counter()
    fuzz_sweep(_good(), inject, variants=0)
    assert inject.call_count == 9


def test_sweep_injects_nine_plus_variants() -> None:
    """With variants>0 the sweep is the nine members plus that many seeded draws."""
    inject = _Counter()
    fuzz_sweep(_good(), inject, seed=7, variants=5)
    assert inject.call_count == _NINE + 5


def test_first_nine_are_the_mutation_members_in_enum_order() -> None:
    """The nine deterministic frames are mutate(good, how) for each member, in order."""
    good = _good()
    inject = _Counter()
    fuzz_sweep(good, inject, variants=0)
    expected = [mutate(good, how) for how in Mutation]
    assert inject.frames == expected


def test_seeded_variant_sequence_is_reproducible_under_a_fixed_seed() -> None:
    """Two runs with the same seed inject the identical seeded-variant sequence."""
    good = _good()
    a, b = _Counter(), _Counter()
    fuzz_sweep(good, a, seed=1234, variants=8)
    fuzz_sweep(good, b, seed=1234, variants=8)
    assert a.frames == b.frames, "seeded variant sequence not reproducible under a fixed seed"


def test_a_different_seed_changes_the_variant_sequence() -> None:
    """Different seeds produce a different seeded-variant tail (the nine prefix is unchanged)."""
    good = _good()
    a, b = _Counter(), _Counter()
    fuzz_sweep(good, a, seed=1, variants=20)
    fuzz_sweep(good, b, seed=2, variants=20)
    assert a.frames[:_NINE] == b.frames[:_NINE]  # deterministic nine identical
    assert a.frames[_NINE:] != b.frames[_NINE:]  # seeded tails diverge


def test_every_injected_frame_is_a_mutation_of_the_good_frame() -> None:
    """No injected frame equals the good frame or is hand-built: each is a named corruption."""
    good = _good()
    corpus = {mutate(good, how) for how in Mutation}
    inject = _Counter()
    fuzz_sweep(good, inject, seed=3, variants=6)
    for frame_bytes in inject.frames:
        assert frame_bytes != good
        assert frame_bytes in corpus


# --------------------------------------------------------------------------------------
# run_fuzz liveness classification.
# --------------------------------------------------------------------------------------


def test_run_fuzz_clean_run_yields_no_finding() -> None:
    """A PD that stays live through every injection is the true negative: no Finding."""
    findings = run_fuzz(_good(), lambda _frame: True, variants=4)
    assert findings == []


def test_run_fuzz_reports_a_failing_mutation_with_its_name() -> None:
    """A corruption that knocks the PD out yields one Finding naming that mutation."""
    good = _good()
    killer = mutate(good, Mutation.oversized)

    def probe(frame_bytes: bytes) -> bool:
        return frame_bytes != killer  # the oversized frame kills the PD; all else is survived

    findings = run_fuzz(good, probe, variants=0)
    assert len(findings) == 1, findings
    assert findings[0].id == f"ATK-07-fuzz-{Mutation.oversized.value}"
    assert Mutation.oversized.value in findings[0].evidence


def test_run_fuzz_finding_carries_the_seed_for_reproducibility() -> None:
    """A seeded-variant failure records the fixed seed in its evidence."""

    def probe(_frame: bytes) -> bool:
        return False  # every injection fails, so seeded variants are reported too

    findings = run_fuzz(_good(), probe, seed=99, variants=2)
    assert len(findings) == _NINE + 2
    assert any("seed=99" in f.evidence for f in findings)
    assert any("#seed99" in f.id for f in findings)


# --------------------------------------------------------------------------------------
# The good-frame seed and the iterator order.
# --------------------------------------------------------------------------------------


def test_craft_poll_builds_a_valid_decodable_cmd_poll() -> None:
    """The good seed is a valid cp->pd CMD_POLL (reply flag clear), built via codec.encode."""
    frame = codec.decode(craft_poll(101))
    assert frame.code == constants.CMD_POLL
    assert not frame.address & constants.ADDR_REPLY_FLAG
    assert frame.address == 101


def test_iter_mutations_labels_the_nine_then_the_variants() -> None:
    """iter_mutations labels the nine members by name, then variants as <name>#seed<seed>."""
    labels = [label for label, _ in iter_mutations(_good(), seed=5, variants=3)]
    assert labels[:_NINE] == [how.value for how in Mutation]
    assert all(tail.endswith("#seed5") for tail in labels[_NINE:])
    assert len(labels) == _NINE + 3


def test_craft_poll_default_bytes_are_unchanged() -> None:
    """The default good seed is still control 0x05 (CRC + sequence 1): the corpus is stable."""
    frame = codec.decode(craft_poll())
    assert frame.control == 0x05
    assert craft_poll() == craft_poll(sequence=1)


def test_craft_poll_sequence_zero_is_the_restart_poll() -> None:
    """craft_poll(sequence=0) decodes as a CMD_POLL with sequence 0; out-of-range is rejected."""
    frame = codec.decode(craft_poll(sequence=0))
    assert frame.code == constants.CMD_POLL
    assert frame.control & constants.PKT_CONTROL_SQN == 0
    assert frame.control & constants.PKT_CONTROL_CRC
    with pytest.raises(ValueError):
        craft_poll(sequence=4)


# --------------------------------------------------------------------------------------
# fuzz_lab over real TCP against a one-accept fake PD (the lab listen() shape).
# --------------------------------------------------------------------------------------

_PD_ADDRESS = 101
_SOCKET_TIMEOUT = 10.0


def _ack(request: OsdpFrame) -> bytes:
    """Build the REPLY_ACK a PD sends to ``request``: reply flag set, same sequence, CRC."""
    return codec.encode(
        OsdpFrame(
            had_mark=request.had_mark,
            address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
            control=constants.PKT_CONTROL_CRC | (request.control & constants.PKT_CONTROL_SQN),
            scb=b"",
            code=constants.REPLY_ACK,
            data=b"",
            use_crc=True,
        )
    )


class _OneAcceptPd:
    """A fake PD on 127.0.0.1 that accepts exactly ONE connection, like tcp_channel.listen.

    It frames the incoming stream with ``framer.iter_frames`` and ``codec.decode`` and answers
    every decodable CMD_POLL addressed to 101 with a REPLY_ACK; everything else is ignored.
    ``answer=False`` makes a PD that accepts the connection but never replies. Every socket op
    carries a timeout so no test can hang.
    """

    def __init__(self, *, answer: bool = True) -> None:
        self.answer = answer
        self.accepted = 0
        self.polls_answered = 0
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(_SOCKET_TIMEOUT)
        self.port: int = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _addr = self._listener.accept()
        except OSError:
            return
        finally:
            self._listener.close()  # one connection ever, exactly like the lab PD
        self.accepted += 1
        with conn:
            conn.settimeout(_SOCKET_TIMEOUT)
            buffer = b""
            while True:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    return
                if not chunk:
                    return
                buffer += chunk
                buffer = self._handle(conn, buffer)

    def _handle(self, conn: socket.socket, buffer: bytes) -> bytes:
        """Answer every complete poll in ``buffer``; return the bytes after the last frame."""
        consumed = 0
        for raw in framer.iter_frames(buffer):
            consumed = buffer.index(raw, consumed) + len(raw)
            try:
                frame = codec.decode(raw)
            except codec.DecodeError:
                continue
            if frame.code != constants.CMD_POLL or frame.address != _PD_ADDRESS:
                continue
            if self.answer:
                conn.sendall(_ack(frame))
                self.polls_answered += 1
        return buffer[consumed:]

    def join(self) -> None:
        self._thread.join(timeout=_SOCKET_TIMEOUT)


def _free_port() -> int:
    """Return a loopback port with nothing listening on it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def test_fuzz_lab_holds_one_connection_and_reports_a_healthy_pd_clean() -> None:
    """Against a one-accept PD that answers polls, the whole sweep is clean on ONE connection.

    The old probe dialled a fresh connection per exchange; this PD would refuse every one after
    the first, which is exactly how the lab produced nine false HIGH findings.
    """
    pd = _OneAcceptPd()
    findings = fuzz_lab(("127.0.0.1", pd.port), connect_attempts=1)
    pd.join()
    assert findings == []
    assert pd.accepted == 1
    assert pd.polls_answered >= 1 + _NINE  # baseline + one follow-up per mutation


def test_fuzz_lab_raises_when_the_pd_never_answers_the_baseline() -> None:
    """A PD that accepts but stays silent gives no verdict at all, not nine findings."""
    pd = _OneAcceptPd(answer=False)
    with pytest.raises(FuzzBaselineError):
        fuzz_lab(("127.0.0.1", pd.port), connect_attempts=1)
    pd.join()
    assert pd.accepted == 1


def test_fuzz_lab_raises_when_nothing_is_listening() -> None:
    """No listener: the connect retries run out and FuzzBaselineError names host:port."""
    port = _free_port()
    with pytest.raises(FuzzBaselineError, match=f"127.0.0.1:{port}"):
        fuzz_lab(("127.0.0.1", port), connect_attempts=2, connect_delay=0.01)
