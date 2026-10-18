"""ATK-01 passive OSDP bus sniffing: decode the wire into a PD topology (D-01/D-02).

``run_sniff`` is the pure library function: it folds a direction-tagged, decoded
frame sequence into a per-PD topology (each PD address, the command/reply code
names it used, and the Secure Channel posture of the session) and emits one
``interlock.plugin.Finding`` per PD address. ``decode_chunks`` turns a raw
(direction, bytes) stream into decoded ``(Direction, OsdpFrame)`` pairs, framing
and decoding each chunk through the Phase 3 codec - never hand-parsing - and
wrapping ``codec.decode`` in a ``DecodeError`` guard (V5: never trust frame bytes).
``sniff_lab`` is the thin collector that drives the read-only ``TCPTap`` against
the bundled lab (TCP) by default. ``register`` adds the ``sniff`` subcommand.

Flagged-assumption negative: an empty or zero-decodable-frame capture yields NO
Finding (``run_sniff`` returns ``[]``). No-frames-decoded is reported as an
explicit negative, never a false "success".

Import discipline: this module stays importable with the standard library plus the
stdlib-only Phase 3 modules (codec/framer/constants/transport). ``secure_channel``
(which pulls cryptography), ``typer`` and ``report`` are imported lazily inside the
functions that need them, so importing the library does not require them.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import codec, constants, framer
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction, TCPTap
from interlock.plugin import Finding, Severity

if TYPE_CHECKING:
    import typer

    from interlock.osdp.secure_channel import ChannelState

# Lab defaults: listen in the attacker position and relay to the upstream PD. No
# serial path exists in this plan; the --physical consent gate arrives in 04-03.
_DEFAULT_LISTEN_PORT = 10000
_DEFAULT_UPSTREAM = ("pd", 10000)
_DEFAULT_MAX_FRAMES = 200

# ATK-01 free-text ATT&CK id (T1040 Network Sniffing); Phase 5 enriches the mapping.
_TECHNIQUE = "T1040"


def decode_chunks(
    chunks: Iterable[tuple[Direction, bytes]],
    *,
    max_frames: int = _DEFAULT_MAX_FRAMES,
) -> list[tuple[Direction, OsdpFrame]]:
    """Decode a (direction, bytes) chunk stream into (Direction, OsdpFrame) pairs.

    Bytes are buffered per direction because recv chunks are not frame-aligned; the
    framer is re-run over the growing per-direction buffer and only newly completed
    frames (beyond those already emitted) are decoded, so each frame is decoded
    once. ``codec.decode`` is wrapped in a ``DecodeError`` guard so a malformed or
    garbage chunk never crashes the collector. Stops after ``max_frames`` decodes.
    """
    buffers: dict[Direction, bytearray] = {
        Direction.cp_to_pd: bytearray(),
        Direction.pd_to_cp: bytearray(),
    }
    emitted: dict[Direction, int] = {Direction.cp_to_pd: 0, Direction.pd_to_cp: 0}
    out: list[tuple[Direction, OsdpFrame]] = []
    for direction, chunk in chunks:
        buffer = buffers[direction]
        buffer.extend(chunk)
        frames = list(framer.iter_frames(bytes(buffer)))
        for raw in frames[emitted[direction] :]:
            try:
                out.append((direction, codec.decode(raw)))
            except codec.DecodeError:
                pass  # trailer-valid but structurally malformed; skip, never crash (V5)
            if len(out) >= max_frames:
                return out
        emitted[direction] = len(frames)
    return out


def run_sniff(
    frames: Iterable[tuple[Direction, OsdpFrame]],
    *,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Fold decoded frames into a per-PD topology and emit one Finding per PD.

    For each address (with the reply flag masked off) the command/reply code names
    seen are recorded (via ``COMMAND_CODES`` / ``REPLY_CODES`` by direction, falling
    back to a hex string for unknown codes). The session Secure Channel posture is
    read from the wire via ``secure_channel.detect_state``. An empty frame sequence
    returns ``[]`` - no spurious Finding on an empty capture (flagged assumption).
    """
    from interlock.osdp import secure_channel

    items = list(frames)
    if not items:
        return []

    codes: dict[int, set[str]] = {}
    for direction, frame in items:
        address = frame.address & ~constants.ADDR_REPLY_FLAG
        table = (
            constants.COMMAND_CODES
            if direction is Direction.cp_to_pd
            else constants.REPLY_CODES
        )
        name = table.get(frame.code, f"0x{frame.code:02x}")
        codes.setdefault(address, set()).add(name)

    state = secure_channel.detect_state(items)
    posture = _posture(state)
    severity = Severity.MEDIUM if state.clear_text else Severity.INFO
    remediation = _remediation(state)

    findings: list[Finding] = []
    for address in sorted(codes):
        names = ", ".join(sorted(codes[address]))
        findings.append(
            Finding(
                id=f"ATK-01-sniff-pd-{address}",
                title=f"OSDP PD {address} observed on the bus",
                severity=severity,
                evidence=(
                    f"PD address {address}; codes seen: {names}; "
                    f"Secure Channel posture: {posture}."
                ),
                attack_technique=technique,
                remediation=remediation,
            )
        )
    return findings


def sniff_lab(
    target_port: int,
    upstream: tuple[str, int],
    *,
    max_frames: int = _DEFAULT_MAX_FRAMES,
) -> list[Finding]:
    """Drive the read-only ``TCPTap`` against the lab bus and return sniff Findings.

    Observes one bridged CP<->PD session, decodes up to ``max_frames`` frames, and
    folds them with ``run_sniff``. Read-only pass-through only (SAFE-01): the tap
    forwards the exact bytes it reads and observes a copy.
    """
    tap = TCPTap(target_port, upstream)
    frames = decode_chunks(tap.observe(), max_frames=max_frames)
    return run_sniff(frames)


def _posture(state: ChannelState) -> str:
    """Return a short human-readable Secure Channel posture string."""
    if state.clear_text:
        return "clear-text"
    if state.scbk_d_confirmed:
        return "Secure Channel (default SCBK-D key confirmed)"
    return "Secure Channel"


def _remediation(state: ChannelState) -> str:
    """Return remediation guidance keyed to the observed Secure Channel posture."""
    if state.clear_text:
        return (
            "Enable OSDP Secure Channel (SCBK) so bus traffic is authenticated and "
            "encrypted; do not operate readers in clear-text."
        )
    if state.scbk_d_confirmed:
        return (
            "Replace the default Secure Channel Base Key (SCBK-D) with a unique "
            "per-site key; the spec default provides no confidentiality."
        )
    return "Confirm the Secure Channel key is unique per site and not a known default."


def register(app: typer.Typer) -> None:
    """Attach the ``sniff`` subcommand to the ``osdp`` Typer group."""
    import typer

    from interlock import report

    @app.command("sniff")
    def sniff(
        port: int = typer.Option(
            _DEFAULT_LISTEN_PORT,
            "--port",
            help="Local TCP port to listen on (attacker position, lab default).",
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
        max_frames: int = typer.Option(
            _DEFAULT_MAX_FRAMES,
            "--max-frames",
            help="Stop after decoding this many frames.",
        ),
        output: Path = typer.Option(
            Path("interlock-report.md"),
            "--output",
            "-o",
            help="Path to write the Markdown report to.",
        ),
    ) -> None:
        """Passively sniff the OSDP bus (lab TCP by default) and report PD topology."""
        findings = sniff_lab(port, (upstream_host, upstream_port), max_frames=max_frames)
        if not findings:
            typer.echo("No OSDP frames decoded - no PDs observed (empty capture).")
        report.render_terminal(findings)
        report.write_markdown(findings, path=output)
        typer.echo(f"Wrote report to {output}")
