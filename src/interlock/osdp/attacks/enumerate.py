"""ATK-02 PD enumeration: addresses and advertised capabilities (D-01/D-02).

Two wire-grounded modes build a topology-with-capabilities view of an OSDP bus, the
reconnaissance step before any targeted attack:

- **passive** (``run_enumerate``): read the ``REPLY_PDID`` (0x45) and ``REPLY_PDCAP``
  (0x46) replies the live CP already solicits, decoding each PD's identity and the
  capability triples it advertises straight off the wire.
- **active** (``sweep_addresses``): inject ``CMD_ID`` / ``CMD_CAP`` per address through a
  write-capable send/receive seam and collect the replies, so the capability also works
  against real hardware where interlock is the only CP. Every crafted frame is built with
  ``codec.encode`` (never hand-assembled bytes) and addressed with the reply flag cleared.

``run_enumerate`` lists a PD only when a ``REPLY_PDID`` or ``REPLY_PDCAP`` for its address
was decoded (an empty / no-reply capture lists NO device - a true negative, never an
invented one), and reports a capability only when a ``REPLY_PDCAP`` triple backs it. No
address and no capability is ever guessed (threat T-4-08, prohibition).

Active sweep safety (threat T-4-09): the sweep itself is transport-agnostic - it drives
whatever send/receive injector it is given. The CLI's ``--physical`` branch is the ONLY
path to a real port and routes through ``safety.open_physical_endpoint`` (the SAFE-02
consent gate); the lab is the default.

Import discipline: this module stays importable with the standard library plus the
stdlib-only Phase 3 modules (codec/framer/constants/transport). ``typer``, ``report`` and
``safety`` are imported lazily inside the functions that need them, so importing the
library requires none of them.
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import codec, constants, framer
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction, TCPTap
from interlock.plugin import Finding, Severity

if TYPE_CHECKING:
    import typer

# Lab defaults: listen in the attacker position and relay to the upstream PD for the
# passive read-only tap, mirroring sniff. The active sweep dials the PD directly (interlock
# as CP). No serial path is reachable except through the --physical consent gate (04-03).
_DEFAULT_LISTEN_PORT = 10000
_DEFAULT_UPSTREAM = ("pd", 10000)
_DEFAULT_MAX_FRAMES = 200

# Active sweep address space: the full OSDP 7-bit PD address range (0x00..0x7F). The reply
# flag (0x80) is never set on a cp->pd command, so every swept address is already clear of it.
_SWEEP_ADDRESSES = range(0x80)  # 0x00..0x7F inclusive

# Per-reply read size for the active sweep injectors (TCP and serial).
_READ_SIZE = 4096

# ATK-02 free-text ATT&CK id (T1200 default per the plan); Phase 5 enriches the mapping.
_TECHNIQUE = "T1200"

# OSDP PD capability function codes -> readable names, matching the pyosdp Capability enum the
# lab PD driver builds from (lab/osdp/pd_driver.py: getattr(Capability, name)). VERIFIED
# against the OSDP spec function-code table and the lab's _BASE_CAPS (OutputControl=2,
# LEDControl=4, AudibleControl=5, TextOutput=6, CommunicationSecurity=9). Unknown codes fall
# back to a hex string so an unmapped capability is still reported from the wire, never dropped.
CAPABILITY_CODES: dict[int, str] = {
    0x01: "ContactStatusMonitoring",
    0x02: "OutputControl",
    0x03: "CardDataFormat",
    0x04: "LEDControl",
    0x05: "AudibleControl",
    0x06: "TextOutput",
    0x07: "TimeKeeping",
    0x08: "CheckCharacterSupport",
    0x09: "CommunicationSecurity",
    0x0A: "ReceiveBufferSize",
    0x0B: "LargestCombinedMessage",
    0x0C: "SmartCardSupport",
    0x0D: "Readers",
    0x0E: "Biometrics",
}

# A send/receive injector for the active sweep: given one crafted frame's bytes it transmits
# them and returns the raw reply bytes (b"" when nothing came back). This is the write-capable
# seam the active sweep drives; the CLI backs it with a direct TCP socket to the lab PD or,
# behind the --physical gate, with the single consented serial endpoint.
SendFrame = Callable[[bytes], bytes]


class Capability:
    """A single advertised PD capability, decoded from one REPLY_PDCAP triple.

    ``function_code``, ``compliance`` and ``count`` are the three raw bytes exactly as they
    appeared on the wire; ``name`` is the readable mapping (or a hex fallback for an unmapped
    code). Nothing here is inferred - every field is a decoded wire byte (prohibition).
    """

    __slots__ = ("compliance", "count", "function_code")

    def __init__(self, function_code: int, compliance: int, count: int) -> None:
        self.function_code = function_code
        self.compliance = compliance
        self.count = count

    @property
    def name(self) -> str:
        """Return the readable capability name, or a hex fallback for an unmapped code."""
        return CAPABILITY_CODES.get(self.function_code, f"0x{self.function_code:02x}")

    def describe(self) -> str:
        """Return ``Name(compliance=C,count=N)`` for the evidence listing."""
        return f"{self.name}(compliance={self.compliance},count={self.count})"


def parse_pdcap(data: bytes) -> list[Capability]:
    """Decode a REPLY_PDCAP payload into its advertised capability triples.

    The payload is a flat sequence of 3-byte (function_code, compliance, count) triples. Any
    trailing bytes that do not complete a triple are ignored (fail-soft: a truncated tail
    never raises and never fabricates a capability). Each triple is reported exactly as decoded.
    """
    caps: list[Capability] = []
    for i in range(0, len(data) - (len(data) % 3), 3):
        caps.append(Capability(data[i], data[i + 1], data[i + 2]))
    return caps


def parse_pdid(data: bytes) -> str:
    """Return a readable PD identity string decoded from a REPLY_PDID payload.

    The 12-byte PDID layout is vendor code (3), model (1), version (1), serial (4), firmware
    (3). A short payload is reported as its raw hex rather than being padded or invented, so
    the identity is always exactly what the wire carried.
    """
    if len(data) < 12:
        return f"raw={data.hex()}"
    vendor = data[0:3].hex()
    model = data[3]
    version = data[4]
    serial = data[5:9].hex()
    firmware = f"{data[9]}.{data[10]}.{data[11]}"
    return (
        f"vendor=0x{vendor} model={model} version={version} "
        f"serial=0x{serial} firmware={firmware}"
    )


def run_enumerate(
    frames: Iterable[tuple[Direction, OsdpFrame]],
    *,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Fold decoded frames into a per-PD enumeration and emit one Finding per PD address.

    For each ``REPLY_PDID`` the PD identity is decoded; for each ``REPLY_PDCAP`` the advertised
    capability triples are decoded. A device is listed only for an address that produced at
    least one of those replies (an empty / no-reply capture returns ``[]`` - the flagged
    true negative). A capability is listed only when a REPLY_PDCAP triple backs it; nothing is
    guessed. The source address is resolved by masking the reply flag off ``frame.address``.
    """
    identities: dict[int, str] = {}
    capabilities: dict[int, list[Capability]] = {}

    for _direction, frame in frames:
        address = frame.address & ~constants.ADDR_REPLY_FLAG
        if frame.code == constants.REPLY_PDID:
            identities[address] = parse_pdid(frame.data)
        elif frame.code == constants.REPLY_PDCAP:
            capabilities.setdefault(address, []).extend(parse_pdcap(frame.data))

    addresses = sorted(set(identities) | set(capabilities))
    findings: list[Finding] = []
    for address in addresses:
        identity = identities.get(address, "not observed (no REPLY_PDID)")
        caps = capabilities.get(address)
        if caps:
            cap_str = ", ".join(cap.describe() for cap in caps)
        else:
            cap_str = "none observed (no REPLY_PDCAP)"
        findings.append(
            Finding(
                id=f"ATK-02-enumerate-pd-{address}",
                title=f"OSDP PD {address} enumerated",
                severity=Severity.LOW,
                evidence=(
                    f"PD address {address}; identity: {identity}; "
                    f"advertised capabilities: {cap_str}."
                ),
                attack_technique=technique,
                remediation=(
                    "Enable OSDP Secure Channel so identity (REPLY_PDID) and capability "
                    "(REPLY_PDCAP) replies are authenticated and encrypted; unauthenticated "
                    "clear-text enumeration lets any bus listener map readers before attacking."
                ),
            )
        )
    return findings


def craft_command(address: int, code: int, control: int) -> OsdpFrame:
    """Craft one cp->pd command frame for the active sweep, built via ``codec.encode`` later.

    The reply flag (``ADDR_REPLY_FLAG``) is cleared from ``address`` because this is a
    command travelling CP->PD; ``control`` carries the CRC bit and sequence exactly as the
    lab CP's own startup CMD_ID/CMD_CAP frames do (0x04 / 0x05). ``data`` is the single 0x00
    byte both commands carry on the wire. Raises ``ValueError`` for an out-of-range address.
    """
    if not 0x00 <= address <= 0x7F:
        raise ValueError(f"address {address:#04x} is outside the OSDP range 0x00..0x7F")
    return OsdpFrame(
        had_mark=True,
        address=address & ~constants.ADDR_REPLY_FLAG,
        control=control,
        scb=b"",
        code=code,
        data=b"\x00",
        use_crc=True,
    )


def sweep_addresses(
    send_frame: SendFrame,
    *,
    addresses: Iterable[int] = _SWEEP_ADDRESSES,
    max_frames: int = _DEFAULT_MAX_FRAMES,
) -> list[tuple[Direction, OsdpFrame]]:
    """Inject CMD_ID / CMD_CAP per address through ``send_frame`` and collect decoded replies.

    For each address the sweep crafts a ``CMD_ID`` (control 0x04) then a ``CMD_CAP`` (control
    0x05) via ``codec.encode`` - never hand-built bytes - transmits each through the
    write-capable ``send_frame`` injector, frames the raw reply, and decodes it under a
    ``DecodeError`` guard (garbage never crashes the sweep). The returned
    ``(Direction.pd_to_cp, OsdpFrame)`` pairs feed straight into ``run_enumerate``. Stops
    after ``max_frames`` decoded replies. This is the real-hardware path (interlock as CP).
    """
    collected: list[tuple[Direction, OsdpFrame]] = []
    for address in addresses:
        for code, control in ((constants.CMD_ID, 0x04), (constants.CMD_CAP, 0x05)):
            frame = craft_command(address, code, control)
            reply = send_frame(codec.encode(frame))
            if not reply:
                continue
            for raw in framer.iter_frames(reply):
                try:
                    collected.append((Direction.pd_to_cp, codec.decode(raw)))
                except codec.DecodeError:
                    pass  # trailer-valid but structurally malformed; skip, never crash
                if len(collected) >= max_frames:
                    return collected
    return collected


def enumerate_passive_lab(
    target_port: int,
    upstream: tuple[str, int],
    *,
    max_frames: int = _DEFAULT_MAX_FRAMES,
) -> list[Finding]:
    """Drive the read-only ``TCPTap`` against the lab bus and enumerate from solicited replies.

    Observes one bridged CP<->PD session, decodes up to ``max_frames`` frames with the same
    collector sniff uses, and folds the REPLY_PDID/REPLY_PDCAP the live CP already solicits
    with ``run_enumerate``. Read-only pass-through only (SAFE-01).
    """
    from interlock.osdp.attacks.sniff import decode_chunks

    tap = TCPTap(target_port, upstream)
    frames = decode_chunks(tap.observe(), max_frames=max_frames)
    return run_enumerate(frames)


def _socket_send_frame(host: str, port: int, *, timeout: float = 2.0) -> SendFrame:
    """Return a ``SendFrame`` backed by a fresh TCP connection to the PD per injected frame.

    Each call dials the PD, sends the crafted frame, reads one reply within ``timeout``, and
    closes the socket. Used by the lab active sweep where interlock dials the PD directly
    (no MITM). Returns ``b""`` if the connection or read fails, so one dead address never
    aborts the sweep.
    """

    def send(frame_bytes: bytes) -> bytes:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(frame_bytes)
                try:
                    return sock.recv(_READ_SIZE)
                except OSError:
                    return b""
        except OSError:
            return b""

    return send


def register(app: typer.Typer) -> None:
    """Attach the ``enumerate`` subcommand to the ``osdp`` Typer group."""
    import typer

    from interlock import report

    @app.command("enumerate")
    def enumerate_cmd(
        mode: str = typer.Option(
            "passive",
            "--mode",
            help="passive = read the replies the live CP solicits (lab-safe default); "
            "active = sweep addresses by injecting CMD_ID/CMD_CAP.",
        ),
        port: int = typer.Option(
            _DEFAULT_LISTEN_PORT,
            "--port",
            help="Passive: local TCP port to listen on (attacker position, lab default).",
        ),
        upstream_host: str = typer.Option(
            _DEFAULT_UPSTREAM[0],
            "--upstream-host",
            help="Upstream PD host (passive relay target / active sweep target).",
        ),
        upstream_port: int = typer.Option(
            _DEFAULT_UPSTREAM[1],
            "--upstream-port",
            help="Upstream PD port.",
        ),
        max_frames: int = typer.Option(
            _DEFAULT_MAX_FRAMES,
            "--max-frames",
            help="Stop after decoding this many frames.",
        ),
        physical: bool = typer.Option(
            False,
            "--physical",
            help="Active sweep against a REAL serial port, behind the SAFE-02 consent gate.",
        ),
        device: str = typer.Option(
            "",
            "--device",
            help="Serial device path for --physical (e.g. /dev/ttyUSB0).",
        ),
        target: str = typer.Option(
            "",
            "--target",
            help="Scope identifier you are authorized to assess (required for --physical).",
        ),
        output: Path = typer.Option(
            Path("interlock-report.md"),
            "--output",
            "-o",
            help="Path to write the Markdown report to.",
        ),
    ) -> None:
        """Enumerate OSDP PD addresses and capabilities (passive by default; lab-safe)."""
        if mode not in ("passive", "active"):
            raise typer.BadParameter("--mode must be 'passive' or 'active'")

        if mode == "passive":
            if physical:
                raise typer.BadParameter("--physical applies to --mode active only")
            findings = enumerate_passive_lab(
                port, (upstream_host, upstream_port), max_frames=max_frames
            )
        elif physical:
            # The ONLY real-port path: SAFE-02 consent gate before any byte is transmitted.
            from interlock.osdp.attacks import safety

            if not device or not target:
                raise typer.BadParameter("--physical requires both --device and --target")
            endpoint = safety.open_physical_endpoint(device, target)
            try:
                findings = run_enumerate(
                    sweep_addresses(
                        lambda data: _serial_exchange(endpoint, data), max_frames=max_frames
                    )
                )
            finally:
                endpoint.close()
        else:
            findings = run_enumerate(
                sweep_addresses(
                    _socket_send_frame(upstream_host, upstream_port), max_frames=max_frames
                )
            )

        if not findings:
            typer.echo("No OSDP PDs enumerated - no REPLY_PDID/REPLY_PDCAP observed.")
        report.render_terminal(findings)
        report.write_markdown(findings, path=output)
        typer.echo(f"Wrote report to {output}")


def _serial_exchange(endpoint: object, frame_bytes: bytes) -> bytes:
    """Write one crafted frame to a pyserial endpoint and read one reply (active --physical).

    Kept tiny and dependency-light so the module imports with no pyserial at module scope;
    ``endpoint`` is the ``serial.Serial`` returned by the consented ``open_physical_endpoint``.
    """
    endpoint.write(frame_bytes)  # type: ignore[attr-defined]
    return bytes(endpoint.read(_READ_SIZE))  # type: ignore[attr-defined]
