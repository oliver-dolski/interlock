"""ATK-07 OSDP command fuzzing: drive the nine deterministic corruptions onto the parser.

This takes the locked nine-member corruption corpus from ``osdp.mutate`` (D-06, I/O-free in
Phase 3) and drives it onto a live PD through the 04-03 write-capable seam. Every crafted
frame comes from ``mutate.mutate`` over a known-good frame built by ``codec.encode`` - never
hand-assembled malformed bytes - so each injection is attributable to exactly one named
mutation.

Determinism is the contract (D-06, prohibition): the nine-member ``Mutation`` sweep runs
first, in enum order, before any seeded variant; seeded variants draw from
``random.Random(seed)`` so a run is reproducible for the report. ``iter_mutations`` is the
single source of that order; ``fuzz_sweep`` and ``run_fuzz`` are both built on it.

- ``iter_mutations(good, seed, variants)`` yields ``(label, mutated_bytes)`` in the fixed
  order: the nine members, then ``variants`` seeded draws.
- ``fuzz_sweep(good, inject, ...)`` drives ``iter_mutations`` through a bare
  ``inject(bytes)`` seam (the counting/ordering primitive).
- ``run_fuzz(good, probe, ...)`` drives it through a liveness ``probe(bytes) -> bool`` that
  injects a frame and reports whether the PD is still live afterward. The true negative of a
  robust PD is a clean run (every injection leaves it live -> ``[]``); a frame that knocks it
  out (crash / hang / desync: silence or NAK to a follow-up valid poll) yields one
  ``Finding`` carrying the mutation name and the seed, so the report is reproducible.
- ``register`` adds the ``fuzz`` subcommand (``--seed`` / ``--variants``; lab default;
  ``--physical`` behind the SAFE-02 consent gate).

Import discipline: importable with the standard library plus the stdlib-only Phase 3 modules
(codec/constants/mutate). ``typer``, ``report`` and ``safety`` are imported lazily.
"""

from __future__ import annotations

import random
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import codec, constants
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.mutate import Mutation, mutate
from interlock.plugin import Finding, Severity

if TYPE_CHECKING:
    import typer

# Lab defaults: dial the PD directly (interlock as the sole CP driving the fuzz). The PD
# address is 101 under every profile (lab/osdp/pd_driver.py).
_DEFAULT_UPSTREAM = ("pd", 10000)
_DEFAULT_PD_ADDRESS = 101
_READ_SIZE = 4096

# ATK-07 free-text ATT&CK id: Endpoint Denial of Service (T1499). Phase 5 enriches it.
_TECHNIQUE = "T1499"

# An injection seam that only sends (no response needed): the counting/ordering primitive.
Inject = Callable[[bytes], None]

# A liveness probe: inject a (possibly malformed) frame and return True if the PD is still
# live afterward (responds to a follow-up valid poll), False on crash / hang / desync.
LivenessProbe = Callable[[bytes], bool]


def craft_poll(address: int = _DEFAULT_PD_ADDRESS) -> bytes:
    """Return a known-good CMD_POLL frame (cp->pd) built via ``codec.encode``.

    This is the good seed the fuzzer mutates and the valid frame the liveness probe sends to
    confirm the PD is still polling. control 0x05 = CRC bit set, sequence 1 (the lab CP's own
    steady-state poll). The reply flag is clear because this is a command travelling CP->PD.
    """
    return codec.encode(
        OsdpFrame(
            had_mark=True,
            address=address & ~constants.ADDR_REPLY_FLAG,
            control=0x05,
            scb=b"",
            code=constants.CMD_POLL,
            data=b"",
            use_crc=True,
        )
    )


def iter_mutations(
    good_frame: bytes,
    *,
    seed: int = 0,
    variants: int = 0,
) -> Iterator[tuple[str, bytes]]:
    """Yield ``(label, mutated_bytes)`` in the deterministic sweep order (D-06).

    The nine ``Mutation`` members come first, in enum declaration order, each labelled by its
    name. Then ``variants`` seeded draws from ``random.Random(seed)`` follow, each labelled
    ``<name>#seed<seed>`` so a finding is reproducible. The seeded phase never runs before the
    deterministic nine, and uses the seeded RNG only (never unseeded randomness).
    """
    for how in Mutation:
        yield (how.value, mutate(good_frame, how))
    rng = random.Random(seed)
    for _ in range(variants):
        how = rng.choice(list(Mutation))
        yield (f"{how.value}#seed{seed}", mutate(good_frame, how))


def fuzz_sweep(
    good_frame: bytes,
    inject: Inject,
    *,
    seed: int = 0,
    variants: int = 0,
) -> None:
    """Drive the deterministic nine-member sweep (then seeded variants) through ``inject``.

    Calls ``inject`` once per crafted frame in ``iter_mutations`` order: exactly nine times
    when ``variants == 0`` (one per ``Mutation`` member), and ``9 + variants`` times otherwise.
    ``inject`` only sends; it returns nothing. This is the pure injection primitive - the
    liveness classification lives in ``run_fuzz``.
    """
    for _label, frame_bytes in iter_mutations(good_frame, seed=seed, variants=variants):
        inject(frame_bytes)


def run_fuzz(
    good_frame: bytes,
    probe: LivenessProbe,
    *,
    seed: int = 0,
    variants: int = 0,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Drive the sweep through a liveness ``probe`` and emit a Finding per PD failure.

    For each crafted frame (deterministic nine first, then seeded variants) the probe injects
    it and reports whether the PD is still live. A clean run - every injection leaves the PD
    responding - returns ``[]`` (the true negative of a robust parser). A frame that knocks
    the PD out (crash / hang / desync) yields one ``Finding`` naming the mutation and the seed,
    so the report can reproduce it exactly.
    """
    findings: list[Finding] = []
    for label, frame_bytes in iter_mutations(good_frame, seed=seed, variants=variants):
        if probe(frame_bytes):
            continue  # PD still live: this corruption is a true negative
        findings.append(
            Finding(
                id=f"ATK-07-fuzz-{label}",
                title=f"OSDP PD failed under the {label} malformed frame",
                severity=Severity.HIGH,
                evidence=(
                    f"After injecting the '{label}' corruption (seed={seed}) the PD no longer "
                    f"responded to a follow-up valid CMD_POLL (crash / hang / desync). The "
                    f"frame was built by mutate.mutate over a codec.encode good frame, so it is "
                    f"reproducible from the mutation name and seed."
                ),
                attack_technique=technique,
                remediation=(
                    "Harden the PD's OSDP parser to fail closed on malformed / out-of-sequence "
                    "frames (bounded length, strict sequence and trailer validation) and keep "
                    "polling; a single bad frame must not desync or crash the reader."
                ),
            )
        )
    return findings


def _exchange(host: str, port: int, frame_bytes: bytes, *, timeout: float) -> bytes:
    """Send ``frame_bytes`` to the PD over a fresh connection and return one raw reply.

    Returns ``b""`` if the connection or read fails, so a dead / hung PD reads as silence.
    """
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


def _reply_is_live(reply: bytes) -> bool:
    """Return True if ``reply`` shows the PD still polling: a decodable, non-NAK reply.

    Silence (``b""``) reads as crash / hang; a REPLY_NAK reads as desync; anything that
    decodes to a valid non-NAK reply frame means the PD is still alive and answering polls.
    """
    from interlock.osdp import framer

    for raw in framer.iter_frames(reply):
        try:
            frame = codec.decode(raw)
        except codec.DecodeError:
            continue
        if frame.code != constants.REPLY_NAK:
            return True
    return False


def _socket_probe(
    host: str,
    port: int,
    good_poll: bytes,
    *,
    timeout: float = 2.0,
) -> LivenessProbe:
    """Return a ``LivenessProbe`` that injects over TCP, then checks the PD still polls.

    Each call sends the (possibly malformed) frame, then sends ``good_poll`` and inspects the
    reply: a decodable non-NAK reply means the PD survived the injection (live); silence or a
    NAK means it did not. Used by the lab fuzz driver where interlock dials the PD directly.
    """

    def probe(mutated: bytes) -> bool:
        _exchange(host, port, mutated, timeout=timeout)
        reply = _exchange(host, port, good_poll, timeout=timeout)
        return _reply_is_live(reply)

    return probe


def fuzz_lab(
    upstream: tuple[str, int],
    *,
    address: int = _DEFAULT_PD_ADDRESS,
    seed: int = 0,
    variants: int = 0,
) -> list[Finding]:
    """Fuzz the lab PD over TCP and return any crash / hang / desync Findings.

    Builds a known-good CMD_POLL for ``address``, dials the upstream PD, and runs the
    deterministic sweep (then seeded variants) through a liveness probe. A robust PD yields
    ``[]`` (clean run / true negative); a failure is reported with its mutation name and seed.
    """
    good_poll = craft_poll(address)
    probe = _socket_probe(upstream[0], upstream[1], good_poll)
    return run_fuzz(good_poll, probe, seed=seed, variants=variants)


def register(app: typer.Typer) -> None:
    """Attach the ``fuzz`` subcommand to the ``osdp`` Typer group."""
    import typer

    from interlock import report

    @app.command("fuzz")
    def fuzz(
        upstream_host: str = typer.Option(
            _DEFAULT_UPSTREAM[0],
            "--upstream-host",
            help="Upstream PD host to fuzz (lab default).",
        ),
        upstream_port: int = typer.Option(
            _DEFAULT_UPSTREAM[1],
            "--upstream-port",
            help="Upstream PD port to fuzz.",
        ),
        address: int = typer.Option(
            _DEFAULT_PD_ADDRESS,
            "--address",
            help="PD address to target with the good-frame seed.",
        ),
        seed: int = typer.Option(
            0,
            "--seed",
            help="Fixed seed for the seeded variant phase (reproducible).",
        ),
        variants: int = typer.Option(
            0,
            "--variants",
            help="Seeded variants to run after the deterministic nine-member sweep.",
        ),
        physical: bool = typer.Option(
            False,
            "--physical",
            help="Fuzz a REAL serial port, behind the SAFE-02 consent gate.",
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
        """Fuzz an OSDP PD with the nine deterministic corruptions (plus seeded variants)."""
        good_poll = craft_poll(address)
        if physical:
            # The ONLY real-port path: SAFE-02 consent gate before any byte is transmitted.
            from interlock.osdp.attacks import safety

            if not device or not target:
                raise typer.BadParameter("--physical requires both --device and --target")
            endpoint = safety.open_physical_endpoint(device, target)
            try:
                probe = _serial_probe(endpoint, good_poll)
                findings = run_fuzz(good_poll, probe, seed=seed, variants=variants)
            finally:
                endpoint.close()
        else:
            findings = fuzz_lab(
                (upstream_host, upstream_port), address=address, seed=seed, variants=variants
            )

        if not findings:
            typer.echo(
                "No parser failure detected - the PD stayed live through the whole sweep "
                "(clean run / true negative)."
            )
        report.render_terminal(findings)
        report.write_markdown(findings, path=output)
        typer.echo(f"Wrote report to {output}")


def _serial_probe(endpoint: object, good_poll: bytes, *, timeout: float = 2.0) -> LivenessProbe:
    """Return a ``LivenessProbe`` over a consented pyserial endpoint (active --physical).

    Mirrors ``_socket_probe`` for a real port: write the malformed frame, write the valid poll,
    read one reply, and classify liveness. Kept dependency-light so the module imports with no
    pyserial at module scope; ``endpoint`` is the ``serial.Serial`` from ``open_physical_endpoint``.
    """

    def probe(mutated: bytes) -> bool:
        endpoint.write(mutated)  # type: ignore[attr-defined]
        endpoint.write(good_poll)  # type: ignore[attr-defined]
        return _reply_is_live(bytes(endpoint.read(_READ_SIZE)))  # type: ignore[attr-defined]

    return probe
