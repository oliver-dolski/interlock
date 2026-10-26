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
- ``fuzz_lab(upstream, ...)`` drives the sweep against a lab PD over ONE persistent TCP
  connection. The lab PD (lab/osdp/tcp_channel.listen) accepts exactly one connection and
  then closes its listener, so a probe that dialled a fresh connection per exchange read
  every refused connection as "PD dead" and reported nine false HIGH findings. The
  persistent probe connects once (retrying while the PD comes up), proves a live baseline
  with a valid sequence-0 CMD_POLL before the first mutation (``FuzzBaselineError``
  otherwise, so no verdict is ever drawn from an unreachable PD), and after each corrupted
  frame drains the PD's reply to it, sends a valid CMD_POLL with the next sequence
  (1 -> 2 -> 3 -> 1) and, if that is not answered live, one sequence-0 restart poll. The
  sweep stops at the first dead PD (``run_fuzz(stop_on_failure=True)``): with one connection
  ever, later mutations could not be attributed, so a real failure is exactly one Finding.
- ``register`` adds the ``fuzz`` subcommand (``--seed`` / ``--variants``; lab default;
  ``--physical`` behind the SAFE-02 consent gate).

Import discipline: importable with the standard library plus the stdlib-only Phase 3 modules
(codec/constants/framer/mutate). ``typer``, ``report`` and ``safety`` are imported lazily.
"""

from __future__ import annotations

import random
import socket
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import codec, constants, framer
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

# The lab PD logs "listening" just before it calls accept(); retry the one connection across
# that window (and across a slow container start) before giving up.
_CONNECT_ATTEMPTS = 10
_CONNECT_DELAY = 1.0
# How long to wait for a reply to a valid poll, and how long to drain whatever the PD sends
# back to a corrupted frame so that reply is never mistaken for the follow-up poll's reply.
_REPLY_TIMEOUT = 2.0
_DRAIN_SECONDS = 0.3

# ATK-07 free-text ATT&CK id: Endpoint Denial of Service (T1499). Phase 5 enriches it.
_TECHNIQUE = "T1499"

# Lowercase substrings of LibOSDP PD log lines showing that a corrupted frame reached the PD's
# parser and was rejected there. A lab oracle (matched case-insensitively against the PD log):
# a clean sweep only proves robustness if the corruptions actually reached the parser.
LIBOSDP_REJECTION_MARKERS: tuple[str, ...] = ("invalid crc", "sequence mismatch", "unknown cmd")


class FuzzBaselineError(RuntimeError):
    """The PD could not be reached or did not answer a valid baseline poll.

    Raised before the first mutation is sent: without a proven live baseline on the same
    connection, silence after a corruption cannot be told apart from a PD that was never
    there, so no liveness verdict (and no finding) is possible.
    """


# An injection seam that only sends (no response needed): the counting/ordering primitive.
Inject = Callable[[bytes], None]

# A liveness probe: inject a (possibly malformed) frame and return True if the PD is still
# live afterward (responds to a follow-up valid poll), False on crash / hang / desync.
LivenessProbe = Callable[[bytes], bool]


def craft_poll(address: int = _DEFAULT_PD_ADDRESS, *, sequence: int = 1) -> bytes:
    """Return a known-good CMD_POLL frame (cp->pd) built via ``codec.encode``.

    This is the good seed the fuzzer mutates and the valid frame the liveness probe sends to
    confirm the PD is still polling. The control byte is the CRC bit plus ``sequence``; the
    default sequence 1 gives control 0x05 (the lab CP's own steady-state poll), which is the
    seed of the mutation corpus. Sequence 0 is the OSDP restart poll. The reply flag is clear
    because this is a command travelling CP->PD.
    """
    if not 0 <= sequence <= constants.PKT_CONTROL_SQN:
        raise ValueError(f"OSDP sequence must be 0..3, got {sequence}")
    return codec.encode(
        OsdpFrame(
            had_mark=True,
            address=address & ~constants.ADDR_REPLY_FLAG,
            control=constants.PKT_CONTROL_CRC | sequence,
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
    stop_on_failure: bool = False,
) -> list[Finding]:
    """Drive the sweep through a liveness ``probe`` and emit a Finding per PD failure.

    For each crafted frame (deterministic nine first, then seeded variants) the probe injects
    it and reports whether the PD is still live. A clean run - every injection leaves the PD
    responding - returns ``[]`` (the true negative of a robust parser). A frame that knocks
    the PD out (crash / hang / desync) yields one ``Finding`` naming the mutation and the seed,
    so the report can reproduce it exactly.

    ``stop_on_failure`` ends the sweep at the first failure. Use it when the PD cannot be
    re-reached after it dies (the lab PD accepts one connection): every later mutation would
    otherwise be blamed on a PD that is already gone, so only the first is attributable.
    """
    findings: list[Finding] = []
    for label, frame_bytes in iter_mutations(good_frame, seed=seed, variants=variants):
        if probe(frame_bytes):
            continue  # PD still live: this corruption is a true negative
        stopped = (
            " The sweep stopped here: the PD could not be re-reached, so the remaining "
            "mutations were not run and could not have been attributed to this PD."
            if stop_on_failure
            else ""
        )
        findings.append(
            Finding(
                id=f"ATK-07-fuzz-{label}",
                title=f"OSDP PD failed under the {label} malformed frame",
                severity=Severity.HIGH,
                evidence=(
                    f"After injecting the '{label}' corruption (seed={seed}) the PD no longer "
                    f"responded to a follow-up valid CMD_POLL (crash / hang / desync). The "
                    f"frame was built by mutate.mutate over a codec.encode good frame, so it is "
                    f"reproducible from the mutation name and seed.{stopped}"
                ),
                attack_technique=technique,
                remediation=(
                    "Harden the PD's OSDP parser to fail closed on malformed / out-of-sequence "
                    "frames (bounded length, strict sequence and trailer validation) and keep "
                    "polling; a single bad frame must not desync or crash the reader."
                ),
            )
        )
        if stop_on_failure:
            break
    return findings


def _reply_is_live(reply: bytes) -> bool:
    """Return True if ``reply`` shows the PD still polling: a decodable, non-NAK reply.

    Silence (``b""``) reads as crash / hang; a REPLY_NAK reads as desync; anything that
    decodes to a valid non-NAK reply frame means the PD is still alive and answering polls.
    """
    for raw in framer.iter_frames(reply):
        try:
            frame = codec.decode(raw)
        except codec.DecodeError:
            continue
        if frame.code != constants.REPLY_NAK:
            return True
    return False


def _next_sequence(sequence: int) -> int:
    """Return the OSDP sequence after ``sequence``: 0 -> 1 -> 2 -> 3 -> 1 (0 only on restart)."""
    return sequence % constants.PKT_CONTROL_SQN + 1


class _PersistentProbe:
    """A ``LivenessProbe`` over ONE connected socket to the PD, held for the whole sweep.

    Mirrors ``_serial_probe``'s one-endpoint shape for TCP. ``baseline`` must succeed before
    the probe is called: it proves the PD answers a valid sequence-0 poll on this very
    connection. Each call then sends the corrupted frame, drains the PD's reply to it, sends a
    valid poll with the next sequence and, if that is not answered live, one sequence-0
    restart poll. Any socket error or a closed connection reads as "PD gone" (``False``).
    """

    def __init__(
        self,
        sock: socket.socket,
        address: int,
        *,
        timeout: float = _REPLY_TIMEOUT,
        drain: float = _DRAIN_SECONDS,
    ) -> None:
        self._sock = sock
        self._address = address
        self._timeout = timeout
        self._drain = drain
        self._sequence = 0

    def baseline(self) -> None:
        """Send a sequence-0 CMD_POLL and require a live reply, else ``FuzzBaselineError``."""
        try:
            reply = self._poll(0)
        except OSError as exc:
            raise FuzzBaselineError(
                f"baseline CMD_POLL failed on the PD connection: {exc}"
            ) from exc
        if not _reply_is_live(reply):
            raise FuzzBaselineError(
                "the PD did not answer a valid sequence-0 CMD_POLL with a decodable non-NAK "
                "reply, so no liveness verdict is possible"
            )
        self._sequence = 0

    def __call__(self, mutated: bytes) -> bool:
        try:
            self._sock.sendall(mutated)
            self._read(self._drain, until_frame=False)  # the PD's answer to the corruption
            if _reply_is_live(self._poll(_next_sequence(self._sequence))):
                return True
            return _reply_is_live(self._poll(0))  # one restart before calling the PD dead
        except OSError:
            return False

    def _poll(self, sequence: int) -> bytes:
        """Send a valid CMD_POLL with ``sequence`` and return the raw reply bytes read."""
        self._sequence = sequence
        self._sock.sendall(craft_poll(self._address, sequence=sequence))
        return self._read(self._timeout, until_frame=True)

    def _read(self, window: float, *, until_frame: bool) -> bytes:
        """Read for up to ``window`` seconds; stop early once a frame is complete if asked.

        A closed connection raises ``ConnectionError`` (the PD went away mid-sweep); running
        out of time is not an error and returns whatever arrived.
        """
        buffer = b""
        deadline = time.monotonic() + window
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return buffer
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(_READ_SIZE)
            except TimeoutError:
                return buffer
            if not chunk:
                raise ConnectionError("the PD closed the connection")
            buffer += chunk
            if until_frame and any(True for _ in framer.iter_frames(buffer)):
                return buffer


def _connect(host: str, port: int, *, attempts: int, delay: float) -> socket.socket:
    """Open the single PD connection, retrying; ``FuzzBaselineError`` after the last attempt."""
    last: OSError | None = None
    for attempt in range(attempts):
        try:
            return socket.create_connection((host, port), timeout=_REPLY_TIMEOUT)
        except OSError as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(delay)
    raise FuzzBaselineError(
        f"could not connect to the PD at {host}:{port} after {attempts} attempts: {last}"
    )


def fuzz_lab(
    upstream: tuple[str, int],
    *,
    address: int = _DEFAULT_PD_ADDRESS,
    seed: int = 0,
    variants: int = 0,
    connect_attempts: int | None = None,
    connect_delay: float | None = None,
) -> list[Finding]:
    """Fuzz the lab PD over one persistent TCP connection and return any failure Findings.

    Opens one connection to ``upstream`` (retrying while the PD comes up), proves a live
    baseline with a valid sequence-0 poll, then runs the deterministic sweep (then seeded
    variants) through the persistent probe on that same connection. A robust PD yields ``[]``
    (clean run / true negative). The sweep stops at the first dead PD, which yields exactly
    one Finding: the lab PD accepts one connection, so later mutations are unattributable.
    Raises ``FuzzBaselineError`` when the PD cannot be reached or does not answer the
    baseline: a sweep against an absent PD would only report silence.
    """
    attempts = _CONNECT_ATTEMPTS if connect_attempts is None else connect_attempts
    delay = _CONNECT_DELAY if connect_delay is None else connect_delay
    sock = _connect(upstream[0], upstream[1], attempts=attempts, delay=delay)
    try:
        probe = _PersistentProbe(sock, address)
        probe.baseline()
        return run_fuzz(
            craft_poll(address), probe, seed=seed, variants=variants, stop_on_failure=True
        )
    finally:
        sock.close()


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
            try:
                findings = fuzz_lab(
                    (upstream_host, upstream_port), address=address, seed=seed, variants=variants
                )
            except FuzzBaselineError as exc:
                # No proven live baseline means no verdict: never write a "clean" report.
                typer.echo(f"Fuzz baseline failed: {exc}", err=True)
                typer.echo(
                    "The PD must be reachable and idle (no other CP holding its single "
                    "connection); for the lab, bring it up with docker-compose.fuzz.yml.",
                    err=True,
                )
                raise typer.Exit(code=1) from exc

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

    The serial counterpart of ``_PersistentProbe``: write the malformed frame, write the valid poll,
    read one reply, and classify liveness. Kept dependency-light so the module imports with no
    pyserial at module scope; ``endpoint`` is the ``serial.Serial`` from ``open_physical_endpoint``.
    """

    def probe(mutated: bytes) -> bool:
        endpoint.write(mutated)  # type: ignore[attr-defined]
        endpoint.write(good_poll)  # type: ignore[attr-defined]
        return _reply_is_live(bytes(endpoint.read(_READ_SIZE)))  # type: ignore[attr-defined]

    return probe
