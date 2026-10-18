"""ATK-06 weak-key / SCBK-D testing over a captured Secure Channel handshake (D-01/D-02).

``which_weak_key`` extends the Phase 3 single-key ``secure_channel.uses_scbk_d`` into a
candidate-key dictionary sweep: for each named candidate in ``WEAK_KEYS`` it recomputes the
PD cryptogram from a captured CHLNG (RND.A) / CCRYPT (RND.B, cryptogram) handshake under
that key and returns the name of the first candidate that cryptographically verifies, or
``None`` when nothing matches. ``recompute_cryptogram`` performs the exact LibOSDP
derivation ``secure_channel.uses_scbk_d`` uses, reusing ``secure_channel.aes_ecb`` (PyCA) -
AES is never hand-rolled, because a wrong implementation would yield a false key verdict.

``run_weak_key`` is the pure library function (D-02): it extracts every observed RND.A and
every observed (RND.B, cryptogram) from a direction-tagged decoded frame sequence - exactly
as ``secure_channel._confirm_scbk_d`` does - does an all-pairs sweep (robust to the lab's
deterministic-RNG handshake-restart misalignment, where the two per-direction captures do
not line up one-to-one), and emits one HIGH ``Finding`` naming the verified key. A
no-match, an empty capture, or an incomplete handshake (no CHLNG or no CCRYPT observed) all
return ``[]`` - a true negative, never a default "weak" verdict. ``register`` adds the
``weak-key`` subcommand against the bundled lab (TCP) by default.

Dictionary content (SAFE-03, T-4-03): ``WEAK_KEYS`` holds only the public OSDP spec default
SCBK-D (``constants.SCBK_D``, 0x30..0x3F). The lab-arbitrary ``DOWNGRADE_SCBK`` (0x10..0x1F)
and any vendor or production key are NEVER shipped in it - including the downgrade key would
make the lab's "secure" downgrade profile falsely flag as weak.

Import discipline: this module stays importable with the standard library plus the
stdlib-only Phase 3 modules (codec/constants/transport). ``secure_channel`` (which pulls
cryptography), ``typer`` and ``report`` are imported lazily inside the functions that need
them, so importing the library does not require them.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from interlock.osdp import constants
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction, TCPTap
from interlock.plugin import Finding, Severity

if TYPE_CHECKING:
    import typer

# Lab defaults: listen in the attacker position and relay to the upstream PD, mirroring
# sniff. No serial path exists in this plan; the --physical consent gate arrives in 04-03.
_DEFAULT_LISTEN_PORT = 10000
_DEFAULT_UPSTREAM = ("pd", 10000)
_DEFAULT_MAX_FRAMES = 200

# ATK-06 free-text ATT&CK id (T1110 Brute Force - default/weak key); Phase 5 enriches it.
_TECHNIQUE = "T1110"

# Secure Channel random / cryptogram field sizes, from the OSDP handshake layout (mirrors
# secure_channel): RND.A and RND.B are 8 bytes each, the PD cryptogram is one 16-byte block.
_RND_LEN = 8
_CRYPTOGRAM_LEN = 16

# The weak-key dictionary: public OSDP spec defaults ONLY (SAFE-03 / T-4-03). SCBK-D is the
# specification default Secure Channel Base Key, a detection constant, not a vendor secret.
# NEVER add DOWNGRADE_SCBK (lab-arbitrary 0x10..0x1F) or any vendor/production key here.
WEAK_KEYS: dict[str, bytes] = {"SCBK-D": constants.SCBK_D}


def recompute_cryptogram(scbk: bytes, rnd_a: bytes, rnd_b: bytes) -> bytes:
    """Recompute the PD cryptogram under ``scbk`` exactly as ``secure_channel`` does.

    Derives the session encryption key and the expected PD cryptogram with the LibOSDP
    layout, reusing ``secure_channel.aes_ecb`` (PyCA) so AES is never hand-rolled::

        S-ENC    = AES-ECB(scbk, [0x01, 0x82] + RND.A[:6] + 0x00 * 8)
        expected = AES-ECB(S-ENC, RND.A[:8] || RND.B[:8])

    This is the single-key ``secure_channel.uses_scbk_d`` derivation generalised to an
    arbitrary candidate key, so the dictionary sweep stays cryptographically grounded.
    """
    from interlock.osdp.secure_channel import aes_ecb

    context = bytes([0x01, 0x82]) + rnd_a[:6] + b"\x00" * 8
    s_enc = aes_ecb(scbk, context)
    return aes_ecb(s_enc, rnd_a[:_RND_LEN] + rnd_b[:_RND_LEN])


def which_weak_key(rnd_a: bytes, rnd_b: bytes, pd_cryptogram: bytes) -> str | None:
    """Return the name of the ``WEAK_KEYS`` candidate that verifies, or ``None``.

    A candidate verifies only when its recomputed PD cryptogram equals the observed one;
    a non-verifying candidate is never reported (no-match is an explicit true negative,
    never a default-weak verdict). Mismatched field sizes yield ``None``.
    """
    if len(rnd_a) < _RND_LEN or len(rnd_b) < _RND_LEN or len(pd_cryptogram) != _CRYPTOGRAM_LEN:
        return None
    for name, key in WEAK_KEYS.items():
        if recompute_cryptogram(key, rnd_a, rnd_b) == pd_cryptogram:
            return name
    return None


def run_weak_key(
    frames: Iterable[tuple[Direction, OsdpFrame]],
    *,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Sweep a captured handshake against ``WEAK_KEYS`` and emit a Finding on a match.

    Extracts every CHLNG RND.A and every CCRYPT (RND.B, cryptogram) from ``frames`` (via
    ``secure_channel.challenge_random`` / ``ccrypt_reply``), then tries every RND.A against
    every (RND.B, cryptogram) - an all-pairs sweep robust to the lab's deterministic-RNG
    handshake-restart misalignment. A single AES-verifying pair is cryptographically
    unambiguous, so the first verifying candidate yields one HIGH ``Finding`` naming it.
    An empty capture or an incomplete handshake (no CHLNG or no CCRYPT) returns ``[]``.
    """
    from interlock.osdp.secure_channel import ccrypt_reply, challenge_random

    items = list(frames)
    challenge_randoms = [
        rnd_a
        for direction, frame in items
        if (rnd_a := challenge_random(direction, frame)) is not None
    ]
    replies = [
        reply for direction, frame in items if (reply := ccrypt_reply(direction, frame)) is not None
    ]
    if not challenge_randoms or not replies:
        return []  # empty / partial handshake: true negative, no Finding

    for rnd_a in challenge_randoms:
        for rnd_b, cryptogram in replies:
            name = which_weak_key(rnd_a, rnd_b, cryptogram)
            if name is not None:
                return [
                    Finding(
                        id="ATK-06-weak-key",
                        title=f"OSDP Secure Channel uses the known weak key {name}",
                        severity=Severity.HIGH,
                        evidence=(
                            f"The captured CHLNG/CCRYPT handshake recomputes the PD "
                            f"cryptogram under {name} ({WEAK_KEYS[name].hex()}), so the "
                            f"Secure Channel Base Key in use is the public spec default. "
                            f"Confirmed by recomputing the PD cryptogram via AES-128-ECB "
                            f"(PyCA), not a heuristic."
                        ),
                        attack_technique=technique,
                        remediation=(
                            "Replace the default Secure Channel Base Key (SCBK-D) with a "
                            "unique per-site key; the spec default provides no "
                            "confidentiality or authentication."
                        ),
                    )
                ]
    return []


def weak_key_lab(
    target_port: int,
    upstream: tuple[str, int],
    *,
    max_frames: int = _DEFAULT_MAX_FRAMES,
) -> list[Finding]:
    """Drive the read-only ``TCPTap`` against the lab bus and return weak-key Findings.

    Observes one bridged CP<->PD session, decodes up to ``max_frames`` frames with the same
    collector sniff uses, and folds them with ``run_weak_key``. Read-only pass-through only
    (SAFE-01): the tap forwards the exact bytes it reads and observes a copy.
    """
    from interlock.osdp.attacks.sniff import decode_chunks

    tap = TCPTap(target_port, upstream)
    frames = decode_chunks(tap.observe(), max_frames=max_frames)
    return run_weak_key(frames)


def register(app: typer.Typer) -> None:
    """Attach the ``weak-key`` subcommand to the ``osdp`` Typer group."""
    import typer

    from interlock import report

    @app.command("weak-key")
    def weak_key(
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
        """Test a captured Secure Channel handshake for a known weak key (SCBK-D)."""
        findings = weak_key_lab(port, (upstream_host, upstream_port), max_frames=max_frames)
        if not findings:
            typer.echo(
                "No weak key detected - no handshake verified under a known default key."
            )
        report.render_terminal(findings)
        report.write_markdown(findings, path=output)
        typer.echo(f"Wrote report to {output}")
