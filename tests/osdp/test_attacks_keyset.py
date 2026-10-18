"""Host proof of ATK-04 install-mode / KEYSET SCBK extraction over the committed exchange.

Task 1's @lab spike confirmed the lab's high-level ControlPanel/PeripheralDevice API DOES
drive ``CMD_KEYSET`` (0x75) on the sc-scbkd install-mode wire and committed the per-direction
fixtures. These host-only tests (no lab marker, no Docker) load that real exchange and assert
the SCBK recovery read purely from the wire:

- the cp->pd side carries the CHLNG (RND.A) and the CMD_KEYSET encrypted under SCS_17;
- the pd->cp side carries the CCRYPT (for ``uses_scbk_d`` confirmation) and the REPLY_RMAC_I
  whose R-MAC is the command IV (``NOT(R-MAC)``) the SCBK-D session key decrypts the payload with.

Recovery derives S-ENC via ``secure_channel.aes_ecb`` under the spec default SCBK-D, decrypts
the KEYSET payload, reads the enrolled key, and confirms the SCBK-D case via
``secure_channel.uses_scbk_d``. The flagged-assumption negatives (no CMD_KEYSET -> [], an
unconfirmable channel -> []) and the SAFE-03 display rule (only the public spec default SCBK-D
is ever shown; a non-default recovered key is redacted) are covered too.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from interlock.osdp import codec, constants, framer
from interlock.osdp.attacks.keyset import (
    craft_keyset,
    recover_scbk,
    run_keyset,
    trigger_keyset,
)
from interlock.osdp.constants import SCBK_D
from interlock.osdp.secure_channel import aes_ecb, ccrypt_reply, challenge_random
from interlock.osdp.transport import Direction

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# A non-default, non-lab key used only to prove the SAFE-03 redaction branch (never shipped).
_NONDEFAULT_KEY = bytes(range(0x40, 0x50))


def _load_session(profile: str) -> list[tuple[Direction, codec.OsdpFrame]]:
    """Frame and decode both per-direction vectors of ``profile`` into tagged pairs."""
    session: list[tuple[Direction, codec.OsdpFrame]] = []
    for direction, suffix in (
        (Direction.cp_to_pd, "cp2pd"),
        (Direction.pd_to_cp, "pd2cp"),
    ):
        raw = (FIXTURES_DIR / f"{profile}_{suffix}.cap").read_bytes()
        assert raw, f"{profile}_{suffix}.cap is empty; regenerate it from the lab"
        session.extend((direction, codec.decode(frame)) for frame in framer.iter_frames(raw))
    return session


def test_run_keyset_recovers_scbk_d_from_the_install_mode_exchange() -> None:
    """run_keyset reads the enrolled SCBK-D from the real KEYSET exchange and confirms it."""
    findings = run_keyset(_load_session("keyset"))
    assert len(findings) == 1, findings
    finding = findings[0]
    assert finding.id == "ATK-04-keyset"
    assert finding.severity.value == "high"
    # SAFE-03: the recovered key IS the public spec default, so its bytes are shown.
    assert SCBK_D.hex() in finding.evidence
    assert finding.attack_technique


def test_recover_scbk_reads_the_enrolled_key_from_the_payload() -> None:
    """The low-level recovery returns exactly SCBK-D for the right RND.A / R-MAC pair."""
    session = _load_session("keyset")
    keyset_frame = next(
        f for d, f in session if d is Direction.cp_to_pd and f.code == constants.CMD_KEYSET
    )
    rnd_as = [r for d, f in session if (r := challenge_random(d, f)) is not None]
    rmacs = [
        f.data[:16]
        for d, f in session
        if d is Direction.pd_to_cp and f.code == constants.REPLY_RMAC_I and len(f.data) >= 16
    ]
    recovered = [
        key
        for ra in rnd_as
        for rm in rmacs
        if (key := recover_scbk(keyset_frame, ra, rm)) is not None
    ]
    assert SCBK_D in recovered, "expected to read SCBK-D out of the KEYSET payload"


def test_run_keyset_returns_empty_without_a_keyset_frame() -> None:
    """A capture with no CMD_KEYSET (and an empty capture) yields no Finding (true negative)."""
    assert run_keyset(_load_session("cleartext")) == []
    assert run_keyset([]) == []


def test_run_keyset_returns_empty_on_a_non_scbk_d_channel() -> None:
    """The downgrade capture (explicit non-default key, no CMD_KEYSET) never flags a recovery."""
    assert run_keyset(_load_session("downgrade")) == []


def test_run_keyset_returns_empty_when_the_channel_is_not_confirmable_scbk_d() -> None:
    """CMD_KEYSET present but the CCRYPT stripped -> no SCBK-D confirmation -> [] (no fabrication)."""
    session = [
        (d, f)
        for d, f in _load_session("keyset")
        if not (d is Direction.pd_to_cp and f.code == constants.REPLY_CCRYPT)
    ]
    assert any(
        d is Direction.cp_to_pd and f.code == constants.CMD_KEYSET for d, f in session
    ), "the stripped session must still carry the CMD_KEYSET frame"
    assert run_keyset(session) == []


def _confirming_rnd_a(session: list[tuple[Direction, codec.OsdpFrame]]) -> bytes:
    """Return a RND.A whose handshake recomputes under SCBK-D (the recoverable channel)."""
    from interlock.osdp.secure_channel import uses_scbk_d

    ccrypts = [c for d, f in session if (c := ccrypt_reply(d, f)) is not None]
    for d, f in session:
        rnd_a = challenge_random(d, f)
        if rnd_a is not None and any(uses_scbk_d(rnd_a, b, c) for b, c in ccrypts):
            return rnd_a
    raise AssertionError("no SCBK-D-confirming RND.A in the keyset session")


def test_run_keyset_redacts_a_recovered_non_default_key() -> None:
    """A non-default enrolled key is still a HIGH Finding but its bytes are withheld (SAFE-03)."""
    session = _load_session("keyset")
    rnd_a = _confirming_rnd_a(session)
    rmac = next(
        f.data[:16]
        for d, f in session
        if d is Direction.pd_to_cp and f.code == constants.REPLY_RMAC_I and len(f.data) >= 16
    )
    s_enc = aes_ecb(constants.SCBK_D, bytes([0x01, 0x82]) + rnd_a[:6] + b"\x00" * 8)
    iv = bytes(b ^ 0xFF for b in rmac)
    # Craft a KEYSET plaintext enrolling a NON-default key, padded exactly as OSDP SC does.
    plaintext = bytes([0x01, len(_NONDEFAULT_KEY)]) + _NONDEFAULT_KEY + b"\x80"
    plaintext += b"\x00" * (-len(plaintext) % 16)
    encryptor = Cipher(algorithms.AES(s_enc), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    forged = codec.OsdpFrame(
        had_mark=True,
        address=0x65 | constants.ADDR_REPLY_FLAG & 0,  # reply flag already clear for a command
        control=0x0E,
        scb=bytes([0x02, constants.SCS_17]),
        code=constants.CMD_KEYSET,
        data=ciphertext + b"\x00\x00\x00\x00",  # 4-byte MAC tail (content not read by recovery)
        use_crc=True,
    )
    patched = [
        (d, f)
        for d, f in session
        if not (d is Direction.cp_to_pd and f.code == constants.CMD_KEYSET)
    ]
    patched.append((Direction.cp_to_pd, forged))

    findings = run_keyset(patched)
    assert len(findings) == 1, findings
    evidence = findings[0].evidence
    assert _NONDEFAULT_KEY.hex() not in evidence, "a non-default key must never be displayed"
    assert "withheld" in evidence.lower() or "redacted" in evidence.lower()


def test_trigger_keyset_injects_a_wellformed_cmd_keyset_via_the_seam() -> None:
    """trigger_keyset crafts a valid CMD_KEYSET, sends it through the seam, returns the reply."""
    sent: dict[str, bytes] = {}

    def seam(frame_bytes: bytes) -> bytes:
        sent["frame"] = frame_bytes
        return b"reply-bytes"

    reply = trigger_keyset(seam, 101)
    assert reply == b"reply-bytes"
    frame = codec.decode(sent["frame"])
    assert frame.code == constants.CMD_KEYSET
    assert frame.address == 101  # command cp->pd: reply flag cleared


def test_craft_keyset_only_ever_uses_the_spec_default_scbk_d() -> None:
    """The default injected key is the public spec default SCBK-D (SAFE-03)."""
    frame = craft_keyset(101)
    # payload = key_type(1) + key_length(1) + key; the key bytes are exactly SCBK-D.
    assert frame.data[2:] == SCBK_D
    assert frame.data[1] == len(SCBK_D)


def test_keyset_subcommand_is_discovered_under_the_osdp_group() -> None:
    """build_osdp_app() auto-discovers the keyset subcommand via register()."""
    from typer.testing import CliRunner

    from interlock.cli import app

    result = CliRunner().invoke(app, ["osdp", "--help"])
    assert result.exit_code == 0
    assert "keyset" in result.output
