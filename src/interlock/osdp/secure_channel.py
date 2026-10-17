"""Secure Channel state detection from observed OSDP traffic (OSDP-03).

Reads clear-text vs Secure Channel from the wire alone: the SCB control bit and
the SCS stage codes carried in each frame's Secure Control Block. SCBK-D (the
spec default key) is confirmed by recomputing the PD cryptogram from the plaintext
CHLNG/CCRYPT handshake. This module never reads a LibOSDP log line or any
lab-internal signal, so the verdict is a pure function of the decoded bytes (plus,
for SCBK-D, the known OSDP specification default key).

Wire signatures
---------------
================  ===================================================================
verdict           what the stream shows
================  ===================================================================
clear-text        no frame in the session carries the SCB control bit (0x08) and no
                  SCS code ever appears. (cleartext profile: POLL/ACK, CMD_ID/CMD_CAP
                  only, every control byte with bit 0x08 clear.)
Secure Channel    at least one frame carries the SCB bit, or an SCS code (0x11..0x18)
                  appears. The handshake stages (SCS_11..SCS_14) and the data modes
                  (MAC-only SCS_15/16, MAC and encryption SCS_17/18) are recorded as
                  the set of SCS codes seen.
SCBK-D confirmed  a captured CHLNG (RND.A) plus CCRYPT (RND.B, PD cryptogram)
                  handshake recomputes the PD cryptogram under SCBK-D, so SCBK-D is
                  in use. (downgrade profile: SCB present but no handshake verifies
                  under SCBK-D, because an explicit non-default key 0x10..0x1F is in
                  use.)
================  ===================================================================
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from interlock.osdp import constants
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction

# The SCS stage codes that may appear as the type byte (scb[1]) of a Secure Control
# Block: handshake stages 0x11..0x14, then the data-protection modes 0x15..0x18.
_SCS_RANGE = range(constants.SCS_11, constants.SCS_18 + 1)

# Secure Channel random / cryptogram field sizes, from the OSDP handshake layout.
# VERIFIED: src/osdp_pd.c @ v3.0.8 (REPLY_CCRYPT builder) and src/osdp_sc.c @ v3.0.8
# (osdp_compute_session_keys / osdp_compute_pd_cryptogram).
_RND_LEN = 8  # RND.A (cp_random) and RND.B (pd_random) are each 8 bytes
_CRYPTOGRAM_LEN = 16  # the PD cryptogram is one 16-byte AES block
_CCRYPT_UID_LEN = 8  # REPLY_CCRYPT carries cUID(8) || RND.B(8) || PD cryptogram(16)


def aes_ecb(key: bytes, block: bytes) -> bytes:
    """Return AES-128-ECB(``key``, ``block``) using the 03-01 crypto library.

    The only AES source is PyCA ``cryptography`` (resolved in 03-01); AES is never
    hand-rolled, because a wrong implementation would yield a false SCBK-D verdict.
    This mirrors LibOSDP ``osdp_encrypt(key, NULL, ...)`` which, with a NULL IV, is
    single-block AES-128-ECB (VERIFIED: src/crypto/{openssl,tinyaes}.c @ v3.0.8).
    """
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def challenge_random(direction: Direction, frame: OsdpFrame) -> bytes | None:
    """Return RND.A from a CMD_CHLNG frame, or None if this is not one.

    CMD_CHLNG and REPLY_CCRYPT share code 0x76, so the direction disambiguates them:
    CMD_CHLNG travels cp->pd and its payload is the 8-byte CP random RND.A.
    VERIFIED: src/osdp_pd.c @ v3.0.8 (CMD_CHLNG stores buf+pos into cp_random[8]).
    """
    if direction is not Direction.cp_to_pd or frame.code != constants.CMD_CHLNG:
        return None
    if len(frame.data) < _RND_LEN:
        return None
    return frame.data[:_RND_LEN]


def ccrypt_reply(direction: Direction, frame: OsdpFrame) -> tuple[bytes, bytes] | None:
    """Return (RND.B, PD cryptogram) from a REPLY_CCRYPT frame, or None otherwise.

    REPLY_CCRYPT travels pd->cp (telling it apart from CMD_CHLNG, same code 0x76);
    its payload is cUID(8) || RND.B(8) || PD cryptogram(16).
    VERIFIED: src/osdp_pd.c @ v3.0.8 (REPLY_CCRYPT builder).
    """
    if direction is not Direction.pd_to_cp or frame.code != constants.REPLY_CCRYPT:
        return None
    needed = _CCRYPT_UID_LEN + _RND_LEN + _CRYPTOGRAM_LEN
    if len(frame.data) < needed:
        return None
    rnd_b = frame.data[_CCRYPT_UID_LEN : _CCRYPT_UID_LEN + _RND_LEN]
    cryptogram = frame.data[_CCRYPT_UID_LEN + _RND_LEN : needed]
    return rnd_b, cryptogram


def uses_scbk_d(rnd_a: bytes, rnd_b: bytes, pd_cryptogram: bytes) -> bool:
    """Return True if the observed PD cryptogram recomputes under SCBK-D.

    Derives the session encryption key and the expected PD cryptogram exactly as
    LibOSDP does, then compares to the observed cryptogram:

        S-ENC    = AES-ECB(SCBK_D, [0x01, 0x82] + RND.A[:6] + 0x00 * 8)
        expected = AES-ECB(S-ENC, RND.A || RND.B)

    VERIFIED: src/osdp_sc.c @ v3.0.8 (osdp_compute_session_keys builds the S-ENC
    context block [0x01,0x82] + cp_random[0..5] + zero fill; osdp_compute_pd_cryptogram
    is AES-ECB over cp_random[8] || pd_random[8]). SCBK_D is the known OSDP spec
    default (a detection constant, SAFE-03), never a vendor production secret; this is
    detection, not authentication.
    """
    if len(rnd_a) < _RND_LEN or len(rnd_b) < _RND_LEN or len(pd_cryptogram) != _CRYPTOGRAM_LEN:
        return False
    context = bytes([0x01, 0x82]) + rnd_a[:6] + b"\x00" * 8
    s_enc = aes_ecb(constants.SCBK_D, context)
    expected = aes_ecb(s_enc, rnd_a[:_RND_LEN] + rnd_b[:_RND_LEN])
    return expected == pd_cryptogram


@dataclass(frozen=True)
class ChannelState:
    """The Secure Channel verdict for one observed cp<->pd session.

    ``secure`` is True when any Secure Channel marker was seen (the SCB control bit
    or an SCS code); its negation is a clear-text session. ``scbk_d_confirmed`` is
    True only when a captured plaintext handshake recomputes the PD cryptogram under
    SCBK-D. ``scb_seen`` and ``scs_codes`` expose the raw observations the verdict is
    folded from, so a caller can see exactly which stages the stream carried.
    """

    secure: bool
    scbk_d_confirmed: bool
    scb_seen: bool
    scs_codes: frozenset[int]

    @property
    def clear_text(self) -> bool:
        """True when no Secure Channel marker was ever observed in the session."""
        return not self.secure


def detect_state(frames: Iterable[tuple[Direction, OsdpFrame]]) -> ChannelState:
    """Fold a direction-tagged frame sequence into a Secure Channel verdict.

    A session is clear-text when no frame carries the SCB control bit (0x08) and no
    SCS code appears; it is Secure Channel as soon as either shows up. The SCS stage
    codes seen (handshake 0x11..0x14, MAC-only 0x15/0x16, MAC and encryption
    0x17/0x18) are recorded. SCBK-D is confirmed when a captured CHLNG/CCRYPT
    handshake recomputes the PD cryptogram under the spec default key. Everything is
    read from the decoded wire bytes only.
    """
    items = list(frames)
    scb_seen = False
    scs_codes: set[int] = set()
    for _direction, frame in items:
        if frame.control & constants.PKT_CONTROL_SCB:
            scb_seen = True
        if len(frame.scb) >= 2 and frame.scb[1] in _SCS_RANGE:
            scs_codes.add(frame.scb[1])
    secure = scb_seen or bool(scs_codes)
    return ChannelState(
        secure=secure,
        scbk_d_confirmed=_confirm_scbk_d(items),
        scb_seen=scb_seen,
        scs_codes=frozenset(scs_codes),
    )


def _confirm_scbk_d(items: list[tuple[Direction, OsdpFrame]]) -> bool:
    """Return True if any captured CHLNG/CCRYPT pair recomputes under SCBK-D.

    The two per-direction captures do not line up one-to-one (the lab's PD and CP use
    the same deterministic RNG, and a session can restart), so every observed RND.A is
    tried against every observed (RND.B, PD cryptogram). A match is cryptographically
    unambiguous - AES makes a wrong pairing verifying by chance infeasible - so one
    verifying pair proves SCBK-D is in use; the downgrade profile (explicit non-default
    key) yields no verifying pair.
    """
    challenge_randoms = [
        rnd_a
        for direction, frame in items
        if (rnd_a := challenge_random(direction, frame)) is not None
    ]
    replies = [
        reply for direction, frame in items if (reply := ccrypt_reply(direction, frame)) is not None
    ]
    return any(
        uses_scbk_d(rnd_a, rnd_b, cryptogram)
        for rnd_a in challenge_randoms
        for rnd_b, cryptogram in replies
    )
