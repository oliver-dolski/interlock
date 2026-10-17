"""Secure Channel state detection from observed OSDP traffic (OSDP-03).

Reads clear-text vs Secure Channel from the wire alone: the SCB control bit and
the SCS stage codes carried in each frame's Secure Control Block. SCBK-D (the
spec default key) confirmation by cryptogram recomputation is added in a second
step; this module never reads a LibOSDP log line or any lab-internal signal, so
the verdict is a pure function of the decoded bytes (plus, for SCBK-D, the known
OSDP specification default key).

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
                  use.) Filled by the SCBK-D recomputation step below.
================  ===================================================================
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from interlock.osdp import constants
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction

# The SCS stage codes that may appear as the type byte (scb[1]) of a Secure Control
# Block: handshake stages 0x11..0x14, then the data-protection modes 0x15..0x18.
_SCS_RANGE = range(constants.SCS_11, constants.SCS_18 + 1)


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
    0x17/0x18) are recorded. Everything is read from the decoded wire bytes only.
    """
    scb_seen = False
    scs_codes: set[int] = set()
    for _direction, frame in frames:
        if frame.control & constants.PKT_CONTROL_SCB:
            scb_seen = True
        if len(frame.scb) >= 2 and frame.scb[1] in _SCS_RANGE:
            scs_codes.add(frame.scb[1])
    secure = scb_seen or bool(scs_codes)
    # SCBK-D confirmation is added by the recomputation step below; clear-text and
    # explicit non-default-key sessions keep this False.
    return ChannelState(
        secure=secure,
        scbk_d_confirmed=False,
        scb_seen=scb_seen,
        scs_codes=frozenset(scs_codes),
    )
