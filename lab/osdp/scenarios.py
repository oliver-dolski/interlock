"""Scenario profiles for the OSDP lab: the one validated LAB_SCENARIO selection path.

This module is the lab's configuration source of truth. It maps the ``LAB_SCENARIO``
value to a frozen profile descriptor that the PD and CP drivers build from. It mirrors
Phase 1's model layer (``plugin.py`` enum + frozen dataclass, ``registry.py`` allow-list
lookup) and deliberately imports nothing from ``osdp``: the fast contract test runs on the
host interpreter where LibOSDP is not installed, so the flags and capabilities are stored as
their LibOSDP attribute *names* (plain strings) and the drivers translate them to real
``osdp.LibFlag`` / ``osdp.Capability`` members at construction time.

Selection is exact string equality against a four-value allow-list, no case-folding and no
coercion (ASVS V5): an unknown, wrong-case, or whitespace-padded value raises ``KeyError``
and the caller fails closed, never defaulting to a scenario.

Confirmed Secure Channel mapping
--------------------------------
The flag semantics below were confirmed empirically (Wave-0 spike, 2026-10-17) against the
fixed image (libosdp==3.0.8) by reading ``docker compose logs`` at LibOSDP log level Info.
The observed per-profile log signatures are:

======================================================================================
profile     PD construction            CP construction       observed LibOSDP log
======================================================================================
cleartext   scbk=None, no flags        scbk=None             PD "SCBK not provided. PD is
            (install mode, but CP                             in INSTALL_MODE";
            never starts SC)                                  CP "Online; Without SC";
                                                              no "SC Active" anywhere.
--------------------------------------------------------------------------------------
sc-scbkd    scbk=None + InstallMode     scbk=SCBK-D           PD "SC Active with SCBK-D"
            (derives the default                              (osdp_pd.c:905) + "SC Active";
            SCBK-D key)                                       CP "SC active with SCBK-D. Set
                                                              SCBK" + "Online; With SC".
--------------------------------------------------------------------------------------
downgrade   scbk=DOWNGRADE_SCBK,        scbk=DOWNGRADE_SCBK,  PD "SC Active" (NOT the
            advertises                  enforce_secure=False  SCBK-D line, an explicit key
            CommunicationSecurity       (no EnforceSecure)    is used); CP "Online; With
            capability                                        SC"; no "ENFORCE_SECURE"
                                                              line, so the CP does not
                                                              refuse a clear-text fallback.
--------------------------------------------------------------------------------------
cve-replay  served by the vuln image (libosdp v2.4.0) and its own drivers; wired in plan
            02-04. The descriptor exists so every enum value round-trips through get(), but
            the fixed drivers and lab.sh do not run it on this image.
======================================================================================

Driver application contract (how the four fields map onto each role):
- ``scbk``           : the Secure Channel Base Key the CP holds. ``None`` means no key
                       (clear-text). The PD uses ``None`` instead whenever ``flags``
                       contains "InstallMode", so it derives the default SCBK-D itself.
- ``flags``          : LibOSDP ``LibFlag`` names applied to the PD's ``PDInfo`` (only
                       "InstallMode" is used by the fixed profiles).
- ``caps``           : the PD capabilities advertised, as (Capability name, compliance,
                       count) triples.
- ``enforce_secure`` : whether the CP adds ``LibFlag.EnforceSecure``; the whole point of
                       the downgrade profile is that this is False.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# OSDP specification default Secure Channel Base Key (SCBK-D), bytes 0x30..0x3F. This is the
# spec default documented in LibOSDP's source (src/osdp_sc.c), not a vendor production key
# (SAFE-03). The future attack module (ATK-06) must agree on this exact value.
SCBK_D = bytes(range(0x30, 0x40))

# A lab-arbitrary Secure Channel key for the downgrade profile. Distinct from SCBK-D so the
# downgrade bus comes up secure on an explicit key (no "with SCBK-D" log), isolating the
# vulnerability to the CP not enforcing Secure Channel. Not a vendor key (SAFE-03).
DOWNGRADE_SCBK = bytes(range(0x10, 0x20))

# PD capabilities shared by every fixed profile (mirrors the Phase 02-01 tracer PD).
_BASE_CAPS: tuple[tuple[str, int, int], ...] = (
    ("OutputControl", 1, 1),
    ("LEDControl", 2, 1),
    ("AudibleControl", 1, 1),
    ("TextOutput", 1, 1),
)


class Scenario(str, Enum):
    """The four LAB_SCENARIO values. Three run on the fixed image; cve-replay on the vuln image."""

    cleartext = "cleartext"
    sc_scbkd = "sc-scbkd"
    downgrade = "downgrade"
    cve_replay = "cve-replay"


@dataclass(frozen=True)
class Profile:
    """A frozen scenario descriptor the PD and CP drivers build their LibOSDP objects from."""

    scbk: bytes | None
    flags: tuple[str, ...]
    caps: tuple[tuple[str, int, int], ...]
    enforce_secure: bool


_PROFILES: dict[str, Profile] = {
    Scenario.cleartext.value: Profile(
        scbk=None,
        flags=(),
        caps=_BASE_CAPS,
        enforce_secure=False,
    ),
    Scenario.sc_scbkd.value: Profile(
        scbk=SCBK_D,
        flags=("InstallMode",),
        caps=_BASE_CAPS,
        enforce_secure=False,
    ),
    Scenario.downgrade.value: Profile(
        scbk=DOWNGRADE_SCBK,
        flags=(),
        caps=(*_BASE_CAPS, ("CommunicationSecurity", 1, 1)),
        enforce_secure=False,
    ),
    # Placeholder so cve-replay round-trips through get(); the real run lives on the vuln
    # image built in plan 02-04. The fixed drivers and lab.sh do not serve this profile.
    Scenario.cve_replay.value: Profile(
        scbk=SCBK_D,
        flags=(),
        caps=_BASE_CAPS,
        enforce_secure=False,
    ),
}


def valid_values() -> tuple[str, ...]:
    """Return the allow-list of valid LAB_SCENARIO values, in declaration order."""
    return tuple(scenario.value for scenario in Scenario)


def get(name: str) -> Profile:
    """Return the profile for ``name`` by exact match, or raise ``KeyError`` if unknown.

    Matching is exact string equality: no case-folding, no stripping. A value differing only
    by case ("CLEARTEXT") or surrounding whitespace (" cleartext ") is rejected as unknown,
    so callers fail closed instead of silently defaulting to a scenario (ASVS V5).
    """
    return _PROFILES[name]
