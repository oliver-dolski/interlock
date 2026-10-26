"""The single source of truth for the MITRE ATT&CK ids the OSDP attacks cite.

Every attack module reads its technique ids from ``MAPPINGS`` instead of carrying its
own literal, so a renumbering in a future ATT&CK release is a change to this one file.
The ids are pinned to ATT&CK v20.0 (``ATTACK_VERSION``), which the assessment report
records next to the findings.

Enterprise is the primary matrix: a finding's ``attack_technique`` is always the
Enterprise id. ICS is only an optional secondary mapping (``attack_technique_ics``),
used where an ICS technique genuinely fits, because OSDP is physical access control,
not an industrial process. Since ATT&CK v19 some ICS techniques are sub-techniques
numbered T1xxx.xxx, so both matrices share the id shape ``T`` + 4 digits with an
optional ``.`` + 3 digit sub-technique.

``ACCESS_VECTOR`` is the engagement-level technique, not a per-finding one: every bus
attack presumes a device physically added to the RS-485 segment (T1200).

The fuzz, spoof, replay and downgrade modules run inside the minimal lab image, so this
module must stay standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass

ATTACK_VERSION = "20.0"


@dataclass(frozen=True)
class Technique:
    """One attack's Enterprise (primary) and optional ICS (secondary) technique."""

    enterprise: str
    enterprise_name: str
    ics: str | None
    ics_name: str | None


MAPPINGS: dict[str, Technique] = {
    "sniff": Technique("T1040", "Network Sniffing", "T0842", "Network Sniffing"),
    "enumerate": Technique(
        "T1018",
        "Remote System Discovery",
        "T0888",
        "Remote System Information Discovery",
    ),
    "weak-key": Technique(
        "T1110.002",
        "Brute Force: Password Cracking",
        "T1694.001",
        "Insecure Credentials: Default Credentials",
    ),
    "keyset": Technique("T1040", "Network Sniffing", "T0842", "Network Sniffing"),
    "downgrade": Technique("T1689", "Downgrade Attack", "T0830", "Adversary-in-the-Middle"),
    "replay": Technique(
        "T1557",
        "Adversary-in-the-Middle",
        "T1692.002",
        "Unauthorized Message: Reporting Message",
    ),
    "cve-2024-52288": Technique(
        "T1557", "Adversary-in-the-Middle", "T0830", "Adversary-in-the-Middle"
    ),
    "spoof": Technique(
        "T1565.002",
        "Data Manipulation: Transmitted Data Manipulation",
        "T1692.001",
        "Unauthorized Message: Command Message",
    ),
    "fuzz": Technique(
        "T1499.004",
        "Endpoint Denial of Service: Application or System Exploitation",
        "T0814",
        "Denial of Service",
    ),
}

ACCESS_VECTOR = Technique("T1200", "Hardware Additions", None, None)


def technique_names() -> dict[str, str]:
    """Return every Enterprise and ICS id in ``MAPPINGS`` and ``ACCESS_VECTOR`` -> its name.

    The report renders a finding's technique as "ID (Name)" with this mapping.
    """
    names: dict[str, str] = {}
    for technique in (*MAPPINGS.values(), ACCESS_VECTOR):
        names[technique.enterprise] = technique.enterprise_name
        if technique.ics is not None and technique.ics_name is not None:
            names[technique.ics] = technique.ics_name
    return names
