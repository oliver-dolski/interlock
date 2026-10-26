"""The plugin contract every interlock module implements.

External authors import from this one module: the ``Finding`` dataclass, the
``Severity`` enum, and the ``Plugin`` protocol. Keeping the surface small and
stable here means a new protocol module is an additive package, not a fork.

``finding_to_dict`` and ``finding_from_dict`` give findings a strict, plain
dict form for JSON reports and for findings read back from lab containers.
This module is imported inside the minimal lab images, so it stays standard
library only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable


class Severity(str, Enum):
    """Finding severity, ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    """A single structured result produced by a plugin.

    ``attack_technique`` is the primary MITRE ATT&CK Enterprise technique id
    (for example "T1200"). ``attack_technique_ics`` is an optional secondary
    MITRE ATT&CK for ICS technique id (for example "T0830"); it defaults to
    ``None`` so plugins that do not set it keep working unchanged.
    """

    id: str
    title: str
    severity: Severity
    evidence: str
    attack_technique: str
    remediation: str
    attack_technique_ics: str | None = None


_FINDING_KEYS = frozenset(
    {
        "id",
        "title",
        "severity",
        "evidence",
        "attack_technique",
        "attack_technique_ics",
        "remediation",
    }
)


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Return ``finding`` as a plain dict with the severity as its string value."""
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "evidence": finding.evidence,
        "attack_technique": finding.attack_technique,
        "attack_technique_ics": finding.attack_technique_ics,
        "remediation": finding.remediation,
    }


def finding_from_dict(data: Mapping[str, object]) -> Finding:
    """Parse a finding document produced by ``finding_to_dict``.

    The parser is strict: the key set must match exactly, every value must be a
    ``str`` (``attack_technique_ics`` may also be ``None``) and ``severity`` must
    be a known ``Severity`` value. Any violation raises ``ValueError``.
    """
    if not isinstance(data, Mapping):
        # ValueError, not TypeError: one exception type for every malformed document.
        raise ValueError("finding document must be a mapping")  # noqa: TRY004
    keys = set(data.keys())
    missing = _FINDING_KEYS - keys
    if missing:
        raise ValueError(f"finding document is missing keys: {sorted(missing)}")
    unknown = keys - _FINDING_KEYS
    if unknown:
        raise ValueError(f"finding document has unknown keys: {sorted(map(str, unknown))}")

    values: dict[str, str] = {}
    for key in _FINDING_KEYS - {"attack_technique_ics"}:
        value = data[key]
        if not isinstance(value, str):
            message = f"finding field {key!r} must be a str, got {type(value).__name__}"
            raise ValueError(message)  # noqa: TRY004 - one exception type, see above
        values[key] = value

    ics = data["attack_technique_ics"]
    if ics is not None and not isinstance(ics, str):
        raise ValueError(
            f"finding field 'attack_technique_ics' must be a str or None, got {type(ics).__name__}"
        )

    try:
        severity = Severity(values["severity"])
    except ValueError:
        raise ValueError(f"unknown finding severity: {values['severity']!r}") from None

    return Finding(
        id=values["id"],
        title=values["title"],
        severity=severity,
        evidence=values["evidence"],
        attack_technique=values["attack_technique"],
        remediation=values["remediation"],
        attack_technique_ics=ics,
    )


@runtime_checkable
class Plugin(Protocol):
    """The contract a plugin object must satisfy to be discoverable and runnable."""

    name: str
    summary: str

    def run(
        self,
        target: str | None = None,
        options: dict[str, object] | None = None,
    ) -> list[Finding]:
        """Run the plugin and return its findings."""
        ...
