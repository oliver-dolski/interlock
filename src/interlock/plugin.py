"""The plugin contract every interlock module implements.

External authors import from this one module: the ``Finding`` dataclass, the
``Severity`` enum, and the ``Plugin`` protocol. Keeping the surface small and
stable here means a new protocol module is an additive package, not a fork.
"""

from __future__ import annotations

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

    ``attack_technique`` is a free-form MITRE ATT&CK technique id (for example
    "T1200") for now; richer ATT&CK modeling lands in a later phase.
    """

    id: str
    title: str
    severity: Severity
    evidence: str
    attack_technique: str
    remediation: str


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
