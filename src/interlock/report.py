"""Shared, plugin-agnostic report generation.

Renders a list of findings to the terminal as a rich table, to a Markdown file
and to a JSON file (``schema_version`` plus the findings in their
``finding_to_dict`` form). Every written report carries
``AUTHORIZED_USE_NOTICE``; neither writer can turn it off. HTML output is
deferred to a later phase.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from interlock.plugin import Finding, finding_to_dict

_console = Console()

AUTHORIZED_USE_NOTICE = (
    "Authorized use only. interlock runs against its bundled, network-isolated lab by "
    "default. Use it on real equipment only with the owner's written authorization; "
    "physical mode is gated by --physical, a disclaimer and a typed scope confirmation. "
    "This tool ships no vendor default production keys; the only built-in key is the "
    "public OSDP specification default SCBK-D."
)

JSON_SCHEMA_VERSION = 1

_JSON_RESERVED_KEYS = frozenset({"schema_version", "notice", "findings"})


def render_terminal(findings: list[Finding]) -> None:
    """Print findings as a rich table to the terminal."""
    table = Table(title="interlock findings")
    table.add_column("id", style="bold")
    table.add_column("severity")
    table.add_column("title")
    table.add_column("ATT&CK")
    table.add_column("remediation")

    for finding in findings:
        table.add_row(
            finding.id,
            finding.severity.value,
            finding.title,
            finding.attack_technique,
            finding.remediation,
        )

    _console.print(table)


def _technique(technique_id: str, technique_names: Mapping[str, str] | None) -> str:
    if technique_names is not None and technique_id in technique_names:
        return f"{technique_id} ({technique_names[technique_id]})"
    return technique_id


def write_markdown(
    findings: list[Finding],
    path: Path,
    *,
    title: str = "interlock findings",
    preamble: Sequence[str] = (),
    appendix: Sequence[str] = (),
    technique_names: Mapping[str, str] | None = None,
) -> None:
    """Write findings as a Markdown report to ``path``, creating parents as needed.

    The report opens with ``# {title}`` and the authorized-use notice, then the
    ``preamble`` lines, one section per finding and the ``appendix`` lines.
    ``technique_names`` maps an ATT&CK id to its name, rendered as "ID (Name)".

    The content is written as plain text only; the path is used exactly as given
    (no shell expansion, no resolution beyond it) per threat T-01-02.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = [f"# {title}", "", AUTHORIZED_USE_NOTICE, ""]
    lines.extend(preamble)
    for finding in findings:
        lines.append(f"## {finding.id}: {finding.title}")
        lines.append("")
        lines.append(f"- **Severity:** {finding.severity.value}")
        lines.append(
            f"- **ATT&CK technique:** {_technique(finding.attack_technique, technique_names)}"
        )
        if finding.attack_technique_ics is not None:
            lines.append(
                f"- **ATT&CK for ICS:** "
                f"{_technique(finding.attack_technique_ics, technique_names)}"
            )
        lines.append(f"- **Evidence:** {finding.evidence}")
        lines.append(f"- **Remediation:** {finding.remediation}")
        lines.append("")
    lines.extend(appendix)

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))


def write_json(
    findings: list[Finding],
    path: Path,
    *,
    metadata: Mapping[str, object] | None = None,
) -> None:
    """Write findings as a JSON report to ``path``, creating parents as needed.

    The document is ``{"schema_version", "notice", "findings"}`` merged with
    ``metadata``; a metadata key that collides with one of those three raises
    ``ValueError``. The path is used exactly as given, as for ``write_markdown``.
    """
    extra = dict(metadata) if metadata is not None else {}
    collisions = _JSON_RESERVED_KEYS & extra.keys()
    if collisions:
        raise ValueError(f"metadata keys collide with reserved report keys: {sorted(collisions)}")

    document: dict[str, object] = {
        **extra,
        "schema_version": JSON_SCHEMA_VERSION,
        "notice": AUTHORIZED_USE_NOTICE,
        "findings": [finding_to_dict(finding) for finding in findings],
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
