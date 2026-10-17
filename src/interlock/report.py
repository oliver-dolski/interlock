"""Shared, plugin-agnostic report generation.

Renders a list of findings to the terminal as a rich table and to a Markdown
file. HTML output is deferred to a later phase.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from interlock.plugin import Finding

_console = Console()


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


def write_markdown(findings: list[Finding], path: Path) -> None:
    """Write findings as a Markdown report to ``path``, creating parents as needed.

    The content is written as plain text only; the path is used exactly as given
    (no shell expansion, no resolution beyond it) per threat T-01-02.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = ["# interlock findings", ""]
    for finding in findings:
        lines.append(f"## {finding.id}: {finding.title}")
        lines.append("")
        lines.append(f"- **Severity:** {finding.severity.value}")
        lines.append(f"- **ATT&CK technique:** {finding.attack_technique}")
        lines.append(f"- **Evidence:** {finding.evidence}")
        lines.append(f"- **Remediation:** {finding.remediation}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
