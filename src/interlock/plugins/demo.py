"""A trivial built-in plugin that proves the pipeline end to end.

It does nothing offensive. It exists to exercise registry, contract, and report
together, and to be the worked example the authoring guide references.
"""

from __future__ import annotations

from interlock.plugin import Finding, Severity


class DemoPlugin:
    """A sample plugin returning a single canned finding."""

    name = "demo"
    summary = "A trivial sample plugin that returns one canned finding."

    def run(
        self,
        target: str | None = None,
        options: dict[str, object] | None = None,
    ) -> list[Finding]:
        return [
            Finding(
                id="DEMO-001",
                title="interlock plugin pipeline is wired end to end",
                severity=Severity.INFO,
                evidence="The demo plugin was discovered, loaded, and executed by the core.",
                attack_technique="T1200",
                remediation="None required; this is a self-test of the platform core.",
            )
        ]
