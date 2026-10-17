"""The canonical worked example of an interlock plugin.

This module is the template the plugin-authoring guide points to. A plugin is
three things, all shown below:

1. A ``name`` attribute: the short id interlock lists and runs it by.
2. A ``summary`` attribute: a one-line description shown by ``interlock plugins``.
3. A ``run(target, options) -> list[Finding]`` method: the work, returning
   structured findings from the shared ``interlock.plugin`` model.

A plugin reaches interlock by being installed: ship it as a package that
registers an entry point in the ``interlock.plugins`` group (see this project's
``pyproject.toml`` for the entry that exposes ``DemoPlugin``). Installing a
package is how a third party adds a protocol with no fork of interlock.

The demo does nothing offensive; it returns a single canned finding to prove the
registry, contract, and report pipeline end to end.
"""

from __future__ import annotations

from interlock.plugin import Finding, Severity


class DemoPlugin:
    """A sample plugin returning a single canned finding.

    Copy this class as the starting point for a real plugin: set ``name`` and
    ``summary``, then build the list of ``Finding`` your ``run`` method returns.
    Each ``Finding`` carries ``id``, ``title``, ``severity`` (a ``Severity``
    member), ``evidence``, ``attack_technique`` (a free-form MITRE ATT&CK id for
    now), and ``remediation``.
    """

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
