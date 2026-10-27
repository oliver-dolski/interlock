"""The minimal third-party interlock plugin from the plugin-authoring guide.

This file is copied into docs/plugin-authoring.md verbatim, and a test keeps the two
identical. It shows both halves of the contract a package can declare in its own
pyproject.toml:

- ``ExamplePlugin``, registered in the ``interlock.plugins`` group: a class with a
  ``name``, a one-line ``summary`` and a ``run`` method returning findings.
- ``build_example_app``, registered in the ``interlock.commands`` group: a
  zero-argument factory returning the ``typer.Typer`` attached as ``interlock example``.

The example does nothing offensive and touches no network, port or device. It returns
one informational finding and prints text.
"""

from __future__ import annotations

import typer

from interlock.plugin import Finding, Severity


class ExamplePlugin:
    """A plugin that returns one informational finding."""

    name = "example"
    summary = "The minimal plugin from the plugin-authoring guide."

    def run(
        self,
        target: str | None = None,
        options: dict[str, object] | None = None,
    ) -> list[Finding]:
        return [
            Finding(
                id="EXAMPLE-001",
                title="the example plugin was discovered and run",
                severity=Severity.INFO,
                evidence="interlock loaded this plugin from its entry point; it has no effect.",
                attack_technique="T1200",
                remediation="None required; this is a self-test with no effect.",
            )
        ]


def build_example_app() -> typer.Typer:
    """Return the ``interlock example`` command group."""
    app = typer.Typer(no_args_is_help=True, help="The example plugin's commands.")

    @app.command()
    def info() -> None:
        """Print what the example plugin is."""
        typer.echo(ExamplePlugin.summary)

    return app
