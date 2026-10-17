"""The interlock command-line interface (Typer).

Commands:
- ``interlock plugins``: list discovered plugins.
- ``interlock run <plugin>``: run a plugin, render its findings to the terminal,
  and write a Markdown report.
"""

from __future__ import annotations

from pathlib import Path

import typer

from interlock import registry, report

app = typer.Typer(help="Extensible red-team and security-assessment platform.")


@app.command()
def plugins() -> None:
    """List the plugins discovered via the interlock.plugins entry-point group."""
    discovered = registry.discover()
    if not discovered:
        typer.echo("No plugins found.")
        return
    for name, plugin in sorted(discovered.items()):
        typer.echo(f"{name}  {plugin.summary}")


@app.command()
def run(
    plugin_name: str = typer.Argument(..., help="Name of the plugin to run."),
    output: Path = typer.Option(
        Path("interlock-report.md"),
        "--output",
        "-o",
        help="Path to write the Markdown report to.",
    ),
) -> None:
    """Run a plugin, render its findings, and write a Markdown report."""
    try:
        plugin = registry.get(plugin_name)
    except KeyError:
        available = ", ".join(sorted(registry.discover())) or "none"
        typer.echo(
            f"Unknown plugin '{plugin_name}'. Available plugins: {available}.",
            err=True,
        )
        raise typer.Exit(code=1)

    findings = plugin.run()
    report.render_terminal(findings)
    report.write_markdown(findings, path=output)
    typer.echo(f"Wrote report to {output}")


if __name__ == "__main__":
    app()
