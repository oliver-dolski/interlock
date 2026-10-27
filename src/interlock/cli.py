"""The interlock command-line interface (Typer).

Commands:
- ``interlock plugins``: list discovered plugins.
- ``interlock run <plugin>``: run a plugin, render its findings to the terminal,
  and write a Markdown report.

Every other command group comes from an installed package that registers it under
the ``interlock.commands`` entry-point group (D-04); the core imports no protocol
package, so a new protocol adds its group with no edit here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from interlock import registry, report

# Core command names a discovered command group may never take over (T-06-02).
_CORE_COMMANDS = frozenset({"plugins", "run"})


def plugins() -> None:
    """List the plugins discovered via the interlock.plugins entry-point group."""
    discovered = registry.discover()
    if not discovered:
        typer.echo("No plugins found.")
        return
    for name, plugin in sorted(discovered.items()):
        typer.echo(f"{name}  {plugin.summary}")


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


def _attach_command_groups(app: typer.Typer) -> None:
    """Attach every discovered command group to ``app`` under its entry-point name.

    A target that is already a ``typer.Typer`` is attached as is: calling a Typer runs
    the CLI, so it is never called. Any other callable target is a factory and is called
    with no arguments. A
    reserved name, a factory that raises and a result that is not a ``typer.Typer`` are
    each skipped with one warning to stderr, so the core commands keep working (T-06-01,
    T-06-02).
    """
    for name, target in sorted(registry.discover_commands().items()):
        if name in _CORE_COMMANDS:
            print(f"interlock: skipping command group '{name}': name is reserved", file=sys.stderr)
            continue
        try:
            if isinstance(target, typer.Typer):
                group: object = target
            elif callable(target):
                group = target()
            else:
                group = target
        except Exception as exc:  # noqa: BLE001 - one bad command group must not break the CLI
            print(f"interlock: skipping command group '{name}': {exc}", file=sys.stderr)
            continue
        if not isinstance(group, typer.Typer):
            print(f"interlock: skipping command group '{name}': not a typer.Typer", file=sys.stderr)
            continue
        app.add_typer(group, name=name)


def build_app() -> typer.Typer:
    """Build the CLI: the core commands plus every discovered command group."""
    app = typer.Typer(help="Extensible red-team and security-assessment platform.")
    app.command()(plugins)
    app.command()(run)
    _attach_command_groups(app)
    return app


app = build_app()


if __name__ == "__main__":
    app()
