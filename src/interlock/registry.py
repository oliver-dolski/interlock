"""Plugin discovery via the ``interlock.plugins`` entry-point group.

This is the universality mechanism: a third party ships a package that
registers an entry point in the ``interlock.plugins`` group, and interlock
discovers it with no fork. Only installed entry points are loaded; there is no
arbitrary-path or auto-download loading (trust boundary T-01-01).

A second group, ``interlock.commands``, carries CLI command groups (D-04). Each
entry is a zero-argument factory returning a ``typer.Typer`` (or the Typer
itself), keyed by the command name it is attached under. A protocol package
registers its group there, so the core never imports a protocol package and a
new protocol needs no core edit. This module only loads the targets; the CLI
checks and attaches them, so it stays standard library only.
"""

from __future__ import annotations

import sys
from importlib.metadata import entry_points

from interlock.plugin import Plugin

ENTRY_POINT_GROUP = "interlock.plugins"
COMMANDS_GROUP = "interlock.commands"


def discover() -> dict[str, Plugin]:
    """Discover installed plugins keyed by their ``name`` attribute.

    Each entry-point load is isolated: a plugin whose target fails to import or
    instantiate is skipped with a warning to stderr, so one broken plugin does
    not abort discovery (threat T-01-03).
    """
    discovered: dict[str, Plugin] = {}
    for entry_point in entry_points(group=ENTRY_POINT_GROUP):
        try:
            plugin_class = entry_point.load()
            plugin = plugin_class()
            discovered[plugin.name] = plugin
        except Exception as exc:  # noqa: BLE001 - one bad plugin must not abort discovery
            print(
                f"interlock: skipping plugin '{entry_point.name}': {exc}",
                file=sys.stderr,
            )
    return discovered


def discover_commands() -> dict[str, object]:
    """Load every installed command-group target, keyed by its entry-point name.

    Each load is isolated: a target that fails to import is skipped with a warning
    to stderr, so one broken command group does not abort discovery (T-06-01).
    """
    discovered: dict[str, object] = {}
    for entry_point in entry_points(group=COMMANDS_GROUP):
        try:
            discovered[entry_point.name] = entry_point.load()
        except Exception as exc:  # noqa: BLE001 - one bad command group must not abort discovery
            print(
                f"interlock: skipping command group '{entry_point.name}': {exc}",
                file=sys.stderr,
            )
    return discovered


def get(name: str) -> Plugin:
    """Return a discovered plugin by name, or raise ``KeyError`` if unknown."""
    plugins = discover()
    return plugins[name]
