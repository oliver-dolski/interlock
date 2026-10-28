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
checks and attaches them, so it stays standard library only. A name registered by
more than one distribution is never resolved by install order: the core keeps its
own names and any other shared name is refused.
"""

from __future__ import annotations

import re
import sys
from importlib.metadata import EntryPoint, entry_points

from interlock.plugin import Plugin

ENTRY_POINT_GROUP = "interlock.plugins"
COMMANDS_GROUP = "interlock.commands"

# The distribution whose own command groups (osdp) no other package may take over (T-06-02).
CORE_DISTRIBUTION = "interlock"


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


def _distribution(entry_point: EntryPoint) -> str:
    """Return the normalized name of the distribution that registered ``entry_point``."""
    name = getattr(getattr(entry_point, "dist", None), "name", None)
    if not isinstance(name, str) or not name:
        return "an unknown distribution"
    return re.sub(r"[-_.]+", "-", name).lower()


def _listed(distributions: list[str]) -> str:
    """Return "a and b" or "a, b and c"."""
    if len(distributions) == 1:
        return distributions[0]
    return f"{', '.join(distributions[:-1])} and {distributions[-1]}"


def discover_commands() -> dict[str, object]:
    """Load every installed command-group target, keyed by its entry-point name.

    Each load is isolated: a target that fails to import is skipped with a warning
    to stderr, so one broken command group does not abort discovery (T-06-01). A name
    more than one distribution registers is settled before anything loads, never by
    install order: the core distribution keeps its own entry and every other claim is
    skipped with a warning naming both; a name only other distributions share is
    refused for all of them, so no package's code runs under a name it does not own
    alone (WR-06).
    """
    claims: dict[str, list[tuple[str, EntryPoint]]] = {}
    for entry_point in entry_points(group=COMMANDS_GROUP):
        claims.setdefault(entry_point.name, []).append((_distribution(entry_point), entry_point))
    discovered: dict[str, object] = {}
    for name, claimed in claims.items():
        if len(claimed) > 1:
            core = [entry for entry in claimed if entry[0] == CORE_DISTRIBUTION]
            if len(core) != 1:
                print(
                    f"interlock: skipping command group '{name}': registered by "
                    f"{_listed([distribution for distribution, _ in claimed])}",
                    file=sys.stderr,
                )
                continue
            for distribution, _ in claimed:
                if distribution != CORE_DISTRIBUTION:
                    print(
                        f"interlock: skipping command group '{name}' from {distribution}: "
                        f"already registered by {CORE_DISTRIBUTION}",
                        file=sys.stderr,
                    )
            claimed = core
        entry_point = claimed[0][1]
        try:
            discovered[name] = entry_point.load()
        except Exception as exc:  # noqa: BLE001 - one bad command group must not abort discovery
            print(
                f"interlock: skipping command group '{name}': {exc}",
                file=sys.stderr,
            )
    return discovered


def get(name: str) -> Plugin:
    """Return a discovered plugin by name, or raise ``KeyError`` if unknown."""
    plugins = discover()
    return plugins[name]
