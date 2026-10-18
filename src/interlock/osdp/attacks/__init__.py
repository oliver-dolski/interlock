"""OSDP offensive capabilities package and the self-registering CLI seam (D-01).

Every attack capability is reusable library code in its own module here AND a
subcommand under the ``interlock osdp`` group. ``build_osdp_app`` auto-discovers
each sibling module that exposes a ``register(app)`` callable, so a later attack
plan adds a module with its own ``register()`` and is wired up with no edit to any
shared file. This is the one registration seam for all attack subcommands.
"""

from __future__ import annotations

import importlib
import pkgutil

import typer

# The command group every attack subcommand attaches to: ``interlock osdp <...>``.
osdp_app = typer.Typer(
    help="OSDP offensive capabilities (lab-default; --physical gates real hardware).",
    no_args_is_help=True,
)

# Sibling modules that are not attack subcommands and must be skipped by discovery.
_SKIP_MODULES = frozenset({"safety"})

# Discovery is idempotent per process: Typer accumulates commands, so attaching the
# same subcommands twice would duplicate them. cli.py calls this once at import.
_registered = False


def build_osdp_app() -> typer.Typer:
    """Return the ``osdp`` Typer group with every sibling attack subcommand attached.

    Discovers each non-private sibling module in this package via
    ``pkgutil.iter_modules``, imports it, and - when it exposes a ``register(app)``
    callable - calls ``register(osdp_app)``. Modules whose name starts with ``_``
    and the non-subcommand ``safety`` module are skipped. The result is cached so
    repeat calls return the same group without re-registering.
    """
    global _registered
    if _registered:
        return osdp_app
    for module_info in pkgutil.iter_modules(__path__):
        name = module_info.name
        if name.startswith("_") or name in _SKIP_MODULES:
            continue
        module = importlib.import_module(f"{__name__}.{name}")
        register = getattr(module, "register", None)
        if callable(register):
            register(osdp_app)
    _registered = True
    return osdp_app
