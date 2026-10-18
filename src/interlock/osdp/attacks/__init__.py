"""OSDP offensive capabilities package and the self-registering CLI seam (D-01).

Every attack capability is reusable library code in its own module here AND a
subcommand under the ``interlock osdp`` group. ``build_osdp_app`` auto-discovers
each sibling module that exposes a ``register(app)`` callable, so a later attack
plan adds a module with its own ``register()`` and is wired up with no edit to any
shared file. This is the one registration seam for all attack subcommands.

``typer`` is imported lazily, inside ``build_osdp_app``, not at module scope (Rule 3
fix, 04-07): every attack module's own ``main()`` entrypoint is invoked as
``python -m interlock.osdp.attacks.<name>`` inside the minimal lab/attacker image
(e.g. ``docker-compose.downgrade.yml``, ``docker-compose.spoof.yml``), which has no
``typer`` installed. Running that submodule still imports this package's
``__init__.py`` first, so a top-level ``import typer`` here broke every such
entrypoint with ``ModuleNotFoundError`` - a pre-existing bug this plan's spoof/replay
``@lab`` proofs depend on fixing, caught because `python -m interlock.osdp.attacks.downgrade``
failed identically under this package's own prior ``import typer``.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import typer

# Sibling modules that are not attack subcommands and must be skipped by discovery.
_SKIP_MODULES = frozenset({"safety"})

# Cached osdp Typer group: built once, on first call, so repeat calls return the same
# group without re-registering (Typer would otherwise accumulate duplicate commands).
_osdp_app: typer.Typer | None = None


def build_osdp_app() -> typer.Typer:
    """Return the ``osdp`` Typer group with every sibling attack subcommand attached.

    Discovers each non-private sibling module in this package via
    ``pkgutil.iter_modules``, imports it, and - when it exposes a ``register(app)``
    callable - calls ``register(app)``. Modules whose name starts with ``_`` and the
    non-subcommand ``safety`` module are skipped. The result is cached so repeat calls
    return the same group without re-registering.
    """
    global _osdp_app
    if _osdp_app is not None:
        return _osdp_app

    import typer

    app = typer.Typer(
        help="OSDP offensive capabilities (lab-default; --physical gates real hardware).",
        no_args_is_help=True,
    )
    for module_info in pkgutil.iter_modules(__path__):
        name = module_info.name
        if name.startswith("_") or name in _SKIP_MODULES:
            continue
        module = importlib.import_module(f"{__name__}.{name}")
        register = getattr(module, "register", None)
        if callable(register):
            register(app)
    _osdp_app = app
    return _osdp_app
