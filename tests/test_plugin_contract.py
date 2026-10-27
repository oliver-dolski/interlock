"""The plugin contract for protocol command groups (D-04, CORE-05).

A protocol reaches the CLI as a plugin of the core, the way a third party's package would: its
command group arrives through the ``interlock.commands`` entry-point group, and the core imports
nothing from it. These tests pin the CLI surface that users and the README depend on, so the
move onto the contract changes no command name, option or exit code.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
import typer
import typer.core
import typer.main

from interlock import cli, registry
from interlock.cli import app

REPO_ROOT = Path(__file__).resolve().parents[1]

# Every option string of every osdp subcommand, as the CLI exposed it before the refactor.
_OSDP_SURFACE: dict[str, list[str]] = {
    "assess": ["--lab-dir", "--output", "-o"],
    "downgrade": [
        "--device",
        "--physical",
        "--port",
        "--target",
        "--upstream-device",
        "--upstream-host",
        "--upstream-port",
    ],
    "enumerate": [
        "--device",
        "--max-frames",
        "--mode",
        "--output",
        "--physical",
        "--port",
        "--target",
        "--upstream-host",
        "--upstream-port",
        "-o",
    ],
    "fuzz": [
        "--address",
        "--device",
        "--output",
        "--physical",
        "--seed",
        "--target",
        "--upstream-host",
        "--upstream-port",
        "--variants",
        "-o",
    ],
    "keyset": [
        "--address",
        "--device",
        "--max-frames",
        "--mode",
        "--output",
        "--physical",
        "--port",
        "--target",
        "--upstream-host",
        "--upstream-port",
        "-o",
    ],
    "replay": [
        "--device",
        "--mode",
        "--physical",
        "--port",
        "--target",
        "--upstream-device",
        "--upstream-host",
        "--upstream-port",
    ],
    "sniff": ["--max-frames", "--output", "--port", "--upstream-host", "--upstream-port", "-o"],
    "spoof": [
        "--address",
        "--device",
        "--kind",
        "--physical",
        "--port",
        "--target",
        "--upstream-device",
        "--upstream-host",
        "--upstream-port",
    ],
    "weak-key": ["--max-frames", "--output", "--port", "--upstream-host", "--upstream-port", "-o"],
}


def _options(command: Any) -> list[str]:
    """Return every option string of ``command`` (primary and secondary), sorted."""
    return sorted(
        option
        for param in command.params
        for option in (*param.opts, *param.secondary_opts)
        if option.startswith("-")
    )


def test_cli_surface_is_unchanged() -> None:
    root = typer.main.get_command(app)
    assert isinstance(root, typer.core.TyperGroup)
    assert sorted(root.commands) == ["osdp", "plugins", "run"]

    assert root.commands["plugins"].params == []

    run_params = root.commands["run"].params
    arguments = [param.name for param in run_params if isinstance(param, typer.core.TyperArgument)]
    assert arguments == ["plugin_name"]
    assert _options(root.commands["run"]) == ["--output", "-o"]

    osdp = root.commands["osdp"]
    assert isinstance(osdp, typer.core.TyperGroup)
    surface = {name: _options(command) for name, command in sorted(osdp.commands.items())}
    assert surface == _OSDP_SURFACE


# D-04 core import guard. -------------------------------------------------------------------

_PROTOCOL_PACKAGE = "interlock.osdp"
_CORE_MODULES = (
    "src/interlock/__init__.py",
    "src/interlock/cli.py",
    "src/interlock/plugin.py",
    "src/interlock/registry.py",
    "src/interlock/report.py",
    "src/interlock/plugins/demo.py",
)


def _names_protocol(dotted: str) -> bool:
    return dotted == _PROTOCOL_PACKAGE or dotted.startswith(f"{_PROTOCOL_PACKAGE}.")


def protocol_imports(source: str) -> list[str]:
    """Return every place in ``source`` that reaches the protocol package.

    An ``import`` or ``from ... import`` whose dotted module (or module plus bound name) starts
    with the protocol package is flagged, and so is any string constant naming it, which catches
    ``importlib.import_module``. Each is reported as ``line N: <the statement or literal>``.
    """
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            dotted = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            dotted = [module] + [f"{module}.{alias.name}" for alias in node.names]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _PROTOCOL_PACKAGE in node.value:
                found.append((node.lineno, repr(node.value)))
            continue
        else:
            continue
        if any(_names_protocol(name) for name in dotted):
            found.append((node.lineno, ast.unparse(node)))
    return [f"line {line}: {statement}" for line, statement in sorted(found)]


def test_core_imports_no_protocol_package() -> None:
    offenders = {
        module: found
        for module in _CORE_MODULES
        if (found := protocol_imports((REPO_ROOT / module).read_text(encoding="utf-8")))
    }
    assert not offenders, f"core modules reach a protocol package: {offenders}"


def test_osdp_group_comes_from_the_commands_entry_point(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with_discovery = typer.main.get_command(cli.build_app())
    assert isinstance(with_discovery, typer.core.TyperGroup)
    assert "osdp" in with_discovery.commands

    monkeypatch.setattr(registry, "discover_commands", dict)
    without = typer.main.get_command(cli.build_app())
    assert isinstance(without, typer.core.TyperGroup)
    assert sorted(without.commands) == ["plugins", "run"]
