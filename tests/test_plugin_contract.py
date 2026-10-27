"""The plugin contract for protocol command groups (D-04, CORE-05).

A protocol reaches the CLI as a plugin of the core, the way a third party's package would: its
command group arrives through the ``interlock.commands`` entry-point group, and the core imports
nothing from it. These tests pin the CLI surface that users and the README depend on, so the
move onto the contract changes no command name, option or exit code.
"""

from __future__ import annotations

from typing import Any

import typer
import typer.core
import typer.main

from interlock.cli import app

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
