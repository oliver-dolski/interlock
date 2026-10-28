"""The plugin contract for protocol command groups (D-04, CORE-05).

A protocol reaches the CLI as a plugin of the core, the way a third party's package would: its
command group arrives through the ``interlock.commands`` entry-point group, and the core imports
nothing from it. These tests pin the CLI surface that users and the README depend on, so the
move onto the contract changes no command name, option or exit code.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
import typer.core
import typer.main
from typer.testing import CliRunner

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


def test_import_scan_flags_a_planted_protocol_import() -> None:
    source = (
        "import importlib\n"
        "import interlock.osdp.codec\n"
        "from interlock.osdp import assessment\n"
        'attacks = importlib.import_module("interlock.osdp.attacks")\n'
    )
    assert protocol_imports(source) == [
        "line 2: import interlock.osdp.codec",
        "line 3: from interlock.osdp import assessment",
        "line 4: 'interlock.osdp.attacks'",
    ]


def test_import_scan_passes_a_clean_core_module() -> None:
    assert protocol_imports("import typer\nfrom interlock import registry\n") == []


# D-04 command-group seam: a broken or hostile group never takes the core CLI down. -----------


@dataclass(frozen=True)
class _FakeEntryPoint:
    """An ``interlock.commands`` entry point whose ``load()`` returns or raises ``target``.

    ``dist`` stands in for the distribution that registered it (anything with a ``name``).
    """

    name: str
    target: object
    dist: object = None

    def load(self) -> object:
        if isinstance(self.target, BaseException):
            raise self.target
        return self.target


class _NeverCalledTyper(typer.Typer):
    """A Typer that fails the test if the core calls it (calling a Typer runs the CLI)."""

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a Typer registered directly must be attached, never called")


def _group(typer_class: type[typer.Typer] = typer.Typer) -> typer.Typer:
    group = typer_class(help="A fake protocol group.")

    @group.command()
    def ping() -> None:
        """Answer with pong."""
        typer.echo("pong")

    return group


def _install_command_groups(
    monkeypatch: pytest.MonkeyPatch, *fakes: _FakeEntryPoint
) -> Callable[[], typer.Typer]:
    """Serve ``fakes`` for the commands group and the real entry points for any other group."""

    def fake_entry_points(*, group: str) -> Any:
        if group == registry.COMMANDS_GROUP:
            return list(fakes)
        return entry_points(group=group)

    monkeypatch.setattr(registry, "entry_points", fake_entry_points)
    return cli.build_app


def _commands(app: typer.Typer) -> list[str]:
    root = typer.main.get_command(app)
    assert isinstance(root, typer.core.TyperGroup)
    return sorted(root.commands)


def _boom() -> typer.Typer:
    raise RuntimeError("factory exploded")


def test_a_group_that_fails_to_load_is_skipped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    build = _install_command_groups(
        monkeypatch,
        _FakeEntryPoint("broken", ImportError("No module named 'nowhere'")),
        _FakeEntryPoint("good", _group),
    )
    commands = _commands(build())
    assert commands == ["good", "plugins", "run"]
    assert "interlock: skipping command group 'broken':" in capsys.readouterr().err


def test_a_factory_that_raises_is_skipped_and_the_others_attach(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    build = _install_command_groups(
        monkeypatch, _FakeEntryPoint("boom", _boom), _FakeEntryPoint("good", _group)
    )
    commands = _commands(build())
    assert commands == ["good", "plugins", "run"]
    assert "interlock: skipping command group 'boom': factory exploded" in capsys.readouterr().err


def test_a_factory_returning_something_else_is_skipped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    build = _install_command_groups(monkeypatch, _FakeEntryPoint("odd", lambda: object()))
    assert _commands(build()) == ["plugins", "run"]
    assert "interlock: skipping command group 'odd': not a typer.Typer" in capsys.readouterr().err


def test_reserved_names_never_shadow_the_core_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    build = _install_command_groups(
        monkeypatch, _FakeEntryPoint("plugins", _group), _FakeEntryPoint("run", _group)
    )
    built = build()
    err = capsys.readouterr().err
    assert "interlock: skipping command group 'plugins': name is reserved" in err
    assert "interlock: skipping command group 'run': name is reserved" in err

    result = CliRunner().invoke(built, ["plugins"])
    assert result.exit_code == 0, result.output
    assert result.output.startswith("demo")


def test_a_typer_registered_directly_is_attached_and_never_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build = _install_command_groups(
        monkeypatch, _FakeEntryPoint("direct", _group(_NeverCalledTyper))
    )
    built = build()
    assert _commands(built) == ["direct", "plugins", "run"]
    result = CliRunner().invoke(built, ["direct", "--help"])
    assert result.exit_code == 0, result.output
    assert "ping" in result.output


def test_a_valid_factory_is_attached(monkeypatch: pytest.MonkeyPatch) -> None:
    build = _install_command_groups(monkeypatch, _FakeEntryPoint("proto", _group))
    built = build()
    result = CliRunner().invoke(built, ["proto", "--help"])
    assert result.exit_code == 0, result.output
    result = CliRunner().invoke(built, ["proto", "ping"])
    assert result.exit_code == 0, result.output
    assert result.output == "pong\n"


# A name two distributions both register is never resolved by install order (WR-06). ---------


def _from(distribution: str) -> SimpleNamespace:
    return SimpleNamespace(name=distribution)


def _hostile_group() -> typer.Typer:
    group = typer.Typer(help="Another package's group under a taken name.")

    @group.command()
    def ping() -> None:
        """Answer as someone else."""
        typer.echo("hijacked")

    return group


def _loaded_by(record: list[str], name: str, target: object) -> object:
    """Return a factory that records ``name`` when the core runs it."""

    def factory() -> object:
        record.append(name)
        return target() if callable(target) else target

    return factory


def test_a_name_two_third_party_distributions_register_is_refused_for_both(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    build = _install_command_groups(
        monkeypatch,
        _FakeEntryPoint("proto", _group, _from("acme-osdp")),
        _FakeEntryPoint("proto", _hostile_group, _from("Other_Osdp")),
    )
    assert _commands(build()) == ["plugins", "run"]
    err = capsys.readouterr().err
    assert "interlock: skipping command group 'proto':" in err
    assert "acme-osdp" in err and "other-osdp" in err


@pytest.mark.parametrize("core_first", [True, False])
def test_a_third_party_package_never_replaces_the_core_osdp_group(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], core_first: bool
) -> None:
    core = _FakeEntryPoint("osdp", _group, _from("interlock"))
    hostile = _FakeEntryPoint("osdp", _hostile_group, _from("evil-osdp"))
    order = (core, hostile) if core_first else (hostile, core)
    build = _install_command_groups(monkeypatch, *order)
    built = build()
    err = capsys.readouterr().err
    assert "interlock: skipping command group 'osdp' from evil-osdp:" in err
    assert "interlock" in err.split("evil-osdp:", 1)[1]
    result = CliRunner().invoke(built, ["osdp", "ping"])
    assert result.exit_code == 0, result.output
    assert result.output == "pong\n"


def test_a_refused_duplicate_is_never_loaded(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    loaded: list[str] = []
    build = _install_command_groups(
        monkeypatch,
        _FakeEntryPoint("proto", _loaded_by(loaded, "acme", _group), _from("acme-osdp")),
        _FakeEntryPoint("proto", _loaded_by(loaded, "other", _group), _from("other-osdp")),
        _FakeEntryPoint("osdp", _loaded_by(loaded, "core", _group), _from("interlock")),
        _FakeEntryPoint("osdp", _loaded_by(loaded, "evil", _group), _from("evil-osdp")),
    )
    assert _commands(build()) == ["osdp", "plugins", "run"]
    assert loaded == ["core"]


def test_the_real_cli_and_its_osdp_group_answer_help() -> None:
    assert CliRunner().invoke(app, ["--help"]).exit_code == 0
    result = CliRunner().invoke(app, ["osdp", "--help"])
    assert result.exit_code == 0, result.output
    assert "assess" in result.output
