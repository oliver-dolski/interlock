"""CLI output in the tests is plain text whatever colour variables the CI runner sets.

GitHub Actions sets ``GITHUB_ACTIONS`` and other runners set ``FORCE_COLOR`` or ``PY_COLORS``.
Under any of them the CLI styles its output, which splits an option name such as ``--output``
into separate escape runs, so a test asserting plain text fails in CI and passes locally.
``tests/conftest.py`` switches the styling off for the whole suite, and these tests fail on a
plain local run when that switch stops working, instead of on the next CI run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer import rich_utils

_ESCAPE = "\x1b["

_CI_COLOUR_VARIABLES = {"GITHUB_ACTIONS": "true", "FORCE_COLOR": "1", "PY_COLORS": "1"}


def _cli(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", "from interlock.cli import app; app()", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
        timeout=60,
    )


def test_typer_help_console_is_never_a_terminal_in_the_tests() -> None:
    assert rich_utils.FORCE_TERMINAL is False, (
        "typer renders help through a forced terminal: tests/conftest.py ran after the first "
        "typer import, or typer no longer reads _TYPER_FORCE_DISABLE_TERMINAL"
    )


# typer and rich decide at import and when a console is created, so setting a variable inside
# this process proves nothing; the CLI runs in a fresh interpreter that inherits os.environ.
@pytest.mark.parametrize("name", sorted(_CI_COLOUR_VARIABLES))
def test_help_in_a_fresh_interpreter_is_plain_under_a_ci_colour_variable(name: str) -> None:
    result = _cli("osdp", "assess", "--help", env={**os.environ, name: _CI_COLOUR_VARIABLES[name]})
    assert result.returncode == 0, result.stdout + result.stderr
    assert _ESCAPE not in result.stdout, repr(result.stdout)
    assert "--output" in result.stdout, result.stdout
    assert "--lab-dir" in result.stdout, result.stdout


def test_report_table_in_a_fresh_interpreter_is_plain_under_force_color(tmp_path: Path) -> None:
    output = tmp_path / "report.md"
    result = _cli("run", "demo", "-o", str(output), env={**os.environ, "FORCE_COLOR": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert _ESCAPE not in result.stdout, repr(result.stdout)
    assert "DEMO-001" in result.stdout, result.stdout
