"""D-06 drift gate: the plugin-authoring guide's example is a real, working plugin.

The example under ``docs/examples/minimal-plugin`` is "installed" without pip or network:
a fixture writes a ``*.dist-info`` directory into ``tmp_path`` whose ``entry_points.txt`` is
generated from the example's own ``pyproject.toml`` (read with ``tomllib``), so the
declaration the guide documents is the one tested. ``importlib.metadata`` discovers any
dist-info on ``sys.path``, so putting that directory and the example's ``src`` on
``PYTHONPATH`` is enough.

The CLI runs in a subprocess because ``interlock.cli`` attaches command groups when it is
imported, and this test process imported it long before the fixture ran. ``-I`` is not
passed, since it would drop ``PYTHONPATH``; ``os.pathsep`` keeps the path list valid on
Windows.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from interlock import report

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIR = REPO_ROOT / "docs" / "examples" / "minimal-plugin"
EXAMPLE_PYPROJECT = EXAMPLE_DIR / "pyproject.toml"
EXAMPLE_SRC = EXAMPLE_DIR / "src"


def _example_entry_points() -> dict[str, dict[str, str]]:
    data = tomllib.loads(EXAMPLE_PYPROJECT.read_text(encoding="utf-8"))
    groups: dict[str, dict[str, str]] = data["project"]["entry-points"]
    return groups


@pytest.fixture
def example_path(tmp_path: Path) -> str:
    """Install the example through a hand-made dist-info and return the PYTHONPATH."""
    project = tomllib.loads(EXAMPLE_PYPROJECT.read_text(encoding="utf-8"))["project"]
    dist_info = tmp_path / "interlock_example-0.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {project['name']}\nVersion: {project['version']}\n",
        encoding="utf-8",
    )
    sections: list[str] = []
    for group, entries in _example_entry_points().items():
        lines = [f"[{group}]"] + [f"{name} = {target}" for name, target in entries.items()]
        sections.append("\n".join(lines))
    (dist_info / "entry_points.txt").write_text("\n\n".join(sections) + "\n", encoding="utf-8")
    return str(tmp_path) + os.pathsep + str(EXAMPLE_SRC)


def _cli(pythonpath: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": pythonpath}
    return subprocess.run(
        [sys.executable, "-c", "from interlock.cli import app; app()", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
        timeout=120,
    )


def test_guide_example_plugin_is_listed(example_path: str) -> None:
    result = _cli(example_path, "plugins")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert any(line.startswith("example ") for line in lines), result.stdout + result.stderr
    assert any(line.startswith("demo ") for line in lines), result.stdout


def test_guide_example_plugin_runs_and_writes_a_report(example_path: str, tmp_path: Path) -> None:
    output = tmp_path / "r.md"
    result = _cli(example_path, "run", "example", "-o", str(output))
    assert result.returncode == 0, result.stdout + result.stderr
    text = output.read_text(encoding="utf-8")
    assert text.startswith("# interlock findings")
    assert report.AUTHORIZED_USE_NOTICE in text
    assert "EXAMPLE-001" in text


def test_guide_example_command_group_is_attached(example_path: str) -> None:
    result = _cli(example_path, "example", "--help")
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(r"\binfo\b", result.stdout), result.stdout
