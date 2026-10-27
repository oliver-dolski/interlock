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

The guide itself is held to the code too: every block between ``<!-- example:start <path> -->``
and ``<!-- example:end -->`` must equal the file it names, every repository path it cites must
exist, and it must state the contract, the safety obligations and the 0.x surface note.
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
GUIDE = REPO_ROOT / "docs" / "plugin-authoring.md"

_EXAMPLE_BLOCK = re.compile(
    r"^<!-- example:start (\S+) -->\n```[a-z]*\n(.*?)^```\n<!-- example:end -->$",
    re.MULTILINE | re.DOTALL,
)
_FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_PATH_PREFIXES = ("src/", "lab/", "tests/", "docs/")
_TOP_LEVEL_FILE = re.compile(r"^(Dockerfile|[A-Za-z0-9_.*-]+\.(toml|yml|yaml|md|txt))$")

# Built from code points so this file never holds the characters it forbids.
_LONG_DASHES = (chr(0x2014), chr(0x2013))


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


def _guide_text() -> str:
    assert GUIDE.is_file(), f"{GUIDE} is missing"
    return GUIDE.read_text(encoding="utf-8").replace("\r\n", "\n")


def test_guide_code_blocks_match_the_example_files() -> None:
    blocks = _EXAMPLE_BLOCK.findall(_guide_text())
    assert len(blocks) >= 2, "the guide must show the example's pyproject.toml and module"
    for relative, shown in blocks:
        path = REPO_ROOT / relative
        assert path.is_file(), f"the guide shows {relative}, which does not exist"
        actual = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        assert shown == actual, f"the guide's copy of {relative} differs from the file"


def test_guide_paths_exist() -> None:
    prose = _FENCE.sub("", _guide_text())
    cited = [
        token
        for token in _INLINE_CODE.findall(prose)
        if token.startswith(_PATH_PREFIXES) or _TOP_LEVEL_FILE.match(token)
    ]
    assert cited, "the guide cites no repository path"
    missing = [token for token in cited if not any(REPO_ROOT.glob(token.rstrip("/")))]
    assert not missing, f"the guide cites paths that do not exist: {missing}"


def test_guide_states_the_contract() -> None:
    text = _guide_text()
    for heading in (
        "### Lab",
        "### Attack and assessment",
        "### ATT&CK mapping",
        "### Report via Finding",
        "## Safety obligations every plugin inherits",
    ):
        assert f"\n{heading}\n" in text, f"missing section {heading!r}"
    for phrase in (
        "interlock.plugin`",
        "interlock.plugins",
        "interlock.commands",
        "0.x",
        "safety.py",
        "authorized-use notice",
        "not a guarantee",
    ):
        assert phrase in text, f"the guide does not say {phrase!r}"
    assert not any(dash in text for dash in _LONG_DASHES)
    assert "generated with" not in text.lower()
