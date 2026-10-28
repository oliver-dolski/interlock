"""The unit path must import on Windows, where termios and friends do not exist (D-08).

The CLI builds its command groups at import, so one POSIX-only module imported at module
scope anywhere under the osdp group takes the whole CLI down on Windows, and with it every
CLI test and the collection of tests/lab. These tests run the CLI in a fresh interpreter
with the POSIX terminal modules blocked, which is the shape of the Windows stdlib. A static
scan also keeps the tests from joining a host path with a '/' literal, which only Windows sees.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# The POSIX terminal modules the Windows stdlib does not ship.
_BLOCKED = ("termios", "tty", "fcntl", "pty")

_SCRIPT = """
import sys
from pathlib import Path
for name in {blocked!r}:
    sys.modules[name] = None
from interlock.cli import app
app({argv!r})
"""


def _run_cli_without_posix_terminal(argv: list[str]) -> subprocess.CompletedProcess[str]:
    script = _SCRIPT.format(blocked=_BLOCKED, argv=argv)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )


def test_cli_imports_without_posix_terminal_modules() -> None:
    top = _run_cli_without_posix_terminal(["--help"])
    assert top.returncode == 0, top.stderr
    assert "skipping command group" not in top.stderr, top.stderr
    assert "osdp" in top.stdout

    osdp = _run_cli_without_posix_terminal(["osdp", "--help"])
    assert osdp.returncode == 0, osdp.stderr
    assert "assess" in osdp.stdout


# The Windows checkout rules (PUB-02): a CR in a hook, lab.sh or a Dockerfile breaks them
# under sh, and a text conversion of a .cap fixture corrupts the bytes the parsers replay.
_REPO = Path(__file__).resolve().parent.parent

_WIN32_SKIPPED = {
    ("tests/osdp/test_transport_pty.py", 50),
    ("tests/osdp/test_transport_rewrite.py", 139),
    ("tests/osdp/test_transport_rewrite.py", 146),
}


def _check_attr(attrs: list[str], paths: list[str]) -> dict[tuple[str, str], str]:
    git = shutil.which("git")
    if git is None or not (_REPO / ".git").exists():
        pytest.skip("git or the repository is unavailable")
    out = subprocess.run(
        [git, "check-attr", *attrs, "--", *paths],
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    result: dict[tuple[str, str], str] = {}
    for line in out.splitlines():
        path, attr, value = line.rsplit(": ", 2)
        result[(path, attr)] = value
    return result


def test_gitattributes_declares_binary_fixtures_and_lf_scripts() -> None:
    lines = {
        " ".join(line.split())
        for line in (_REPO / ".gitattributes").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    for rule in (
        "*.cap binary",
        "*.sh text eol=lf",
        ".githooks/* text eol=lf",
        "Dockerfile text eol=lf",
        "Dockerfile.* text eol=lf",
    ):
        assert rule in lines, rule


def test_git_resolves_checkout_attributes_for_the_real_paths() -> None:
    fixture = "tests/osdp/fixtures/cleartext_sample.cap"
    assert (_REPO / fixture).is_file()
    binary = _check_attr(["diff", "merge", "text"], [fixture])
    assert binary == {
        (fixture, "diff"): "unset",
        (fixture, "merge"): "unset",
        (fixture, "text"): "unset",
    }
    lf_paths = [".githooks/commit-msg", "lab.sh", "Dockerfile", "Dockerfile.vuln"]
    for path in lf_paths:
        assert (_REPO / path).is_file(), path
    lf = _check_attr(["text", "eol"], lf_paths)
    for path in lf_paths:
        assert lf[(path, "text")] == "set", path
        assert lf[(path, "eol")] == "lf", path


def _is_win32_skipif(node: ast.expr) -> bool:
    if not (isinstance(node, ast.Call) and ast.unparse(node.func) == "pytest.mark.skipif"):
        return False
    return any(
        isinstance(arg, ast.Compare)
        and ast.unparse(arg.left) == "sys.platform"
        and any(isinstance(c, ast.Constant) and c.value == "win32" for c in arg.comparators)
        for arg in node.args
    )


def test_only_the_pty_select_tests_skip_on_windows() -> None:
    found: set[tuple[str, int]] = set()
    for path in sorted((_REPO / "tests").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                for deco in node.decorator_list:
                    if _is_win32_skipif(deco):
                        found.add((path.relative_to(_REPO).as_posix(), deco.lineno))
            elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
            ):
                values = node.value.elts if isinstance(node.value, ast.List) else [node.value]
                for value in values:
                    if _is_win32_skipif(value):
                        found.add((path.relative_to(_REPO).as_posix(), value.lineno))
    assert found == _WIN32_SKIPPED


# A POSIX host builds the same string from f"{path}/name" and str(path / "name"), so only the
# source shows the separator that breaks the test on Windows before a Windows run does.
def _slash_joined_path_params(source: str) -> list[int]:
    lines: set[int] = set()
    for func in ast.walk(ast.parse(source)):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        args = func.args
        params = {
            arg.arg
            for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
            if arg.annotation is not None and ast.unparse(arg.annotation) == "Path"
        }
        for node in ast.walk(func):
            if not isinstance(node, ast.JoinedStr):
                continue
            for value, after in zip(node.values, node.values[1:], strict=False):
                if (
                    isinstance(value, ast.FormattedValue)
                    and isinstance(value.value, ast.Name)
                    and value.value.id in params
                    and isinstance(after, ast.Constant)
                    and isinstance(after.value, str)
                    and after.value.startswith(("/", "\\"))
                ):
                    lines.add(node.lineno)
    return sorted(lines)


def test_no_test_builds_a_host_path_with_a_slash_literal() -> None:
    offenders = [
        f"{path.relative_to(_REPO).as_posix()}:{line}"
        for path in sorted((_REPO / "tests").rglob("*.py"))
        for line in _slash_joined_path_params(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_slash_literal_scan_flags_a_planted_join() -> None:
    head = "from pathlib import Path\n\n\ndef build(tmp_path: Path) -> str:\n    return "
    assert _slash_joined_path_params(head + 'f"{tmp_path}/a"\n') == [5]
    assert _slash_joined_path_params(head + 'str(tmp_path / "a")\n') == []
