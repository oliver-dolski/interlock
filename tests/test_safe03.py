"""SAFE-03 and D-04 guards: authorized-use statement, no long dashes, no key material.

SAFE-03: the README and every report state authorized, lab-by-default use, quoting
``report.AUTHORIZED_USE_NOTICE`` verbatim, and neither the README, the rendered reports nor
anything under ``src/`` carries a long dash. An AST scan of every Python file under ``src/``,
``lab/`` and ``tests/`` finds no 16-byte key literal outside an allow-list keyed by value and
path: the public spec default SCBK-D anywhere, the lab-arbitrary downgrade key only in ``lab/``
and ``tests/``, the synthetic withheld-display key only in ``tests/``. The complementary
dictionary guard, ``WEAK_KEYS`` holding only SCBK-D, stays in
``tests/lab/test_attacks_weak_key.py`` (``test_weak_keys_dictionary_excludes_the_downgrade_key``).

D-04: ``interlock osdp assess`` has no route to real hardware. Its help offers no
``--physical`` or ``--device`` option, and the modules it runs import nothing from the
SAFE-02 physical path.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import string
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest
from typer.testing import CliRunner

from interlock import report
from interlock.cli import app
from interlock.plugins.demo import DemoPlugin

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
SRC_DIR = REPO_ROOT / "src"

# Built from code points so this file never holds the characters it forbids.
_LONG_DASHES = (chr(0x2014), chr(0x2013))

_POWERSHELL_BLOCK = re.compile(r"^```powershell\n(.*?)^```", re.MULTILINE | re.DOTALL)


def _readme_text() -> str:
    assert README.is_file(), f"{README} is missing"
    return README.read_text(encoding="utf-8")


def _render_reports(tmp_path: Path) -> tuple[str, str]:
    findings = DemoPlugin().run()
    md_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"
    report.write_markdown(findings, md_path)
    report.write_json(findings, json_path)
    return md_path.read_text(encoding="utf-8"), json_path.read_text(encoding="utf-8")


def _long_dash_lines(text: str) -> list[int]:
    return [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if any(dash in line for dash in _LONG_DASHES)
    ]


def test_readme_states_authorized_use_with_the_notice_verbatim() -> None:
    text = _readme_text()
    assert "## Authorized use only" in text
    assert report.AUTHORIZED_USE_NOTICE in text
    section = text.split("## Authorized use only", 1)[1]
    assert section.lstrip().startswith(report.AUTHORIZED_USE_NOTICE)


def test_readme_powershell_block_has_no_shell_chaining() -> None:
    blocks = _POWERSHELL_BLOCK.findall(_readme_text())
    assert blocks, "README has no ```powershell block"
    for block in blocks:
        assert "&&" not in block, f"PowerShell 5.1 has no '&&':\n{block}"
    assert any("interlock osdp assess" in block for block in blocks)


def test_readme_quickstart_has_a_zsh_block_and_marks_windows_unverified() -> None:
    text = _readme_text()
    assert "```zsh\n" in text
    zsh_block = text.split("```zsh\n", 1)[1].split("```", 1)[0]
    assert ".venv/bin/interlock osdp assess" in zsh_block
    assert "&&" not in zsh_block
    assert "has not yet been run on a Windows machine" in text


def test_readme_carries_no_tooling_banner() -> None:
    lowered = _readme_text().lower()
    assert "generated with" not in lowered
    assert "co-authored-by" not in lowered


def test_markdown_and_json_reports_carry_the_notice(tmp_path: Path) -> None:
    markdown, raw_json = _render_reports(tmp_path)
    assert report.AUTHORIZED_USE_NOTICE in markdown
    assert json.loads(raw_json)["notice"] == report.AUTHORIZED_USE_NOTICE


def test_readme_has_no_long_dash() -> None:
    lines = _long_dash_lines(_readme_text())
    assert not lines, f"README.md has a long dash on lines {lines}"


def test_rendered_reports_have_no_long_dash(tmp_path: Path) -> None:
    markdown, raw_json = _render_reports(tmp_path)
    assert not _long_dash_lines(markdown), "Markdown report has a long dash"
    assert not _long_dash_lines(raw_json), "JSON report has a long dash"


def test_src_has_no_long_dash() -> None:
    offenders = [
        f"{path.relative_to(REPO_ROOT)}:{number}"
        for pattern in ("*.py", "*.yml", "*.md")
        for path in sorted(SRC_DIR.rglob(pattern))
        if "__pycache__" not in path.parts
        for number in _long_dash_lines(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"long dash in src/: {offenders}"


# SAFE-03 key-literal guard. ---------------------------------------------------------------

_KEY_LENGTH = 16
_SCAN_DIRS = ("src", "lab", "tests")

# Allowed 16-byte values and the repo-relative path prefixes each may appear under.
_SCBK_D = bytes(range(0x30, 0x40))  # public OSDP spec default, allowed anywhere
_LAB_DOWNGRADE_KEY = bytes(range(0x10, 0x20))  # lab-arbitrary, lab/ and tests/ only
_SYNTHETIC_TEST_KEY = bytes(range(0x40, 0x50))  # withheld-display test key, tests/ only
_ALLOWED_KEYS: dict[bytes, tuple[str, ...]] = {
    _SCBK_D: ("",),
    _LAB_DOWNGRADE_KEY: ("lab/", "tests/"),
    _SYNTHETIC_TEST_KEY: ("tests/",),
}


class KeyLiteral(NamedTuple):
    path: str
    line: int
    value: bytes

    def __str__(self) -> str:
        return f"{self.path}:{self.line} {self.value.hex()}"


def _int_constant(node: ast.expr) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _range_bytes(node: ast.Call) -> bytes | None:
    """``bytes(range(a, b))`` with integer constants and ``b - a == 16``, else None."""
    if not (isinstance(node.func, ast.Name) and node.func.id == "bytes" and len(node.args) == 1):
        return None
    inner = node.args[0]
    if not (
        isinstance(inner, ast.Call)
        and isinstance(inner.func, ast.Name)
        and inner.func.id == "range"
        and len(inner.args) == 2
        and not inner.keywords
    ):
        return None
    start, stop = (_int_constant(arg) for arg in inner.args)
    if start is None or stop is None or stop - start != _KEY_LENGTH:
        return None
    if not 0 <= start < stop <= 0x100:
        return None
    return bytes(range(start, stop))


def _is_ascii_word(value: bytes) -> bool:
    return all(0x20 <= byte <= 0x7E for byte in value) and any(
        chr(byte).isalpha() for byte in value
    )


def _key_value(node: ast.AST) -> bytes | None:
    """The 16 bytes a key-like node spells, or None if the node is not key-like.

    The printable-ASCII word exemption covers only a bytes literal written as text, such as a
    16-character token; a range or hex spelling of the same bytes is still a key literal.
    """
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bytes) and len(value) == _KEY_LENGTH and not _is_ascii_word(value):
            return value
        if (
            isinstance(value, str)
            and len(value) == 2 * _KEY_LENGTH
            and all(char in string.hexdigits for char in value)
        ):
            return bytes.fromhex(value)
    if isinstance(node, ast.Call):
        return _range_bytes(node)
    return None


def _allowed(value: bytes, path: str) -> bool:
    prefixes = _ALLOWED_KEYS.get(value)
    return prefixes is not None and path.startswith(prefixes)


def find_key_literals(source: str, path: str) -> list[KeyLiteral]:
    """Return every 16-byte key-like literal in ``source`` that the allow-list does not cover.

    Key-like is a 16-byte bytes constant, a 32-hex-char string or ``bytes(range(a, a + 16))``.
    ``path`` is the repo-relative POSIX path the allow-list prefixes are matched against.
    """
    hits = [
        KeyLiteral(path, node.lineno, value)
        for node in ast.walk(ast.parse(source, filename=path))
        if (value := _key_value(node)) is not None and not _allowed(value, path)
    ]
    return sorted(hits, key=lambda hit: hit.line)


def _scanned_files() -> list[Path]:
    return [
        path
        for directory in _SCAN_DIRS
        for path in sorted((REPO_ROOT / directory).rglob("*.py"))
        if "__pycache__" not in path.parts
    ]


def _planted(path: str, statement: str) -> list[KeyLiteral]:
    """Scan a synthetic module whose third line is ``statement``."""
    source = f'"""Planted module."""\n\n{statement}\n'
    return find_key_literals(source, path)


def test_repository_has_no_unexplained_key_literal() -> None:
    files = _scanned_files()
    assert any(path.name == "constants.py" for path in files), "scan found no source files"
    violations = [
        hit
        for path in files
        for hit in find_key_literals(
            path.read_text(encoding="utf-8"), path.relative_to(REPO_ROOT).as_posix()
        )
    ]
    assert not violations, "16-byte key literal outside the SAFE-03 allow-list:\n" + "\n".join(
        str(hit) for hit in violations
    )


def test_scanner_flags_a_planted_16_byte_bytes_literal() -> None:
    value = bytes(range(0x80, 0x80 + _KEY_LENGTH))
    literal = "b'" + "".join(f"\\x{byte:02x}" for byte in value) + "'"
    hits = _planted("src/interlock/planted.py", f"KEY = {literal}")
    assert hits == [KeyLiteral("src/interlock/planted.py", 3, value)]


def test_scanner_flags_a_planted_32_hex_char_string() -> None:
    hex_text = "a5" * _KEY_LENGTH
    hits = _planted("src/interlock/planted.py", f"KEY = '{hex_text}'")
    assert hits == [KeyLiteral("src/interlock/planted.py", 3, bytes.fromhex(hex_text))]


def test_scanner_flags_a_planted_16_byte_range() -> None:
    start = 0x50
    hits = _planted(
        "src/interlock/planted.py", f"KEY = bytes(range({start:#x}, {start + _KEY_LENGTH:#x}))"
    )
    assert hits == [
        KeyLiteral("src/interlock/planted.py", 3, bytes(range(start, start + _KEY_LENGTH)))
    ]


def _range_statement(value: bytes) -> str:
    return f"KEY = bytes(range({value[0]:#x}, {value[-1] + 1:#x}))"


def test_scanner_allows_scbk_d_anywhere() -> None:
    for path in ("src/interlock/planted.py", "lab/planted.py", "tests/planted.py"):
        assert _planted(path, _range_statement(_SCBK_D)) == [], path


def test_scanner_confines_the_lab_downgrade_key_to_lab_and_tests() -> None:
    statement = _range_statement(_LAB_DOWNGRADE_KEY)
    assert _planted("src/interlock/planted.py", statement) == [
        KeyLiteral("src/interlock/planted.py", 3, _LAB_DOWNGRADE_KEY)
    ]
    assert _planted("lab/planted.py", statement) == []
    assert _planted("tests/planted.py", statement) == []


def test_scanner_confines_the_synthetic_key_to_tests() -> None:
    statement = _range_statement(_SYNTHETIC_TEST_KEY)
    for path in ("src/interlock/planted.py", "lab/planted.py"):
        assert _planted(path, statement) == [KeyLiteral(path, 3, _SYNTHETIC_TEST_KEY)], path
    assert _planted("tests/planted.py", statement) == []


def test_scanner_ignores_a_printable_ascii_word_literal() -> None:
    word = "arm-" + "inline-relay"
    assert len(word) == _KEY_LENGTH
    assert _planted("src/interlock/planted.py", f"TOKEN = b'{word}'") == []


# D-04 no-hardware-path guard. --------------------------------------------------------------

_ASSESSMENT_MODULES = (
    "src/interlock/osdp/assessment.py",
    "src/interlock/osdp/lab_session.py",
    "src/interlock/osdp/attacks/assess.py",
)
_FORBIDDEN_IMPORTS = frozenset(
    {"safety", "serial", "open_serial_endpoint", "open_physical_endpoint"}
)


def forbidden_imports(source: str) -> list[str]:
    """Return every import in ``source`` that names a module or object of the physical path.

    An import is forbidden when a dotted part of its module path or one of the names it binds
    is in ``_FORBIDDEN_IMPORTS``; each is reported as ``line N: <the import statement>``.
    """
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            parts = {part for alias in node.names for part in alias.name.split(".")}
        elif isinstance(node, ast.ImportFrom):
            parts = set((node.module or "").split(".")) | {alias.name for alias in node.names}
        else:
            continue
        if parts & _FORBIDDEN_IMPORTS:
            found.append((node.lineno, ast.unparse(node)))
    return [f"line {line}: {statement}" for line, statement in sorted(found)]


def test_assess_help_offers_no_physical_option() -> None:
    result = CliRunner().invoke(app, ["osdp", "assess", "--help"])
    assert result.exit_code == 0, result.output
    assert "--output" in result.output
    assert "--physical" not in result.output
    assert "--device" not in result.output


def test_assessment_modules_import_nothing_from_the_physical_path() -> None:
    offenders = {
        module: found
        for module in _ASSESSMENT_MODULES
        if (found := forbidden_imports((REPO_ROOT / module).read_text(encoding="utf-8")))
    }
    assert not offenders, f"assessment modules reach the physical path: {offenders}"


def test_import_scan_flags_a_planted_physical_import() -> None:
    source = (
        "import serial\n"
        "from interlock.osdp import safety\n"
        "from interlock.osdp.safety import open_physical_endpoint\n"
        "from interlock.osdp.transport import open_serial_endpoint\n"
        "from interlock.osdp.transport import Direction\n"
    )
    assert forbidden_imports(source) == [
        "line 1: import serial",
        "line 2: from interlock.osdp import safety",
        "line 3: from interlock.osdp.safety import open_physical_endpoint",
        "line 4: from interlock.osdp.transport import open_serial_endpoint",
    ]


# SAFE-03 key-literal guard over git-tracked non-Python text files. ---------------------------

_DIGEST_LENGTHS = (40, 64)
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")


def find_text_key_literals(text: str, path: str) -> list[KeyLiteral]:
    """Return every run of 32 or more hex chars in ``text`` not covered by the allow-list.

    A run of exactly 32 hex chars is a 16-byte key and passes only if allow-listed for
    ``path``. Runs of 40 and 64 chars are SHA-1 and SHA-256 digest lengths (a pinned commit
    in a Dockerfile, a checksum) and are skipped; any other longer run is flagged.
    """
    hits: list[KeyLiteral] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for match in _HEX_RUN.finditer(line):
            run = match.group()
            if len(run) in _DIGEST_LENGTHS:
                continue
            value = bytes.fromhex(run[: len(run) // 2 * 2])
            if len(run) == 2 * _KEY_LENGTH and _allowed(value, path):
                continue
            hits.append(KeyLiteral(path, number, value))
    return hits


def _tracked_text_files() -> list[Path]:
    git = shutil.which("git")
    if git is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("git or the repository is unavailable")
    listed = subprocess.run(
        [git, "-C", str(REPO_ROOT), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.decode()
    paths = [REPO_ROOT / name for name in listed.split("\0") if name and not name.endswith(".py")]
    return [p for p in paths if p.is_file() and b"\0" not in p.read_bytes()]


def test_tracked_text_files_have_no_unexplained_key_literal() -> None:
    files = _tracked_text_files()
    assert any(path.name == "README.md" for path in files), "scan found no text files"
    violations = [
        hit
        for path in files
        for hit in find_text_key_literals(
            path.read_text(encoding="utf-8", errors="replace"),
            path.relative_to(REPO_ROOT).as_posix(),
        )
    ]
    assert not violations, "key literal in a tracked text file:\n" + "\n".join(
        str(hit) for hit in violations
    )


def test_text_scanner_flags_a_planted_hex_key_and_allows_scbk_d(tmp_path: Path) -> None:
    key = "a5" * _KEY_LENGTH
    planted = tmp_path / "planted.yml"
    planted.write_text(
        f"scbk: {key}\nok: {_SCBK_D.hex()}\nshort: {'ab' * 15}\nsha: {'c0' * 20}\n"
        f"odd: {'d1' * 24}\n",
        encoding="utf-8",
    )
    hits = find_text_key_literals(planted.read_text(encoding="utf-8"), "lab/planted.yml")
    assert hits == [
        KeyLiteral("lab/planted.yml", 1, bytes.fromhex(key)),
        KeyLiteral("lab/planted.yml", 5, bytes.fromhex("d1" * 24)),
    ]


def test_text_scanner_confines_the_lab_downgrade_key(tmp_path: Path) -> None:
    line = f"key: {_LAB_DOWNGRADE_KEY.hex().upper()}\n"
    assert find_text_key_literals(line, "lab/x.yml") == []
    assert find_text_key_literals(line, "docs/x.md") == [
        KeyLiteral("docs/x.md", 1, _LAB_DOWNGRADE_KEY)
    ]


# T-05-08 fuzz override containment and 05-08 ignored default outputs. ----------------------


def test_fuzz_override_publishes_no_ports_and_mounts_src_read_only() -> None:
    lines = [
        line.split("#", 1)[0].rstrip()
        for line in (REPO_ROOT / "docker-compose.fuzz.yml").read_text(encoding="utf-8").splitlines()
    ]
    keys = [line.strip().split(":", 1)[0] for line in lines if line.strip()]
    assert "ports" not in keys and "expose" not in keys
    mounts = [line.strip()[2:].strip() for line in lines if line.strip().startswith("- ")]
    assert mounts == ["./src:/app/src:ro"]
    assert "network_mode" not in keys and "networks" not in keys


@pytest.mark.parametrize("name", ["interlock-assessment.md", "interlock-assessment.json"])
def test_default_assessment_outputs_are_git_ignored(name: str) -> None:
    git = shutil.which("git")
    if git is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("git or the repository is unavailable")
    result = subprocess.run([git, "-C", str(REPO_ROOT), "check-ignore", "-q", name], check=False)
    assert result.returncode == 0, f"{name} is not git-ignored"
