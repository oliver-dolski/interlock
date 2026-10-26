"""SAFE-03 and D-04 guards: authorized-use statement, no long dashes, no key material.

SAFE-03: the README and every report state authorized, lab-by-default use, quoting
``report.AUTHORIZED_USE_NOTICE`` verbatim, and neither the README, the rendered reports nor
anything under ``src/`` carries a long dash.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from interlock import report
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
