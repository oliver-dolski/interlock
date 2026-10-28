"""README claims are checked against the repository (D-14).

The finding the README quotes must be a verbatim excerpt of the committed example report, so
the first thing a reader sees cannot drift from the run it came from.
"""

from __future__ import annotations

import re
from pathlib import Path

from interlock.osdp.attack_map import ACCESS_VECTOR, MAPPINGS, technique_names

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
EXAMPLE_REPORT = REPO_ROOT / "docs" / "examples" / "assessment.md"

_TEXT_BLOCK = re.compile(r"^```text\n(.*?)^```", re.MULTILINE | re.DOTALL)


def _normalized(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _readme_text() -> str:
    assert README.is_file(), f"{README} is missing"
    return _normalized(README)


def _section(text: str, heading: str) -> str:
    """The body of a level-2 section, up to the next level-2 heading outside a code block."""
    marker = f"## {heading}\n"
    assert marker in text, f"README has no '## {heading}' section"
    body = text.split(marker, 1)[1]
    in_code = False
    lines: list[str] = []
    for line in body.split("\n"):
        if line.startswith("```"):
            in_code = not in_code
        elif not in_code and line.startswith("## "):
            break
        lines.append(line)
    return "\n".join(lines)


def _quoted_finding() -> str:
    blocks = _TEXT_BLOCK.findall(_section(_readme_text(), "What a finding looks like"))
    assert blocks, "'What a finding looks like' has no ```text block"
    return str(blocks[0])


def test_quoted_finding_is_verbatim_from_the_example_report() -> None:
    block = _quoted_finding()
    assert len(block.strip().splitlines()) >= 5, "the quoted finding is too short"
    assert block in _normalized(EXAMPLE_REPORT), (
        "the README's quoted finding is not a verbatim excerpt of docs/examples/assessment.md"
    )


def test_quoted_finding_is_the_live_spoof_finding() -> None:
    block = _quoted_finding()
    assert "ATK-08-spoof-unlock" in block
    assert "critical" in block


# ATT&CK table and technique ids. ---------------------------------------------------------

_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_ATTACK_START = "<!-- attack:start -->"
_ATTACK_END = "<!-- attack:end -->"


def _split_at_attack_table(text: str) -> tuple[str, str, str]:
    """The README before, inside and after the ATT&CK table markers."""
    assert text.count(_ATTACK_START) == 1, "README needs exactly one attack:start marker"
    assert text.count(_ATTACK_END) == 1, "README needs exactly one attack:end marker"
    before, rest = text.split(_ATTACK_START, 1)
    inside, after = rest.split(_ATTACK_END, 1)
    return before, inside, after


def _table_rows(table: str) -> list[list[str]]:
    rows = [line for line in table.splitlines() if line.startswith("|")]
    assert len(rows) >= 2, "the ATT&CK table has no header and separator"
    body = rows[2:]
    return [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in body]


def test_attack_table_matches_attack_map() -> None:
    _, table, _ = _split_at_attack_table(_readme_text())
    names = technique_names()
    seen: set[str] = set()
    for row in _table_rows(table):
        assert len(row) == 3, f"an ATT&CK row needs three cells: {row}"
        capability, enterprise, ics = row
        key_match = re.search(r"`([^`]+)`", capability)
        assert key_match, f"no backticked MAPPINGS key in {capability!r}"
        key = key_match.group(1)
        assert key in MAPPINGS, f"{key!r} is not a MAPPINGS key"
        assert key not in seen, f"{key!r} appears twice in the table"
        seen.add(key)
        technique = MAPPINGS[key]
        assert set(_TECHNIQUE_ID.findall(enterprise)) == {technique.enterprise}, (
            f"{key}: Enterprise cell {enterprise!r} is not {technique.enterprise}"
        )
        assert names[technique.enterprise] in enterprise, f"{key}: Enterprise name missing"
        if technique.ics is None:
            assert not _TECHNIQUE_ID.findall(ics), f"{key}: ICS cell should carry no id"
        else:
            assert set(_TECHNIQUE_ID.findall(ics)) == {technique.ics}, (
                f"{key}: ICS cell {ics!r} is not {technique.ics}"
            )
            assert names[technique.ics] in ics, f"{key}: ICS name missing"
    assert seen == set(MAPPINGS), f"table keys differ from MAPPINGS: {seen ^ set(MAPPINGS)}"


def test_every_technique_id_in_the_readme_is_known() -> None:
    known = technique_names()
    unknown = sorted(set(_TECHNIQUE_ID.findall(_readme_text())) - set(known))
    assert not unknown, f"README cites technique ids attack_map.py does not know: {unknown}"


def test_access_vector_is_named_outside_the_table() -> None:
    before, table, after = _split_at_attack_table(_readme_text())
    vector = f"{ACCESS_VECTOR.enterprise} {ACCESS_VECTOR.enterprise_name}"
    assert ACCESS_VECTOR.enterprise not in table, "the access vector is not a per-row technique"
    assert vector in before + after, f"README does not name the access vector {vector!r}"


# Links, badges and the quickstart. -------------------------------------------------------

_LINK_TARGET = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")
_REPO_URL = "https://github.com/oliver-dolski/interlock"


def test_readme_links_resolve() -> None:
    missing = []
    for target in _LINK_TARGET.findall(_readme_text()):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            continue
        path = target.split("#", 1)[0]
        if not (REPO_ROOT / path).exists():
            missing.append(target)
    assert not missing, f"README links to paths that do not exist: {missing}"


def test_readme_badges() -> None:
    text = _readme_text()
    workflow = f"{_REPO_URL}/actions/workflows/ci.yml"
    assert f"[![CI]({workflow}/badge.svg)]({workflow})" in text
    assert "[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)" in (
        text
    )
    assert (REPO_ROOT / ".github" / "workflows" / "ci.yml").is_file()
    assert (REPO_ROOT / "LICENSE").is_file()


def test_quickstart_is_clone_based() -> None:
    quickstart = _section(_readme_text(), "Quickstart (lab)")
    assert f"git clone {_REPO_URL}.git" in quickstart
    index_install = re.compile(
        r"\b(?:pip|pipx|uv pip|uv tool)\s+install\s+(?:-\S+\s+)*[\"']?interlock\b", re.IGNORECASE
    )
    offenders = [line for line in _readme_text().splitlines() if index_install.search(line)]
    assert not offenders, f"README installs interlock from an index: {offenders}"


# Honesty limits. -------------------------------------------------------------------------


def _example_containment_clause() -> str:
    match = re.search(
        r"so no lab container.*?\(not covered:[^)]*\)", _normalized(EXAMPLE_REPORT), re.DOTALL
    )
    assert match, "the example report has no containment clause"
    return match.group(0)


def test_readme_does_not_overclaim() -> None:
    text = _readme_text()
    lowered = text.lower()
    for match in re.finditer("guarantee", lowered):
        assert lowered[: match.start()].endswith("not a "), (
            f"'guarantee' without 'not a ' at offset {match.start()}"
        )
    for line in text.splitlines():
        if "ENFORCE_SECURE" in line or "enforces Secure Channel" in line:
            assert "host test" in line, f"enforce-secure claim without 'host test': {line!r}"
        if "byte-exact" in line:
            assert "host" in line, f"byte-exact claim without 'host': {line!r}"
    collapsed = " ".join(text.split())
    clause = " ".join(_example_containment_clause().split())
    assert clause in collapsed, "README does not quote the report's containment clause verbatim"
    assert "no real hardware is reachable" not in collapsed.lower()
