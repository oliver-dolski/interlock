"""README claims are checked against the repository (D-14).

The finding the README quotes must be a verbatim excerpt of the committed example report, so
the first thing a reader sees cannot drift from the run it came from.
"""

from __future__ import annotations

import re
from pathlib import Path

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
