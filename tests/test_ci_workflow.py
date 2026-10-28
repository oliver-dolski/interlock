"""The CI workflow contract (D-08..D-10), checked locally before the workflow ever runs.

There is no remote yet, so a workflow that drifted from what the README promises would only
show at the first push, and only if someone read the log. These tests read
``.github/workflows/ci.yml`` as text, because the development environment carries no YAML
parser; the job blocks are cut at the two-space-indented job keys under ``jobs:``. They prove
the file's shape, not that a GitHub run is green: that is only known after the first push.
"""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
EXACT_TAG = re.compile(r"^actions/(checkout|setup-python|upload-artifact)@v\d+\.\d+\.\d+$")
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def job_blocks() -> dict[str, str]:
    """Map each job name to the lines of its block, from its key to the next job key."""
    lines = workflow_text().splitlines()
    start = lines.index("jobs:") + 1
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines[start:]:
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        match = JOB_KEY.match(line)
        if match:
            current = match.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    return {name: "\n".join(body) for name, body in blocks.items()}


def test_every_action_is_pinned_to_an_exact_tag() -> None:
    uses = re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)\s*$", workflow_text(), re.MULTILINE)
    assert uses, "no uses: lines found"
    for value in uses:
        assert EXACT_TAG.match(value), f"not an exact first-party tag: {value}"


def test_triggers_and_permissions() -> None:
    text = workflow_text()
    head = text.split("\njobs:", 1)[0]
    for trigger in ("push:", "pull_request:", "workflow_dispatch:"):
        assert re.search(rf"^  {trigger}", head, re.MULTILINE), trigger
    assert re.search(r"^permissions:\n  contents: read\s*$", head, re.MULTILINE)
    assert "pull_request_target" not in text
    assert "secrets." not in text


def test_unit_job_covers_both_platforms_and_python_versions() -> None:
    unit = job_blocks()["unit"]
    for needle in (
        "ubuntu-latest",
        "windows-latest",
        '"3.11"',
        '"3.15"',
        "fail-fast: false",
        '-m "not lab"',
    ):
        assert needle in unit, needle
