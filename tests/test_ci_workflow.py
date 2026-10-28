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


def test_all_jobs_exist() -> None:
    assert set(job_blocks()) == {"lint", "type", "unit", "build", "lab-smoke", "lab-full"}


def test_lab_jobs_run_on_ubuntu_only() -> None:
    blocks = job_blocks()
    for name, block in blocks.items():
        if name != "unit":
            assert "windows-latest" not in block, name
    for name in ("lab-smoke", "lab-full"):
        assert re.search(r"^    runs-on: ubuntu-latest$", blocks[name], re.MULTILINE), name


def test_lab_smoke_runs_the_assessment_and_checks_the_notice() -> None:
    smoke = job_blocks()["lab-smoke"]
    for needle in (
        "python -m pip install .\n",
        "interlock osdp assess",
        "AUTHORIZED_USE_NOTICE",
        "doc['notice']",
        "actions/upload-artifact@",
        "if: always()",
        "timeout-minutes:",
    ):
        assert needle in smoke + "\n", needle


def test_full_lab_runs_only_on_dispatch() -> None:
    full = job_blocks()["lab-full"]
    assert "if: github.event_name == 'workflow_dispatch'" in full
    assert re.search(r"pytest -q -m lab\s*$", full, re.MULTILINE)


def test_build_job_gates_the_dists() -> None:
    build = job_blocks()["build"]
    for needle in ("python -m build", "python scripts/check_dist.py dist", "twine check --strict"):
        assert needle in build, needle


def test_lint_and_type_jobs() -> None:
    blocks = job_blocks()
    assert "ruff check src tests scripts" in blocks["lint"]
    assert "mypy src" in blocks["type"]


def test_no_format_check_step() -> None:
    steps = [line for line in workflow_text().splitlines() if not line.lstrip().startswith("#")]
    assert not any("ruff format" in line for line in steps)
