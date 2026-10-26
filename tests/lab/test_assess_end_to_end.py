"""Live @lab proof that ``interlock osdp assess`` runs the full assessment end to end (ASSESS-01).

Invokes the real command through Typer's CliRunner with no fakes: it drives the bundled lab at
the repo root through ``LabSession``, runs every assessment step in order and writes the
Markdown report plus the JSON report next to it. The test asserts exit code 0, that both files
exist and carry the authorized-use notice, that every step completed (vulnerable or
not_vulnerable) and that the sniff-enumerate step reports ATK-01-sniff-pd-101 and
ATK-02-enumerate-pd-101. The assertions over ``steps[]`` are generic, so the test keeps holding
as more steps join the assessment.

Uses its own compose project, interlock-assess, so it never collides with the interlock-lab
project the rest of this suite uses. Adds no published port: captures leave the attacker
container only through ``docker compose exec``, so SAFE-01 containment is unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from interlock import report
from interlock.cli import app

REPO_ROOT = Path(__file__).resolve().parents[2]

_COMPLETED = {"vulnerable", "not_vulnerable"}


@pytest.mark.lab
def test_osdp_assess_runs_the_real_lab_end_to_end(tmp_path: Path) -> None:
    md_path = tmp_path / "assessment.md"
    result = CliRunner().invoke(
        app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(REPO_ROOT)]
    )
    assert result.exit_code == 0, result.output

    json_path = md_path.with_suffix(".json")
    assert md_path.is_file(), result.output
    assert json_path.is_file(), result.output

    markdown = md_path.read_text(encoding="utf-8")
    assert markdown.startswith("# interlock OSDP assessment")
    assert report.AUTHORIZED_USE_NOTICE in markdown

    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert document["notice"] == report.AUTHORIZED_USE_NOTICE

    steps = document["steps"]
    assert steps, "the assessment ran no steps"
    incomplete = {step["key"]: step["status"] for step in steps if step["status"] not in _COMPLETED}
    assert not incomplete, f"steps did not complete: {incomplete}"

    by_key = {step["key"]: step for step in steps}
    sniff = by_key["sniff-enumerate"]
    assert sniff["status"] == "vulnerable"
    assert {"ATK-01-sniff-pd-101", "ATK-02-enumerate-pd-101"} <= set(sniff["finding_ids"])

    finding_ids = {finding["id"] for finding in document["findings"]}
    for step in steps:
        assert set(step["finding_ids"]) <= finding_ids, step["key"]
        for finding_id in step["finding_ids"]:
            assert finding_id in markdown, finding_id
