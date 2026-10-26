"""Live @lab proof that ``interlock osdp assess`` runs the full assessment end to end (ASSESS-01/02).

Invokes the real command through Typer's CliRunner with no fakes: it drives the bundled lab at
the repo root through ``LabSession``, runs all seven assessment steps in order (each brings its
own scenario up and tears it down) and writes the Markdown report plus the JSON report next to
it. The JSON is the oracle. On the healthy lab the expected verdicts are: sniff-enumerate,
weak-key-keyset, downgrade, spoof and replay vulnerable; fuzz and cve-2024-52288-fixed
not_vulnerable, the latter quoting the fixed core's "Out of order REPLY_RMAC_I" rejection.

The test pins the finding ids each vulnerable step must report, that no fuzz finding and no
CVE-2024-52288 replay finding appear, that every finding carries severity, evidence, technique
and remediation with the technique taken from ``attack_map.MAPPINGS`` (ASSESS-02), that the
report records ATT&CK v20.0 and that both files carry the authorized-use notice. On a failure
the message carries every step's key, status and detail, so one live run is enough to diagnose.
One test, one real run: about 5-8 minutes on a warm Docker cache.

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
from interlock.osdp import attack_map
from interlock.osdp.assessment import STEPS

REPO_ROOT = Path(__file__).resolve().parents[2]

_EXPECTED_STATUSES = {
    "sniff-enumerate": "vulnerable",
    "fuzz": "not_vulnerable",
    "weak-key-keyset": "vulnerable",
    "downgrade": "vulnerable",
    "spoof": "vulnerable",
    "replay": "vulnerable",
    "cve-2024-52288-fixed": "not_vulnerable",
}
_EXPECTED_FINDING_IDS = {
    "ATK-01-sniff-pd-101",
    "ATK-02-enumerate-pd-101",
    "ATK-06-weak-key",
    "ATK-04-keyset",
    "ATK-03-downgrade",
    "ATK-08-spoof-unlock",
    "ATK-05a-replay-card-exchange",
}
_FORBIDDEN_PREFIXES = ("ATK-07-fuzz-", "ATK-05b-")
_RMAC_I_REJECTED = "Out of order REPLY_RMAC_I"

# Finding-id prefix -> the attack key whose technique the finding must cite.
_ATTACK_BY_PREFIX = {prefix: attack for step in STEPS for attack, prefix in step.attacks}


def _attack_of(finding_id: str) -> str:
    matches = [
        attack for prefix, attack in _ATTACK_BY_PREFIX.items() if finding_id.startswith(prefix)
    ]
    assert len(matches) == 1, f"{finding_id} matches attack prefixes {matches}"
    return matches[0]


@pytest.mark.lab
def test_osdp_assess_runs_the_real_lab_end_to_end(tmp_path: Path) -> None:
    md_path = tmp_path / "assessment.md"
    result = CliRunner().invoke(
        app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(REPO_ROOT)]
    )

    json_path = md_path.with_suffix(".json")
    assert md_path.is_file(), result.output
    assert json_path.is_file(), result.output
    document = json.loads(json_path.read_text(encoding="utf-8"))
    steps = document["steps"]
    diagnosis = "\n".join(f"{s['key']}: {s['status']}: {s['detail']}" for s in steps)
    context = f"{result.output}\nsteps:\n{diagnosis}"

    assert result.exit_code == 0, context

    markdown = md_path.read_text(encoding="utf-8")
    assert markdown.startswith("# interlock OSDP assessment"), context
    assert report.AUTHORIZED_USE_NOTICE in markdown
    assert document["schema_version"] == 1
    assert document["notice"] == report.AUTHORIZED_USE_NOTICE
    assert document["attack_version"] == attack_map.ATTACK_VERSION == "20.0"
    assert "MITRE ATT&CK v20.0" in markdown

    statuses = {step["key"]: step["status"] for step in steps}
    assert statuses == _EXPECTED_STATUSES, context

    by_key = {step["key"]: step for step in steps}
    assert _RMAC_I_REJECTED in by_key["cve-2024-52288-fixed"]["detail"], context

    finding_ids = {finding["id"] for finding in document["findings"]}
    assert _EXPECTED_FINDING_IDS <= finding_ids, (
        f"missing {_EXPECTED_FINDING_IDS - finding_ids}\n{context}"
    )
    unexpected = sorted(i for i in finding_ids if i.startswith(_FORBIDDEN_PREFIXES))
    assert not unexpected, f"unexpected findings {unexpected}\n{context}"

    for finding in document["findings"]:
        fid = finding["id"]
        for field in ("severity", "evidence", "attack_technique", "remediation"):
            assert finding[field], f"{fid} has an empty {field}"
        attack = _attack_of(fid)
        assert finding["attack_technique"] == attack_map.MAPPINGS[attack].enterprise, fid
        assert fid in markdown, fid

    for step in steps:
        assert set(step["finding_ids"]) <= finding_ids, step["key"]
        assert step["method"], step["key"]
