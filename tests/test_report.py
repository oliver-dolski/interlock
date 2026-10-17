"""Unit coverage for the plugin-agnostic report generator (CORE-04)."""

from __future__ import annotations

from interlock import report
from interlock.plugins.demo import DemoPlugin


def test_write_markdown_contains_all_six_finding_fields(tmp_path) -> None:
    finding = DemoPlugin().run()[0]
    report_path = tmp_path / "report.md"

    report.write_markdown([finding], report_path)

    text = report_path.read_text(encoding="utf-8")
    assert finding.id in text
    assert finding.title in text
    assert finding.severity.value in text
    assert finding.evidence in text
    assert finding.attack_technique in text
    assert finding.remediation in text


def test_render_terminal_outputs_id_and_severity(capsys) -> None:
    finding = DemoPlugin().run()[0]

    report.render_terminal([finding])

    captured = capsys.readouterr()
    assert finding.id in captured.out
    assert finding.severity.value in captured.out
