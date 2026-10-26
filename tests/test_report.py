"""Unit coverage for the plugin-agnostic report generator (CORE-04)."""

from __future__ import annotations

import json

import pytest

from interlock import plugin, report
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


def test_write_json_round_trips_the_demo_finding_with_the_notice(tmp_path) -> None:
    finding = DemoPlugin().run()[0]
    report_path = tmp_path / "report.json"

    report.write_json([finding], report_path)

    document = json.loads(report_path.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert document["notice"] == report.AUTHORIZED_USE_NOTICE
    assert plugin.finding_from_dict(document["findings"][0]) == finding


_LONG_DASHES = ("\u2014", "\u2013")


def _ics_finding() -> plugin.Finding:
    return plugin.Finding(
        id="X-2",
        title="downgraded session",
        severity=plugin.Severity.HIGH,
        evidence="e",
        attack_technique="T1689",
        remediation="r",
        attack_technique_ics="T0830",
    )


def test_write_markdown_section_order(tmp_path) -> None:
    finding = DemoPlugin().run()[0]
    report_path = tmp_path / "report.md"

    report.write_markdown([finding], report_path, title="X", preamble=["P"], appendix=["A"])

    text = report_path.read_text(encoding="utf-8")
    assert text.startswith("# X\n\n" + report.AUTHORIZED_USE_NOTICE + "\n\nP\n")
    positions = [
        text.index("# X"),
        text.index(report.AUTHORIZED_USE_NOTICE),
        text.index("\nP\n"),
        text.index(f"## {finding.id}: {finding.title}"),
        text.rindex("\nA"),
    ]
    assert positions == sorted(positions)
    assert text.endswith("\nA")


def test_write_markdown_ics_line_only_when_set(tmp_path) -> None:
    demo = DemoPlugin().run()[0]
    ics = _ics_finding()
    report_path = tmp_path / "report.md"

    report.write_markdown([demo, ics], report_path)

    text = report_path.read_text(encoding="utf-8")
    demo_section, ics_section = text.split(f"## {ics.id}: {ics.title}")
    assert "ATT&CK for ICS" not in demo_section
    assert "- **ATT&CK technique:** T1689\n- **ATT&CK for ICS:** T0830\n" in ics_section


def test_write_markdown_renders_mapped_technique_names(tmp_path) -> None:
    report_path = tmp_path / "report.md"

    report.write_markdown(
        [_ics_finding()], report_path, technique_names={"T1689": "Downgrade Attack"}
    )

    text = report_path.read_text(encoding="utf-8")
    assert "- **ATT&CK technique:** T1689 (Downgrade Attack)" in text
    assert "- **ATT&CK for ICS:** T0830\n" in text


def test_write_json_merges_metadata_and_creates_parents(tmp_path) -> None:
    report_path = tmp_path / "nested" / "dir" / "report.json"

    report.write_json([_ics_finding()], report_path, metadata={"tool": {"name": "interlock"}})

    document = json.loads(report_path.read_text(encoding="utf-8"))
    assert document["tool"] == {"name": "interlock"}
    assert document["schema_version"] == report.JSON_SCHEMA_VERSION
    assert document["notice"] == report.AUTHORIZED_USE_NOTICE
    assert plugin.finding_from_dict(document["findings"][0]) == _ics_finding()


def test_write_json_rejects_metadata_colliding_with_reserved_keys(tmp_path) -> None:
    report_path = tmp_path / "report.json"

    with pytest.raises(ValueError, match="notice"):
        report.write_json([_ics_finding()], report_path, metadata={"notice": "x"})
    assert not report_path.exists()


def test_rendered_reports_contain_no_long_dashes(tmp_path) -> None:
    findings = [DemoPlugin().run()[0], _ics_finding()]
    md_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"

    report.write_markdown(findings, md_path, technique_names={"T1689": "Downgrade Attack"})
    report.write_json(findings, json_path)

    for path in (md_path, json_path):
        text = path.read_text(encoding="utf-8")
        for dash in _LONG_DASHES:
            assert dash not in text
