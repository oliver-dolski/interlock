"""End-to-end walking-skeleton tests: discover, run, report."""

from __future__ import annotations

from typer.testing import CliRunner

from interlock import report
from interlock.cli import app

runner = CliRunner()


def test_plugins_lists_demo() -> None:
    result = runner.invoke(app, ["plugins"])
    assert result.exit_code == 0
    assert "demo" in result.output


def test_run_demo_writes_report(tmp_path) -> None:
    report_path = tmp_path / "report.md"
    result = runner.invoke(app, ["run", "demo", "-o", str(report_path)])
    assert result.exit_code == 0
    assert report_path.exists()
    text = report_path.read_text(encoding="utf-8")
    assert "DEMO-001" in text
    assert text.startswith("# interlock findings\n\n" + report.AUTHORIZED_USE_NOTICE)
