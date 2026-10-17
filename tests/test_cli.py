"""CLI robustness tests: bad input and report path handling."""

from __future__ import annotations

from typer.testing import CliRunner

from interlock.cli import app

runner = CliRunner()


def test_plugins_lists_demo() -> None:
    result = runner.invoke(app, ["plugins"])
    assert result.exit_code == 0
    assert "demo" in result.output


def test_run_unknown_plugin_exits_nonzero_and_lists_available() -> None:
    result = runner.invoke(app, ["run", "no-such-plugin"])
    assert result.exit_code != 0
    assert "demo" in result.output


def test_run_demo_writes_to_exact_output_path(tmp_path) -> None:
    report_path = tmp_path / "custom" / "my-report.md"
    result = runner.invoke(app, ["run", "demo", "-o", str(report_path)])
    assert result.exit_code == 0
    assert report_path.exists()
    assert "DEMO-001" in report_path.read_text(encoding="utf-8")
