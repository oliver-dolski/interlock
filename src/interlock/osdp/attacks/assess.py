"""``interlock osdp assess``: one command, a full assessment of the bundled lab (ASSESS-01).

Runs every ``interlock.osdp.assessment`` step against the bundled lab through ``LabSession``
(its own compose project, ``down -v`` after every bring-up) and writes a Markdown report plus a
JSON report next to it (same stem, ``.json``), both carrying the authorized-use notice.

Lab-only (D-04): there is no --physical, --device or --target option and this module imports
nothing from the physical (SAFE-02) path. Preflight fails closed with exit 2 before anything is
written: Docker not on PATH, no lab dir, a required compose file missing, or a ``.json``
output path (which would collide with the JSON written next to the Markdown).

Exit codes: 0 when every step completed (vulnerable or not_vulnerable), 1 when the reports
were written but a step is inconclusive or error, 2 when preflight fails.

Import discipline: ``typer`` and the assessment module are imported lazily, inside
``register`` and the command, so the attacks package stays importable in the lab image.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    import typer

_DEFAULT_OUTPUT = Path("interlock-assessment.md")


def register(app: typer.Typer) -> None:
    """Attach the ``assess`` subcommand to the ``osdp`` Typer group."""
    import typer

    @app.command("assess")
    def assess(
        output: Path = typer.Option(
            _DEFAULT_OUTPUT,
            "--output",
            "-o",
            help="Markdown report path; the JSON report is written next to it (.json).",
        ),
        lab_dir: Path | None = typer.Option(
            None,
            "--lab-dir",
            help="Directory holding the bundled compose files (default: search from the cwd).",
        ),
    ) -> None:
        """Run the full OSDP assessment against the bundled lab and write the reports."""
        from datetime import UTC, datetime

        from interlock.osdp import assessment, lab_session

        def fail(message: str) -> NoReturn:
            typer.echo(f"interlock osdp assess: {message}", err=True)
            raise typer.Exit(code=2)

        if output.suffix.lower() == ".json":
            fail(f"--output {output} ends in .json; give the Markdown path, the JSON is "
                 "written next to it")
        if not lab_session.docker_available():
            fail("Docker is not on PATH; the assessment runs only against the bundled lab")
        if lab_dir is None:
            lab_dir = lab_session.find_lab_dir(Path.cwd())
            if lab_dir is None:
                fail("no lab dir found in the cwd or its parents; pass --lab-dir")
        missing = [name for name in assessment.required_files() if not (lab_dir / name).is_file()]
        if missing:
            fail(f"lab dir {lab_dir} lacks {', '.join(missing)}")

        typer.echo(
            "Running the OSDP assessment against the bundled lab. The first run builds the "
            "lab images (LibOSDP compiles from source) and can take several minutes."
        )

        def on_step(index: int, total: int, result: assessment.StepResult) -> None:
            typer.echo(
                f"[{index}/{total}] {result.key}: {result.status.value} "
                f"({len(result.findings)} findings, {result.duration_s:.1f} s)"
            )

        session = lab_session.LabSession(lab_dir, runner=lab_session.make_runner(lab_dir))
        results = assessment.run_assessment(session, on_step=on_step)
        generated_at = datetime.now(UTC).isoformat(timespec="seconds")
        json_path = assessment.write_reports(results, output, generated_at=generated_at)
        assessment.render_step_table(results)
        typer.echo(f"Wrote Markdown report to {output}")
        typer.echo(f"Wrote JSON report to {json_path}")
        raise typer.Exit(code=assessment.exit_code(results))
