"""The OSDP assessment orchestrator behind ``interlock osdp assess`` (ASSESS-01).

An assessment is an ordered tuple of ``Step``s. Each step brings one bundled lab scenario up
through the 05-07 wrapper (``with session.scenario(profile, overrides) as lab:``), proves its
lab precondition from the cp log sentinels, runs the existing Phase 4 verdict functions over
live lab output and returns the findings. ``run_assessment`` runs every step in order and
records one ``StepResult`` per step with an explicit ``Status``:

- findings -> ``vulnerable``; no findings -> ``not_vulnerable`` (only after the step proved
  its precondition and ran to completion);
- ``Inconclusive`` raised by the step (an unmet precondition: PD never online, empty capture)
  -> ``inconclusive``, never a silent clean result;
- any other ``Exception`` -> ``error`` with ``"TypeName: message"``; the traceback goes to
  stderr only, never into a report. ``KeyboardInterrupt`` is not caught, so Ctrl-C unwinds
  through the scenario's ``finally`` and the lab is still torn down.

One failing step never loses the findings of the others. ``write_reports`` writes the Markdown
and the JSON report through ``interlock.report``, so both carry the authorized-use notice.

Lab-only by design (D-04): the only lab access is ``LabSession``; this module imports nothing
from the physical (SAFE-02) path and never reads committed test fixtures. Every finding comes
from a live capture or a live oracle.
"""

from __future__ import annotations

import enum
import sys
import time
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

import interlock
from interlock import report
from interlock.osdp import lab_session
from interlock.osdp.attacks.enumerate import run_enumerate
from interlock.osdp.attacks.sniff import decode_chunks, run_sniff
from interlock.osdp.lab_session import LabSession
from interlock.osdp.tap_capture import CP2PD_PATH, PD2CP_PATH
from interlock.osdp.transport import Direction
from interlock.plugin import Finding

_console = Console()

# cp log sentinels printed by the lab drivers (lab/osdp), with the waits the @lab suite uses.
PD_ONLINE = "interlock-lab: PD 101 online"
EVENT_RECEIVED = "interlock-lab: event received"
_PD_ONLINE_TIMEOUT = 180.0
_EVENT_TIMEOUT = 90.0

REPORT_TITLE = "interlock OSDP assessment"


class Status(str, enum.Enum):
    """The outcome of one assessment step."""

    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class Inconclusive(Exception):
    """A step's lab precondition was not proven, so no verdict can be given."""


@dataclass(frozen=True)
class StepOutput:
    """What a step function returns: its findings and an optional detail line."""

    findings: tuple[Finding, ...]
    detail: str = ""


@dataclass(frozen=True)
class Step:
    """One assessment step: a lab scenario, the function that runs it and how it is reported.

    ``attacks`` pairs each attack key the step covers with that attack's finding-id prefix.
    """

    key: str
    title: str
    profile: str
    overrides: tuple[str, ...]
    run: Callable[[LabSession, dict[str, object]], StepOutput]
    method: str
    clean_detail: str
    attacks: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class StepResult:
    """The recorded outcome of one step."""

    key: str
    title: str
    profile: str
    overrides: tuple[str, ...]
    status: Status
    findings: tuple[Finding, ...]
    detail: str
    method: str
    duration_s: float


def _require_log(lab: lab_session.LabHandle, needle: str, timeout: float, what: str) -> None:
    """Raise ``Inconclusive`` unless the cp log shows ``needle`` within ``timeout`` seconds."""
    if not lab.wait_for_log("cp", needle, timeout=timeout):
        raise Inconclusive(f"{what} not observed in the cp log within {timeout:.0f} s")


# sniff-enumerate: the cleartext lab with interlock's read-only TCP tap in the attacker position.
_SNIFF_PROFILE = "cleartext"
_SNIFF_OVERRIDES = ("docker-compose.tap.yml",)


def _sniff_enumerate(session: LabSession, context: dict[str, object]) -> StepOutput:
    """Read both live tap captures and fold them into ATK-01 and ATK-02 findings."""
    with session.scenario(_SNIFF_PROFILE, _SNIFF_OVERRIDES) as lab:
        _require_log(lab, PD_ONLINE, _PD_ONLINE_TIMEOUT, "PD 101 online")
        _require_log(lab, EVENT_RECEIVED, _EVENT_TIMEOUT, "card-read event")
        cp2pd = lab.read_capture(CP2PD_PATH.as_posix())
        pd2cp = lab.read_capture(PD2CP_PATH.as_posix())
    if not cp2pd:
        raise Inconclusive("the cp->pd tap capture is empty")
    if not pd2cp:
        raise Inconclusive("the pd->cp tap capture is empty")

    frames = decode_chunks([(Direction.cp_to_pd, cp2pd), (Direction.pd_to_cp, pd2cp)])
    context["cleartext_frames"] = frames
    findings = [*run_sniff(frames), *run_enumerate(frames)]
    return StepOutput(
        findings=tuple(findings),
        detail=f"{len(frames)} frames decoded from {len(cp2pd) + len(pd2cp)} captured bytes",
    )


STEPS: tuple[Step, ...] = (
    Step(
        key="sniff-enumerate",
        title="Passive bus sniffing and device enumeration",
        profile=_SNIFF_PROFILE,
        overrides=_SNIFF_OVERRIDES,
        run=_sniff_enumerate,
        method=(
            "The read-only TCP tap in the attacker position records both directions of one "
            "cleartext CP-PD session; the captures are decoded with the interlock OSDP codec "
            "and folded into the PD topology (sniff) and the PD identity and capabilities "
            "(enumerate)."
        ),
        clean_detail="The live captures decoded to no PD topology, identity or capabilities.",
        attacks=(("sniff", "ATK-01-"), ("enumerate", "ATK-02-")),
    ),
)


def _describe(exc: BaseException) -> str:
    """Return ``"TypeName: message"`` for ``exc`` (no traceback, no environment)."""
    return f"{type(exc).__name__}: {exc}"


def run_assessment(
    session: LabSession,
    *,
    steps: Sequence[Step] = STEPS,
    clock: Callable[[], float] = time.monotonic,
    on_step: Callable[[int, int, StepResult], None] | None = None,
) -> list[StepResult]:
    """Run every step in order and return one ``StepResult`` per step.

    The project is reset once first (``down -v``) to clear leftovers of an interrupted run.
    ``on_step(index, total, result)`` is called after each step, ``index`` counting from 1.
    """
    session.reset()
    context: dict[str, object] = {}
    results: list[StepResult] = []
    total = len(steps)
    for index, step in enumerate(steps, start=1):
        started = clock()
        findings: tuple[Finding, ...] = ()
        try:
            output = step.run(session, context)
        except Inconclusive as exc:
            status, detail = Status.INCONCLUSIVE, str(exc)
        except Exception as exc:  # noqa: BLE001 - one failing step must not lose the others
            traceback.print_exc(file=sys.stderr)
            status, detail = Status.ERROR, _describe(exc)
        else:
            findings = tuple(output.findings)
            if findings:
                status, detail = Status.VULNERABLE, output.detail
            else:
                status, detail = Status.NOT_VULNERABLE, output.detail or step.clean_detail
        result = StepResult(
            key=step.key,
            title=step.title,
            profile=step.profile,
            overrides=step.overrides,
            status=status,
            findings=findings,
            detail=detail,
            method=step.method,
            duration_s=round(clock() - started, 1),
        )
        results.append(result)
        if on_step is not None:
            on_step(index, total, result)
    return results


def exit_code(results: Sequence[StepResult]) -> int:
    """Return 1 when any step is inconclusive or error, else 0."""
    incomplete = {Status.INCONCLUSIVE, Status.ERROR}
    return 1 if any(result.status in incomplete for result in results) else 0


def required_files(steps: Sequence[Step] = STEPS) -> tuple[str, ...]:
    """Return the compose files the steps need under the lab dir, base file first."""
    files = [lab_session.COMPOSE_FILE]
    for step in steps:
        for override in step.overrides:
            if override not in files:
                files.append(override)
    return tuple(files)


_COLUMNS = ("Step", "Profile", "Status", "Findings", "Duration (s)")


def _row(result: StepResult) -> tuple[str, str, str, str, str]:
    return (
        result.key,
        result.profile,
        result.status.value,
        str(len(result.findings)),
        f"{result.duration_s:.1f}",
    )


def _steps_table(results: Sequence[StepResult]) -> list[str]:
    """Return the Markdown "## Steps" section summarising every step."""
    lines = ["## Steps", "", "| " + " | ".join(_COLUMNS) + " |", "|" + "---|" * len(_COLUMNS)]
    for result in results:
        lines.append("| " + " | ".join(_row(result)) + " |")
    lines.append("")
    return lines


def _step_dict(result: StepResult) -> dict[str, object]:
    return {
        "key": result.key,
        "title": result.title,
        "profile": result.profile,
        "overrides": list(result.overrides),
        "status": result.status.value,
        "detail": result.detail,
        "method": result.method,
        "duration_s": result.duration_s,
        "finding_ids": [finding.id for finding in result.findings],
    }


def write_reports(results: Sequence[StepResult], md_path: Path, *, generated_at: str) -> Path:
    """Write the Markdown report to ``md_path`` and the JSON next to it; return the JSON path.

    Findings appear in step order. Neither report carries raw capture bytes or tracebacks.
    """
    findings = [finding for result in results for finding in result.findings]
    report.write_markdown(
        findings,
        md_path,
        title=REPORT_TITLE,
        preamble=_steps_table(results),
    )
    json_path = md_path.with_suffix(".json")
    report.write_json(
        findings,
        json_path,
        metadata={
            "tool": {"name": "interlock", "version": interlock.__version__},
            "generated_at": generated_at,
            "target": {"kind": "lab", "project": lab_session.DEFAULT_PROJECT},
            "steps": [_step_dict(result) for result in results],
        },
    )
    return json_path


def render_step_table(results: Sequence[StepResult]) -> None:
    """Print the per-step summary as a rich table to the terminal."""
    table = Table(title=REPORT_TITLE)
    for column in _COLUMNS:
        table.add_column(column)
    for result in results:
        table.add_row(*_row(result))
    _console.print(table)
