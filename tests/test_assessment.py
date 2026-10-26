"""Host proof of ``interlock osdp assess`` and its orchestrator (ASSESS-01, no Docker).

A scripted fake compose runner is this plan's lab simulator: it records every (argv, env) it is
handed and answers by subcommand, ``up``/``down`` with exit 0, ``logs`` with both cp sentinels
and ``exec ... python -c <reader> <path>`` with the base64 of the committed cleartext tap capture
for that direction (chosen by the path's basename). Tests may read the fixtures; code under
src/ never does. ``lab_session.make_runner`` and ``lab_session.docker_available`` are
monkeypatched, so the real CLI runs end to end through the real ``LabSession``.
"""

from __future__ import annotations

import base64
import json
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from interlock import report
from interlock.cli import app
from interlock.osdp import lab_session
from interlock.osdp.assessment import (
    Inconclusive,
    Status,
    Step,
    StepOutput,
    StepResult,
    exit_code,
    run_assessment,
    write_reports,
)
from interlock.osdp.lab_session import LabSession
from interlock.plugin import Finding, Severity

FIXTURES_DIR = Path(__file__).resolve().parent / "osdp" / "fixtures"

_PD_ONLINE = "interlock-lab: PD 101 online"
_EVENT = "interlock-lab: event received"
_CP_LOG = f"cp-1  | {_PD_ONLINE}\ncp-1  | {_EVENT}\n"

# The live tap capture per in-container basename, from the committed cleartext fixtures.
_CAPTURES = {
    "cp2pd.cap": (FIXTURES_DIR / "cleartext_cp2pd.cap").read_bytes(),
    "pd2cp.cap": (FIXTURES_DIR / "cleartext_pd2cp.cap").read_bytes(),
}

# Flags of the base ``docker compose`` argv that take a value before the subcommand.
_VALUE_FLAGS = {"-p", "-f"}

runner = CliRunner()


def _subcommand(argv: Sequence[str]) -> str:
    """Return the compose subcommand of ``argv`` (the first token after the base flags)."""
    tokens = list(argv[2:])
    i = 0
    while i < len(tokens) and tokens[i] in _VALUE_FLAGS:
        i += 2
    return tokens[i]


class FakeCompose:
    """A recording ``Runner`` that simulates the lab per compose subcommand.

    ``returncodes`` and ``logs`` override the answer per subcommand; ``captures`` overrides
    the bytes returned for a capture basename (b"" simulates an empty capture).
    """

    def __init__(
        self,
        *,
        returncodes: Mapping[str, int] | None = None,
        logs: str = _CP_LOG,
        captures: Mapping[str, bytes] | None = None,
    ) -> None:
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.returncodes = dict(returncodes or {})
        self.logs = logs
        self.captures = {**_CAPTURES, **(captures or {})}

    @property
    def argvs(self) -> list[list[str]]:
        return [argv for argv, _ in self.calls]

    def __call__(
        self, argv: Sequence[str], env: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        self.calls.append((argv, dict(env)))
        sub = _subcommand(argv)
        if sub == "logs":
            stdout = self.logs
        elif sub == "exec":
            stdout = base64.b64encode(self.captures[PurePosixPath(argv[-1]).name]).decode()
        else:
            stdout = ""
        return subprocess.CompletedProcess(argv, self.returncodes.get(sub, 0), stdout, "")


def _base(lab: Path, *overrides: str) -> list[str]:
    files = ["-f", str(lab / "docker-compose.yml")]
    for override in overrides:
        files += ["-f", str(lab / override)]
    return ["docker", "compose", "-p", "interlock-assess", *files]


@pytest.fixture
def lab_dir(tmp_path: Path) -> Path:
    """A lab dir holding (empty) copies of the compose files the assessment requires."""
    lab = tmp_path / "lab"
    lab.mkdir()
    for name in ("docker-compose.yml", "docker-compose.tap.yml"):
        (lab / name).write_text("", encoding="utf-8")
    return lab.resolve()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeCompose:
    """Install a default ``FakeCompose`` as the lab runner and pretend Docker is on PATH."""
    compose = FakeCompose()
    monkeypatch.setattr(lab_session, "make_runner", lambda lab: compose)
    monkeypatch.setattr(lab_session, "docker_available", lambda: True)
    return compose


def test_assess_runs_sniff_enumerate_end_to_end(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose
) -> None:
    md_path = tmp_path / "out" / "assessment.md"
    result = runner.invoke(app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(lab_dir)])
    assert result.exit_code == 0, result.output
    assert "sniff-enumerate: vulnerable" in result.output

    json_path = tmp_path / "out" / "assessment.json"
    assert md_path.is_file() and json_path.is_file()

    markdown = md_path.read_text(encoding="utf-8")
    assert markdown.startswith("# interlock OSDP assessment\n\n" + report.AUTHORIZED_USE_NOTICE)
    assert "ATK-01-sniff-pd-101" in markdown
    assert "ATK-02-enumerate-pd-101" in markdown

    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert document["notice"] == report.AUTHORIZED_USE_NOTICE
    assert document["findings"]
    assert document["target"] == {"kind": "lab", "project": "interlock-assess"}
    step = document["steps"][0]
    assert step["key"] == "sniff-enumerate"
    assert step["status"] == "vulnerable"
    assert {"ATK-01-sniff-pd-101", "ATK-02-enumerate-pd-101"} <= set(step["finding_ids"])

    # Reset first, then the exact tap bring-up, and a final teardown for the same stack.
    tap = _base(lab_dir, "docker-compose.tap.yml")
    assert fake.argvs[0] == [*_base(lab_dir), "down", "-v"]
    assert fake.argvs[1] == [*tap, "up", "-d", "--build", "--force-recreate"]
    assert fake.calls[1][1]["LAB_SCENARIO"] == "cleartext"
    assert fake.argvs[-1] == [*tap, "down", "-v"]
    reads = [argv[-1] for argv in fake.argvs if _subcommand(argv) == "exec"]
    assert reads == ["/app/capture/cp2pd.cap", "/app/capture/pd2cp.cap"]


def test_assess_help_is_lab_only() -> None:
    result = runner.invoke(app, ["osdp", "assess", "--help"])
    assert result.exit_code == 0
    assert "--output" in result.stdout
    assert "--lab-dir" in result.stdout
    assert "--physical" not in result.stdout


# ---------------------------------------------------------------------------------------------
# Preflight: every failure exits 2 before anything runs or is written.


def _assert_nothing_written(tmp_path: Path, fake: FakeCompose) -> None:
    assert not (tmp_path / "out").exists()
    assert fake.calls == []


def test_preflight_docker_missing_exits_2_without_reports(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lab_session, "docker_available", lambda: False)
    md_path = tmp_path / "out" / "assessment.md"
    result = runner.invoke(app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(lab_dir)])
    assert result.exit_code == 2, result.output
    assert "Docker" in result.stderr
    _assert_nothing_written(tmp_path, fake)


def test_preflight_lab_dir_missing_override_exits_2_without_reports(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose
) -> None:
    (lab_dir / "docker-compose.tap.yml").unlink()
    md_path = tmp_path / "out" / "assessment.md"
    result = runner.invoke(app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(lab_dir)])
    assert result.exit_code == 2, result.output
    assert "docker-compose.tap.yml" in result.stderr
    _assert_nothing_written(tmp_path, fake)


def test_preflight_no_lab_dir_found_exits_2_without_reports(
    tmp_path: Path, fake: FakeCompose, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(empty)
    assert lab_session.find_lab_dir(Path.cwd()) is None
    md_path = tmp_path / "out" / "assessment.md"
    result = runner.invoke(app, ["osdp", "assess", "-o", str(md_path)])
    assert result.exit_code == 2, result.output
    assert "--lab-dir" in result.stderr
    _assert_nothing_written(tmp_path, fake)


def test_preflight_json_output_path_exits_2_without_reports(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose
) -> None:
    json_path = tmp_path / "out" / "assessment.json"
    result = runner.invoke(
        app, ["osdp", "assess", "-o", str(json_path), "--lab-dir", str(lab_dir)]
    )
    assert result.exit_code == 2, result.output
    assert ".json" in result.stderr
    _assert_nothing_written(tmp_path, fake)


# ---------------------------------------------------------------------------------------------
# Orchestrator: per-step isolation, statuses, exit codes and teardown.

_SYNTHETIC = Finding(
    id="SYN-01-synthetic-pd-101",
    title="Synthetic finding",
    severity=Severity.LOW,
    evidence="synthetic evidence",
    attack_technique="T1040",
    remediation="none",
)


def _step(key: str, run: Callable[[LabSession, dict[str, object]], StepOutput]) -> Step:
    return Step(
        key=key,
        title=f"Synthetic {key}",
        profile="cleartext",
        overrides=(),
        run=run,
        method="synthetic",
        clean_detail="synthetic clean",
        attacks=(),
    )


def _raise_inconclusive(session: LabSession, context: dict[str, object]) -> StepOutput:
    raise Inconclusive("PD never online")


def _raise_boom(session: LabSession, context: dict[str, object]) -> StepOutput:
    raise RuntimeError("boom")


def _one_finding(session: LabSession, context: dict[str, object]) -> StepOutput:
    return StepOutput(findings=(_SYNTHETIC,), detail="one synthetic finding")


def test_one_failing_step_never_loses_the_others_findings(
    tmp_path: Path, lab_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    steps = (
        _step("first", _raise_inconclusive),
        _step("second", _raise_boom),
        _step("third", _one_finding),
    )
    session = LabSession(lab_dir, runner=FakeCompose())
    results = run_assessment(session, steps=steps)

    assert [r.status.value for r in results] == ["inconclusive", "error", "vulnerable"]
    assert results[0].detail == "PD never online"
    assert results[1].detail == "RuntimeError: boom"
    assert results[2].findings == (_SYNTHETIC,)
    # The traceback goes to stderr only.
    assert "Traceback" in capsys.readouterr().err

    md_path = tmp_path / "out" / "assessment.md"
    json_path = write_reports(results, md_path, generated_at="2026-10-26T00:00:00+00:00")
    markdown = md_path.read_text(encoding="utf-8")
    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert _SYNTHETIC.id in markdown
    assert [f["id"] for f in document["findings"]] == [_SYNTHETIC.id]
    assert [s["status"] for s in document["steps"]] == ["inconclusive", "error", "vulnerable"]
    assert document["steps"][1]["detail"] == "RuntimeError: boom"
    assert "Traceback" not in markdown
    assert "Traceback" not in json_path.read_text(encoding="utf-8")


def _result(status: Status) -> StepResult:
    return StepResult(
        key=status.value,
        title=status.value,
        profile="cleartext",
        overrides=(),
        status=status,
        findings=(),
        detail="",
        method="synthetic",
        duration_s=0.0,
    )


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ((Status.VULNERABLE,), 0),
        ((Status.NOT_VULNERABLE,), 0),
        ((Status.VULNERABLE, Status.NOT_VULNERABLE), 0),
        ((Status.VULNERABLE, Status.INCONCLUSIVE), 1),
        ((Status.NOT_VULNERABLE, Status.ERROR), 1),
        ((Status.INCONCLUSIVE,), 1),
        ((Status.ERROR,), 1),
    ],
)
def test_exit_code_is_1_only_when_a_step_did_not_complete(
    statuses: tuple[Status, ...], expected: int
) -> None:
    assert exit_code([_result(status) for status in statuses]) == expected


def test_cli_exits_1_and_still_writes_both_reports_when_a_step_is_inconclusive(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose
) -> None:
    fake.captures["pd2cp.cap"] = b""
    md_path = tmp_path / "out" / "assessment.md"
    result = runner.invoke(app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(lab_dir)])
    assert result.exit_code == 1, result.output
    assert "sniff-enumerate: inconclusive" in result.output

    json_path = md_path.with_suffix(".json")
    assert md_path.is_file() and json_path.is_file()
    assert report.AUTHORIZED_USE_NOTICE in md_path.read_text(encoding="utf-8")
    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["steps"][0]["status"] == "inconclusive"
    assert fake.argvs[-1][-2:] == ["down", "-v"]


def test_a_step_raising_inside_its_scenario_is_torn_down_and_the_next_step_runs(
    lab_dir: Path,
) -> None:
    ran: list[str] = []

    def raise_inside(session: LabSession, context: dict[str, object]) -> StepOutput:
        with session.scenario("cleartext", ("docker-compose.tap.yml",)):
            raise RuntimeError("broke while the lab was up")

    def next_step(session: LabSession, context: dict[str, object]) -> StepOutput:
        ran.append("next")
        return StepOutput(findings=())

    fake = FakeCompose()
    after_step: dict[int, int] = {}
    results = run_assessment(
        LabSession(lab_dir, runner=fake),
        steps=(_step("raises", raise_inside), _step("next", next_step)),
        on_step=lambda index, total, result: after_step.__setitem__(index, len(fake.calls)),
    )

    tap = _base(lab_dir, "docker-compose.tap.yml")
    first = fake.argvs[: after_step[1]]
    assert first[-2] == [*tap, "up", "-d", "--build", "--force-recreate"]
    assert first[-1] == [*tap, "down", "-v"]
    assert ran == ["next"]
    assert [r.status.value for r in results] == ["error", "not_vulnerable"]
    assert results[1].detail == "synthetic clean"


# ---------------------------------------------------------------------------------------------
# The sniff-enumerate step: unmet preconditions are inconclusive, lab failures are errors.


class FakeClock:
    """A monotonic clock that only advances when ``sleep`` is called."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.mark.parametrize(
    ("logs", "missing"),
    [
        ("cp-1  | interlock-lab: starting\n", "PD 101 online"),
        (f"cp-1  | {_PD_ONLINE}\n", "card-read event"),
    ],
)
def test_sniff_enumerate_times_out_as_inconclusive_without_real_sleeping(
    lab_dir: Path, logs: str, missing: str
) -> None:
    clock = FakeClock()
    fake = FakeCompose(logs=logs)
    session = LabSession(lab_dir, runner=fake, sleep=clock.sleep, clock=clock)

    started = time.monotonic()
    results = run_assessment(session, clock=clock)
    assert time.monotonic() - started < 10.0

    assert results[0].status is Status.INCONCLUSIVE
    assert missing in results[0].detail
    assert clock.now >= 90.0
    assert not [argv for argv in fake.argvs if _subcommand(argv) == "exec"]
    assert fake.argvs[-1][-2:] == ["down", "-v"]


@pytest.mark.parametrize("basename", ["cp2pd.cap", "pd2cp.cap"])
def test_sniff_enumerate_with_an_empty_capture_is_inconclusive(
    lab_dir: Path, basename: str
) -> None:
    fake = FakeCompose(captures={basename: b""})
    results = run_assessment(LabSession(lab_dir, runner=fake))
    assert results[0].status is Status.INCONCLUSIVE
    assert "empty" in results[0].detail
    assert results[0].findings == ()


@pytest.mark.parametrize(
    ("failing", "message"),
    [
        ("logs", "LabError: docker compose logs cp failed (exit 1)"),
        ("up", "LabError: docker compose up (cleartext) failed (exit 1)"),
    ],
)
def test_sniff_enumerate_lab_error_is_mapped_to_error(
    lab_dir: Path, failing: str, message: str
) -> None:
    fake = FakeCompose(returncodes={failing: 1})
    results = run_assessment(LabSession(lab_dir, runner=fake))
    assert results[0].status is Status.ERROR
    assert results[0].detail.startswith(message)
    assert fake.argvs[-1][-2:] == ["down", "-v"]
