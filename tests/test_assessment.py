"""Host proof of ``interlock osdp assess`` and its orchestrator (ASSESS-01, no Docker).

A scripted fake compose runner is this plan's lab simulator: it records every (argv, env) it is
handed and answers by subcommand, ``up``/``down`` with exit 0, ``logs <service>`` with that
service's healthy-lab sentinels, ``exec ... python -c <reader> <path>`` with the base64 of the
committed cleartext tap capture for that direction (chosen by the path's basename) and the
in-container fuzz sweep with its canned stdout. Tests may read the fixtures; code under src/
never does. ``lab_session.make_runner`` and ``lab_session.docker_available`` are
monkeypatched, so the real CLI runs end to end through the real ``LabSession``.
"""

from __future__ import annotations

import ast
import base64
import json
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from interlock import report
from interlock.cli import app
from interlock.osdp import (
    assessment,
    attack_map,
    codec,
    constants,
    framer,
    lab_session,
    secure_channel,
)
from interlock.osdp.assessment import (
    _FUZZ_SCRIPT,
    STEPS,
    Inconclusive,
    Status,
    Step,
    StepOutput,
    StepResult,
    exit_code,
    required_files,
    run_assessment,
    write_reports,
)
from interlock.osdp.attacks import downgrade
from interlock.osdp.lab_session import LabSession
from interlock.osdp.transport import Direction
from interlock.plugin import Finding, Severity, finding_to_dict

FIXTURES_DIR = Path(__file__).resolve().parent / "osdp" / "fixtures"

_PD_ONLINE = "interlock-lab: PD 101 online"
_EVENT = "interlock-lab: event received"
_CP_LOG = f"cp-1  | {_PD_ONLINE}\ncp-1  | {_EVENT}\n"
_PD_LISTENING = "interlock-lab: PD listening on 0.0.0.0:10000"
# A healthy PD under the fuzz sweep: listening, then one LibOSDP parser-rejection line.
_PD_REJECTED = "pd-1  | OSDP: PD: Invalid CRC 0x1234; expected 0x5678\n"
_PD_LOG = f"pd-1  | {_PD_LISTENING}\n{_PD_REJECTED}"

_CP_AUTHORISED = "interlock-lab: CP authorised unlock on card read"
_RMAC_I_REJECTED = "osdp: CP: Out of order REPLY_RMAC_I"
_UNLOCKED = "interlock-lab: LOCK state=UNLOCKED"

# The healthy-lab log per service; tests override single services. The cp log carries one
# genuine authorisation, the CVE step's baseline.
_LOGS = {"cp": f"{_CP_LOG}cp-1  | {_CP_AUTHORISED}\n", "pd": _PD_LOG}

_SPOOF_TRIGGER = "/tmp/interlock-spoof-fire"
_REPLAY_TRIGGER = "/tmp/interlock-replay-fire"
_CVE_TRIGGER = "/tmp/interlock-cve-fire"

# What each trigger file adds to the logs once touched, on a healthy lab: both relays unlock
# the clear-text PD, and the fixed CP rejects the replayed REPLY_RMAC_I.
_TOUCH_LOGS = {
    _SPOOF_TRIGGER: {"pd": f"pd-1  | {_UNLOCKED}\n"},
    _REPLAY_TRIGGER: {"pd": f"pd-1  | {_UNLOCKED}\n"},
    _CVE_TRIGGER: {"cp": f"cp-1  | {_RMAC_I_REJECTED}\n"},
}

# The in-container fuzz sweep on a healthy PD: no finding, completion reported.
_FUZZ_CLEAN = "INTERLOCK-FUZZ-DONE 0\n"



def _fixture_pair(name: str) -> dict[str, bytes]:
    """Return a committed capture pair keyed by its in-container basename."""
    return {
        "cp2pd.cap": (FIXTURES_DIR / f"{name}_cp2pd.cap").read_bytes(),
        "pd2cp.cap": (FIXTURES_DIR / f"{name}_pd2cp.cap").read_bytes(),
    }


_TAP = "docker-compose.tap.yml"
_DOWNGRADE = "docker-compose.downgrade.yml"
_SNIFF_BRING_UP = ("cleartext", _TAP)

# The live capture pair per bring-up, keyed by (LAB_SCENARIO, last override): a healthy lab.
# The downgrade relay forces the attacked session to clear-text, so it reads like cleartext.
_BRING_UP_CAPTURES = {
    _SNIFF_BRING_UP: _fixture_pair("cleartext"),
    ("sc-scbkd", _TAP): _fixture_pair("sc-scbkd"),
    ("downgrade", _TAP): _fixture_pair("downgrade"),
    ("downgrade", _DOWNGRADE): _fixture_pair("cleartext"),
}

# What ``docker compose config --format json`` resolves for a contained lab: a synthetic dict
# of the probed shape (relative bind source, never a host path). It already satisfies every
# containment rule: one internal network, no published or exposed port, no device, no
# privilege or namespace key, a read-only bind and the cp pinned to the attacker.
_CLEAN_CONFIG: dict[str, object] = {
    "name": "interlock-assess",
    "networks": {"labnet": {"name": "interlock-assess_labnet", "internal": True}},
    "services": {
        "pd": {"networks": {"labnet": None}, "environment": {"LAB_SCENARIO": "cleartext"}},
        "attacker": {
            "networks": {"labnet": None},
            "environment": {"ATTACKER_UPSTREAM": "pd:10000", "PYTHONPATH": "/app/src"},
            "volumes": [
                {"type": "bind", "source": "./src", "target": "/app/src", "read_only": True}
            ],
        },
        "cp": {
            "networks": {"labnet": None},
            "environment": {"LAB_SCENARIO": "cleartext", "CP_UPSTREAM": "attacker:10000"},
        },
    },
}


def _planted(service: str, key: str, value: object) -> dict[str, object]:
    """Return a deep copy of ``_CLEAN_CONFIG`` with ``key: value`` set on one service."""
    config: dict[str, object] = json.loads(json.dumps(_CLEAN_CONFIG))
    services = config["services"]
    assert isinstance(services, dict)
    services[service][key] = value
    return config


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

    ``returncodes`` overrides the exit code per subcommand; ``logs`` overrides the log text
    per service; ``bring_up_logs`` replaces that per-service log text for one bring-up only,
    keyed like ``bring_up_captures`` by (LAB_SCENARIO, last override, "" when none);
    ``bring_up_captures`` replaces the capture pair of a bring-up, keyed by
    (LAB_SCENARIO, last override); ``captures`` overrides single basenames of the
    sniff-enumerate bring-up (b"" simulates an empty capture); ``fuzz_stdout`` and
    ``fuzz_returncode`` script the in-container fuzz sweep. The logs are stateful: once a
    trigger file is touched, ``touch_logs[path]`` is appended per service until the next
    ``up`` (a fresh stack); ``touch_returncode`` is the exit code of every touch.
    ``config`` answers with ``_CLEAN_CONFIG`` as JSON unless ``configs`` holds a document for
    the argv's last override ("" for the base file alone), which plants a violation.
    """

    def __init__(
        self,
        *,
        returncodes: Mapping[str, int] | None = None,
        logs: Mapping[str, str] | None = None,
        captures: Mapping[str, bytes] | None = None,
        bring_up_captures: Mapping[tuple[str, str], Mapping[str, bytes]] | None = None,
        bring_up_logs: Mapping[tuple[str, str], Mapping[str, str]] | None = None,
        fuzz_stdout: str = _FUZZ_CLEAN,
        fuzz_returncode: int = 0,
        touch_logs: Mapping[str, Mapping[str, str]] | None = None,
        touch_returncode: int = 0,
        configs: Mapping[str, Mapping[str, object]] | None = None,
    ) -> None:
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.configs = dict(configs or {})
        self.returncodes = dict(returncodes or {})
        self.logs = {**_LOGS, **(logs or {})}
        self.bring_up_captures = {
            key: dict(pair) for key, pair in {**_BRING_UP_CAPTURES, **(bring_up_captures or {})}.items()
        }
        self.captures.update(captures or {})
        self.bring_up_logs = {key: dict(logs) for key, logs in (bring_up_logs or {}).items()}
        self.fuzz_stdout = fuzz_stdout
        self.fuzz_returncode = fuzz_returncode
        self.touch_logs = {**_TOUCH_LOGS, **(touch_logs or {})}
        self.touch_returncode = touch_returncode
        self.touched: list[str] = []  # since the last ``up``
        self.touches: list[str] = []  # over the whole run

    @property
    def captures(self) -> dict[str, bytes]:
        """The capture pair of the sniff-enumerate bring-up (cleartext under the tap)."""
        return self.bring_up_captures[_SNIFF_BRING_UP]

    @property
    def argvs(self) -> list[list[str]]:
        return [argv for argv, _ in self.calls]

    def __call__(
        self, argv: Sequence[str], env: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        self.calls.append((argv, dict(env)))
        sub = _subcommand(argv)
        returncode = self.returncodes.get(sub, 0)
        if sub == "up":
            self.touched = []
            stdout = ""
        elif sub == "config":
            overrides = _overrides(argv)
            stdout = json.dumps(self.configs.get(overrides[-1] if overrides else "", _CLEAN_CONFIG))
        elif sub == "logs":
            service = argv[-1]
            overrides = _overrides(argv)
            key = (env["LAB_SCENARIO"], overrides[-1] if overrides else "")
            logs = {**self.logs, **self.bring_up_logs.get(key, {})}
            stdout = logs.get(service, "") + "".join(
                self.touch_logs.get(path, {}).get(service, "") for path in self.touched
            )
        elif sub == "exec" and "touch" in argv:
            returncode = self.touch_returncode
            if returncode == 0:
                self.touched.append(argv[-1])
                self.touches.append(argv[-1])
            stdout = ""
        elif sub == "exec" and _FUZZ_SCRIPT in argv:
            stdout, returncode = self.fuzz_stdout, self.fuzz_returncode
        elif sub == "exec":
            pair = self.bring_up_captures[(env["LAB_SCENARIO"], _overrides(argv)[-1])]
            stdout = base64.b64encode(pair[PurePosixPath(argv[-1]).name]).decode()
        else:
            stdout = ""
        return subprocess.CompletedProcess(argv, returncode, stdout, "")


def _base(lab: Path, *overrides: str) -> list[str]:
    files = ["-f", str(lab / "docker-compose.yml")]
    for override in overrides:
        files += ["-f", str(lab / override)]
    return ["docker", "compose", "-p", "interlock-assess", *files]


def _overrides(argv: Sequence[str]) -> tuple[str, ...]:
    """Return the override file names of a compose argv (every -f after the base file)."""
    files = [PurePosixPath(argv[i + 1]).name for i, token in enumerate(argv) if token == "-f"]
    return tuple(files[1:])


def _bring_ups(fake: FakeCompose) -> list[tuple[str, tuple[str, ...]]]:
    """Return (LAB_SCENARIO, overrides) for every ``up`` the fake saw, in order."""
    return [
        (env["LAB_SCENARIO"], _overrides(argv))
        for argv, env in fake.calls
        if _subcommand(argv) == "up"
    ]


@pytest.fixture
def lab_dir(tmp_path: Path) -> Path:
    """A lab dir holding (empty) copies of the compose files the assessment requires."""
    lab = tmp_path / "lab"
    lab.mkdir()
    for name in required_files():
        (lab / name).write_text("", encoding="utf-8")
    return lab.resolve()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeCompose:
    """Install a default ``FakeCompose`` as the lab runner and pretend Docker is on PATH."""
    compose = FakeCompose()
    monkeypatch.setattr(lab_session, "make_runner", lambda lab: compose)
    monkeypatch.setattr(lab_session, "docker_available", lambda: True)
    return compose


# What the default FakeCompose (a healthy lab) yields per step, and the bring-ups it sees.
_HEALTHY_LAB_STATUSES = {
    "sniff-enumerate": "vulnerable",
    "fuzz": "not_vulnerable",
    "weak-key-keyset": "vulnerable",
    "downgrade": "vulnerable",
    "spoof": "vulnerable",
    "replay": "vulnerable",
    "cve-2024-52288-fixed": "not_vulnerable",
}
_HEALTHY_LAB_BRING_UPS = [
    ("cleartext", (_TAP,)),
    ("cleartext", ("docker-compose.fuzz.yml",)),
    ("sc-scbkd", (_TAP,)),
    ("downgrade", (_TAP,)),
    ("downgrade", (_DOWNGRADE,)),
    ("cleartext", ("docker-compose.spoof.yml",)),
    ("cleartext", ("docker-compose.replay.yml",)),
    ("sc-scbkd", ("docker-compose.cve.yml",)),
]


def test_assess_runs_every_step_end_to_end(
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

    statuses = {step["key"]: step["status"] for step in document["steps"]}
    assert statuses == _HEALTHY_LAB_STATUSES

    # The containment check of base + each override first (one bring-up layers exactly one
    # override), then the reset, then every bring-up in step order, each torn down before the
    # next.
    configs = [
        [*_base(lab_dir, override), "config", "--format", "json"]
        for override in required_files()[1:]
    ]
    checked = len(configs)
    assert fake.argvs[:checked] == configs
    tap = _base(lab_dir, "docker-compose.tap.yml")
    assert fake.argvs[checked] == [*_base(lab_dir), "down", "-v"]
    assert fake.argvs[checked + 1] == [*tap, "up", "-d", "--build", "--force-recreate"]
    assert fake.calls[checked + 1][1]["LAB_SCENARIO"] == "cleartext"
    assert _bring_ups(fake) == _HEALTHY_LAB_BRING_UPS
    ups_and_downs = [
        argv for argv in fake.argvs[checked + 1 :] if _subcommand(argv) in {"up", "down"}
    ]
    for up, down in zip(ups_and_downs[::2], ups_and_downs[1::2], strict=True):
        assert up[-4:] == ["up", "-d", "--build", "--force-recreate"]
        assert down == [*up[:-4], "down", "-v"]
    reads = [
        argv[-1]
        for argv in fake.argvs[: fake.argvs.index([*tap, "down", "-v"])]
        if _subcommand(argv) == "exec"
    ]
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
    # The lab is not in the wheel (D-02): a pip-installed user is told where it lives.
    assert "clone" in result.stderr
    assert "--lab-dir" in result.stderr
    _assert_nothing_written(tmp_path, fake)


def test_preflight_containment_violation_exits_2_without_reports(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose
) -> None:
    fake.configs["docker-compose.spoof.yml"] = _planted("pd", "ports", ["8000:10000"])
    md_path = tmp_path / "out" / "assessment.md"
    result = runner.invoke(app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(lab_dir)])
    assert result.exit_code == 2, result.output
    assert "docker-compose.spoof.yml" in result.stderr
    assert "pd" in result.stderr and "ports" in result.stderr
    assert not (tmp_path / "out").exists()
    # The check runs before anything is brought up, and only config calls were made.
    assert fake.calls, "the containment check never ran"
    assert {_subcommand(argv) for argv in fake.argvs} == {"config"}


def test_report_scope_names_the_containment_check(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose
) -> None:
    md_path = tmp_path / "out" / "assessment.md"
    result = runner.invoke(app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(lab_dir)])
    assert result.exit_code == 0, result.output

    markdown = md_path.read_text(encoding="utf-8")
    scope = _section(markdown, "Scope")
    [bullet] = [line for line in scope if line.startswith("- **Containment:** ")]
    assert "checked before the run" in bullet
    assert "every network internal" in bullet and "no published ports" in bullet
    assert str(lab_dir) not in "\n".join(scope)

    document = json.loads(md_path.with_suffix(".json").read_text(encoding="utf-8"))
    containment = document["containment"]
    assert containment["checked"] is True
    assert bullet == f"- **Containment:** {containment['detail']}."


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


def _steps(*keys: str) -> tuple[Step, ...]:
    """Return the real ``STEPS`` entries named by ``keys``, in the order given."""
    by_key = {step.key: step for step in STEPS}
    missing = [key for key in keys if key not in by_key]
    assert not missing, f"STEPS has no step {missing}"
    return tuple(by_key[key] for key in keys)


def _run_steps(lab_dir: Path, fake: FakeCompose, *keys: str) -> list[StepResult]:
    """Run the named real steps over ``fake`` on a fake clock (no wait ever really sleeps)."""
    clock = FakeClock()
    session = LabSession(lab_dir, runner=fake, sleep=clock.sleep, clock=clock)
    started = time.monotonic()
    results = run_assessment(session, steps=_steps(*keys), clock=clock)
    assert time.monotonic() - started < 10.0
    return results


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
    fake = FakeCompose(logs={"cp": logs})
    session = LabSession(lab_dir, runner=fake, sleep=clock.sleep, clock=clock)

    started = time.monotonic()
    results = run_assessment(session, steps=_steps("sniff-enumerate"), clock=clock)
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
    results = run_assessment(LabSession(lab_dir, runner=fake), steps=_steps("sniff-enumerate"))
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
    results = run_assessment(LabSession(lab_dir, runner=fake), steps=_steps("sniff-enumerate"))
    assert results[0].status is Status.ERROR
    assert results[0].detail.startswith(message)
    assert fake.argvs[-1][-2:] == ["down", "-v"]


# ---------------------------------------------------------------------------------------------
# The fuzz step: the in-container sweep's prefixed lines are the only trusted output.

_FUZZ_FINDING = Finding(
    id="ATK-07-fuzz-bad-crc",
    title="PD stopped answering after a corrupted CRC",
    severity=Severity.HIGH,
    evidence="no reply to the follow-up valid poll",
    attack_technique="T0806",
    remediation="harden the parser",
)


def _finding_line(document: Mapping[str, object]) -> str:
    return "INTERLOCK-FINDING " + json.dumps(document) + "\n"


def test_steps_start_with_sniff_enumerate_then_fuzz_under_the_fuzz_override() -> None:
    assert STEPS[0].key == "sniff-enumerate"
    assert STEPS[1].key == "fuzz"
    assert STEPS[1].profile == "cleartext"
    assert STEPS[1].overrides == ("docker-compose.fuzz.yml",)
    assert STEPS[1].attacks == (("fuzz", "ATK-07-fuzz-"),)


def test_fuzz_on_a_healthy_pd_is_not_vulnerable(lab_dir: Path) -> None:
    fake = FakeCompose()
    [result] = _run_steps(lab_dir, fake, "fuzz")
    assert result.status is Status.NOT_VULNERABLE
    assert result.detail == (
        "baseline poll answered; all nine corruptions handled; the PD answered every "
        "follow-up poll"
    )
    assert _bring_ups(fake) == [("cleartext", ("docker-compose.fuzz.yml",))]
    fuzz_runs = [argv for argv in fake.argvs if _FUZZ_SCRIPT in argv]
    assert len(fuzz_runs) == 1
    fuzz_base = _base(lab_dir, "docker-compose.fuzz.yml")
    assert fuzz_runs[0] == [
        *fuzz_base,
        "exec", "-T", "-e", "PYTHONPATH=/app/src", "attacker", "python", "-c", _FUZZ_SCRIPT,
    ]
    assert fake.argvs[-1] == [*fuzz_base, "down", "-v"]


def test_fuzz_with_one_finding_line_is_vulnerable_with_that_id(lab_dir: Path) -> None:
    stdout = _finding_line(finding_to_dict(_FUZZ_FINDING)) + "INTERLOCK-FUZZ-DONE 1\n"
    [result] = _run_steps(lab_dir, FakeCompose(fuzz_stdout=stdout), "fuzz")
    assert result.status is Status.VULNERABLE
    assert result.findings == (_FUZZ_FINDING,)


def test_fuzz_baseline_failure_is_inconclusive(lab_dir: Path) -> None:
    stdout = "INTERLOCK-INCONCLUSIVE the PD did not answer the baseline poll\n"
    [result] = _run_steps(lab_dir, FakeCompose(fuzz_stdout=stdout), "fuzz")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail == "the PD did not answer the baseline poll"


def test_fuzz_finding_with_an_unknown_severity_is_an_error(lab_dir: Path) -> None:
    document = {**finding_to_dict(_FUZZ_FINDING), "severity": "urgent"}
    stdout = _finding_line(document) + "INTERLOCK-FUZZ-DONE 1\n"
    [result] = _run_steps(lab_dir, FakeCompose(fuzz_stdout=stdout), "fuzz")
    assert result.status is Status.ERROR
    assert result.detail == "ValueError: unknown finding severity: 'urgent'"
    assert result.findings == ()


def test_fuzz_ignores_every_line_without_the_exact_prefix(lab_dir: Path) -> None:
    document = json.dumps(finding_to_dict(_FUZZ_FINDING))
    stdout = (
        "starting sweep\n"
        f"{document}\n"
        f"FINDING {document}\n"
        f" INTERLOCK-FINDING {document}\n"
        f"interlock-finding {document}\n"
        "INTERLOCK-FUZZ-DONE 0\n"
    )
    [result] = _run_steps(lab_dir, FakeCompose(fuzz_stdout=stdout), "fuzz")
    assert result.status is Status.NOT_VULNERABLE
    assert result.findings == ()


def test_fuzz_completion_count_must_match_the_parsed_findings(lab_dir: Path) -> None:
    stdout = _finding_line(finding_to_dict(_FUZZ_FINDING)) + "INTERLOCK-FUZZ-DONE 2\n"
    [result] = _run_steps(lab_dir, FakeCompose(fuzz_stdout=stdout), "fuzz")
    assert result.status is Status.ERROR
    assert result.detail.startswith("ValueError: the fuzz sweep reported 2 findings")
    assert result.findings == ()


def test_fuzz_without_a_completion_line_is_inconclusive(lab_dir: Path) -> None:
    stdout = _finding_line(finding_to_dict(_FUZZ_FINDING))
    [result] = _run_steps(lab_dir, FakeCompose(fuzz_stdout=stdout), "fuzz")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail == "fuzz sweep did not report completion"


def test_fuzz_clean_sweep_without_a_pd_rejection_line_is_inconclusive(lab_dir: Path) -> None:
    fake = FakeCompose(logs={"pd": f"pd-1  | {_PD_LISTENING}\n"})
    [result] = _run_steps(lab_dir, fake, "fuzz")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail == "the corruptions never reached the PD parser"


def test_fuzz_waits_for_the_pd_to_listen_before_sweeping(lab_dir: Path) -> None:
    fake = FakeCompose(logs={"pd": "pd-1  | interlock-lab: starting\n"})
    [result] = _run_steps(lab_dir, fake, "fuzz")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail == "PD listening not observed in the pd log within 120 s"
    assert not [argv for argv in fake.argvs if _FUZZ_SCRIPT in argv]
    assert fake.argvs[-1][-2:] == ["down", "-v"]


def test_fuzz_sweep_exiting_non_zero_is_an_error_with_the_output_tail(lab_dir: Path) -> None:
    fake = FakeCompose(fuzz_stdout="Traceback: ModuleNotFoundError\n", fuzz_returncode=1)
    [result] = _run_steps(lab_dir, fake, "fuzz")
    assert result.status is Status.ERROR
    assert result.detail.startswith("LabError: the fuzz sweep in the attacker failed (exit 1)")
    assert "ModuleNotFoundError" in result.detail
    assert fake.argvs[-1][-2:] == ["down", "-v"]


def test_fuzz_script_imports_only_stdlib_plugin_and_fuzz() -> None:
    allowed = {"interlock.plugin", "interlock.osdp.attacks.fuzz"}
    imported: list[str] = []
    for node in ast.walk(ast.parse(_FUZZ_SCRIPT)):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert imported, "the scan found no imports at all"
    for name in imported:
        assert name in allowed or name.split(".")[0] in sys.stdlib_module_names, name


# ---------------------------------------------------------------------------------------------
# The Secure Channel steps: weak-key + keyset on sc-scbkd, the downgrade before/after pair.


def _finding_ids(result: StepResult) -> set[str]:
    return {finding.id for finding in result.findings}


def test_steps_continue_with_the_secure_channel_steps() -> None:
    keys = [step.key for step in STEPS]
    assert keys[:4] == ["sniff-enumerate", "fuzz", "weak-key-keyset", "downgrade"]
    weak, down = _steps("weak-key-keyset", "downgrade")
    assert (weak.profile, weak.overrides) == ("sc-scbkd", (_TAP,))
    assert weak.attacks == (("weak-key", "ATK-06-"), ("keyset", "ATK-04-"))
    assert (down.profile, down.overrides) == ("downgrade", (_TAP, _DOWNGRADE))
    assert down.attacks == (("downgrade", "ATK-03-"),)


def test_weak_key_keyset_on_the_sc_scbkd_capture_flags_the_weak_key(lab_dir: Path) -> None:
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): _fixture_pair("sc-scbkd")})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.VULNERABLE
    assert "ATK-06-weak-key" in _finding_ids(result)
    assert _bring_ups(fake) == [("sc-scbkd", (_TAP,))]
    assert fake.argvs[-1] == [*_base(lab_dir, _TAP), "down", "-v"]


def test_weak_key_keyset_on_the_keyset_capture_recovers_the_enrolled_key(lab_dir: Path) -> None:
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): _fixture_pair("keyset")})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.VULNERABLE
    assert "ATK-04-keyset" in _finding_ids(result)


def test_weak_key_keyset_without_a_handshake_is_inconclusive(lab_dir: Path) -> None:
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): _fixture_pair("cleartext")})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.INCONCLUSIVE
    assert "no Secure Channel handshake captured" in result.detail
    assert result.findings == ()


@pytest.mark.parametrize("basename", ["cp2pd.cap", "pd2cp.cap"])
def test_weak_key_keyset_with_an_empty_capture_is_inconclusive(
    lab_dir: Path, basename: str
) -> None:
    pair = {**_fixture_pair("sc-scbkd"), basename: b""}
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.INCONCLUSIVE
    assert "empty" in result.detail


@pytest.fixture
def weak_key_cap_400(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore the old 400-frame weak-key cap, so the cap tests stay cheap to reach.

    The step reads ``_WEAK_KEY_MAX_FRAMES`` at call time, so the patch reaches the real step.
    """
    monkeypatch.setattr(assessment, "_WEAK_KEY_MAX_FRAMES", 400)


def test_weak_key_keyset_decodes_each_direction_up_to_the_ceiling(
    lab_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[tuple[Direction, ...], int]] = []
    real = assessment.decode_chunks

    def spy(chunks: Iterable[tuple[Direction, bytes]], *, max_frames: int = 200) -> object:
        chunks = list(chunks)
        seen.append((tuple(direction for direction, _ in chunks), max_frames))
        return real(chunks, max_frames=max_frames)

    monkeypatch.setattr(assessment, "decode_chunks", spy)
    [result] = _run_steps(lab_dir, FakeCompose(), "weak-key-keyset")
    assert result.status is Status.VULNERABLE
    # One call per direction, each under its own cap: a long cp->pd never starves pd->cp.
    assert seen == [((Direction.cp_to_pd,), 20000), ((Direction.pd_to_cp,), 20000)]


@pytest.mark.usefixtures("weak_key_cap_400")
def test_weak_key_keyset_with_cp_to_pd_past_the_cap_still_sees_the_pd_handshake(
    lab_dir: Path,
) -> None:
    pair = _fixture_pair("keyset")
    pair["cp2pd.cap"] = _with_trailing(pair["cp2pd.cap"], constants.CMD_POLL, _PAST_WEAK_KEY_CAP)
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.VULNERABLE
    assert {"ATK-06-weak-key", "ATK-04-keyset"} <= _finding_ids(result)


def test_weak_key_keyset_without_the_pd_half_of_the_handshake_is_inconclusive(
    lab_dir: Path,
) -> None:
    pair = _fixture_pair("sc-scbkd")
    pair["pd2cp.cap"] = _without_ccrypt(pair["pd2cp.cap"])
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.INCONCLUSIVE
    assert "no REPLY_CCRYPT pd->cp captured" in result.detail
    assert result.findings == ()


def test_weak_key_keyset_with_a_truncated_ccrypt_is_inconclusive(lab_dir: Path) -> None:
    # The REPLY_CCRYPT frame is there, but too short to carry RND.B and the PD cryptogram.
    pair = _fixture_pair("sc-scbkd")
    pair["pd2cp.cap"] = _with_truncated_payload(pair["pd2cp.cap"], constants.REPLY_CCRYPT, 8)
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.INCONCLUSIVE, result.detail
    assert "no REPLY_CCRYPT pd->cp captured" in result.detail
    assert result.findings == ()


def test_weak_key_keyset_with_a_truncated_chlng_is_inconclusive(lab_dir: Path) -> None:
    # The CMD_CHLNG frame is there, but too short to carry the 8-byte RND.A.
    pair = _fixture_pair("sc-scbkd")
    pair["cp2pd.cap"] = _with_truncated_payload(pair["cp2pd.cap"], constants.CMD_CHLNG, 4)
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.INCONCLUSIVE, result.detail
    assert "no CMD_CHLNG cp->pd" in result.detail
    assert result.findings == ()


@pytest.mark.parametrize(
    ("key", "bring_up", "fixture"),
    [
        ("sniff-enumerate", _SNIFF_BRING_UP, "cleartext"),
        ("weak-key-keyset", ("sc-scbkd", _TAP), "sc-scbkd"),
    ],
    ids=["sniff-enumerate", "weak-key-keyset"],
)
@pytest.mark.parametrize(
    ("basename", "label"), [("cp2pd.cap", "cp->pd"), ("pd2cp.cap", "pd->cp")], ids=["cp2pd", "pd2cp"]
)
def test_capture_direction_decoding_to_no_frame_is_inconclusive(
    lab_dir: Path, key: str, bring_up: tuple[str, str], fixture: str, basename: str, label: str
) -> None:
    # Non-empty, but no OSDP frame in it: proves nothing, the same as an empty capture.
    pair = {**_fixture_pair(fixture), basename: bytes(64)}
    fake = FakeCompose(bring_up_captures={bring_up: pair})
    [result] = _run_steps(lab_dir, fake, key)
    assert result.status is Status.INCONCLUSIVE
    assert "decoded to no OSDP frame" in result.detail
    assert label in result.detail
    assert result.findings == ()


def test_weak_key_keyset_on_a_non_default_key_bus_is_not_vulnerable(lab_dir: Path) -> None:
    """Guard for the fail-closed gates: a full, uncut, non-default-key handshake is clean."""
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): _fixture_pair("downgrade")})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.NOT_VULNERABLE
    assert result.findings == ()


def test_weak_key_keyset_clean_bus_with_a_long_tail_is_not_vulnerable(lab_dir: Path) -> None:
    # A slow host reads the capture late, so polls and acks pile up behind the handshake; under
    # the real ceiling that tail is decoded in full and the clean verdict stands.
    pair = _fixture_pair("downgrade")
    pair["cp2pd.cap"] = _with_trailing(pair["cp2pd.cap"], constants.CMD_POLL, _PAST_WEAK_KEY_CAP)
    pair["pd2cp.cap"] = _with_trailing(pair["pd2cp.cap"], constants.REPLY_ACK, _PAST_WEAK_KEY_CAP)
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.NOT_VULNERABLE, result.detail
    assert result.findings == ()
    assert "frame cap" not in result.detail
    assert result.capped == ()


def test_weak_key_keyset_method_names_the_frame_ceiling() -> None:
    [weak] = _steps("weak-key-keyset")
    assert "20000" in weak.method


@pytest.mark.usefixtures("weak_key_cap_400")
@pytest.mark.parametrize(
    ("basename", "code", "label"),
    [
        ("cp2pd.cap", constants.CMD_POLL, "cp->pd"),
        ("pd2cp.cap", constants.REPLY_ACK, "pd->cp"),
    ],
    ids=["cp2pd", "pd2cp"],
)
def test_weak_key_keyset_without_a_match_past_the_frame_cap_is_inconclusive(
    lab_dir: Path, basename: str, code: int, label: str
) -> None:
    # No weak key matched, but the matching handshake may lie past the cap: not a clean result.
    pair = _fixture_pair("downgrade")
    pair[basename] = _with_trailing(pair[basename], code, _PAST_WEAK_KEY_CAP)
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.INCONCLUSIVE
    assert f"decoding stopped at the 400-frame cap in {label}" in result.detail
    assert result.findings == ()


@pytest.mark.usefixtures("weak_key_cap_400")
def test_capture_detail_counts_frames_per_direction_and_names_a_reached_cap(
    lab_dir: Path,
) -> None:
    pair = _fixture_pair("sc-scbkd")
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    captured = len(pair["cp2pd.cap"]) + len(pair["pd2cp.cap"])
    assert result.detail == f"13 cp->pd and 14 pd->cp frames decoded from {captured} captured bytes"

    # Findings decoded within the cap stay proof; the detail names the direction that hit it.
    long_cp = _fixture_pair("keyset")
    long_cp["cp2pd.cap"] = _with_trailing(long_cp["cp2pd.cap"], constants.CMD_POLL, _PAST_WEAK_KEY_CAP)
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): long_cp})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.VULNERABLE
    assert result.detail.endswith("; decoding stopped at the 400-frame cap in cp->pd")

    long_both = {**long_cp}
    long_both["pd2cp.cap"] = _with_trailing(
        long_both["pd2cp.cap"], constants.REPLY_ACK, _PAST_WEAK_KEY_CAP
    )
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): long_both})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.VULNERABLE
    assert result.detail.endswith("; decoding stopped at the 400-frame cap in cp->pd and pd->cp")


def test_downgrade_pair_forced_to_clear_text_is_vulnerable(lab_dir: Path) -> None:
    fake = FakeCompose(
        bring_up_captures={
            ("downgrade", _TAP): _fixture_pair("downgrade"),
            ("downgrade", _DOWNGRADE): _fixture_pair("cleartext"),
        }
    )
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.VULNERABLE
    assert "ATK-03-downgrade" in _finding_ids(result)

    # Two bring-ups of the downgrade profile, each torn down: the tap, then the relay.
    assert _bring_ups(fake) == [("downgrade", (_TAP,)), ("downgrade", (_DOWNGRADE,))]
    ups = [argv for argv in fake.argvs if _subcommand(argv) == "up"]
    downs = [argv for argv in fake.argvs[1:] if _subcommand(argv) == "down"]
    assert ups == [
        [*_base(lab_dir, _TAP), "up", "-d", "--build", "--force-recreate"],
        [*_base(lab_dir, _DOWNGRADE), "up", "-d", "--build", "--force-recreate"],
    ]
    assert downs == [[*_base(lab_dir, _TAP), "down", "-v"], [*_base(lab_dir, _DOWNGRADE), "down", "-v"]]


def test_downgrade_with_a_clear_text_baseline_is_inconclusive(lab_dir: Path) -> None:
    fake = FakeCompose(
        bring_up_captures={
            ("downgrade", _TAP): _fixture_pair("cleartext"),
            ("downgrade", _DOWNGRADE): _fixture_pair("cleartext"),
        }
    )
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail == "baseline was not Secure Channel"
    # No verdict without a secure baseline, so the attacked bring-up never runs.
    assert _bring_ups(fake) == [("downgrade", (_TAP,))]


def test_downgrade_whose_attacked_session_stays_secure_is_not_vulnerable(lab_dir: Path) -> None:
    fake = FakeCompose(
        bring_up_captures={
            ("downgrade", _TAP): _fixture_pair("downgrade"),
            ("downgrade", _DOWNGRADE): _fixture_pair("downgrade"),
        }
    )
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.NOT_VULNERABLE
    assert "attacked session stayed Secure Channel" in result.detail


def _without_pdcap(capture: bytes) -> bytes:
    """Return ``capture`` with every REPLY_PDCAP frame dropped (nothing left to strip)."""
    return b"".join(
        raw for raw in framer.iter_frames(capture)
        if codec.decode(raw).code != constants.REPLY_PDCAP
    )


# Trailing frame counts past each frame cap: the default 200, and the 400 that
# ``weak_key_cap_400`` restores for weak-key-keyset (its real ceiling is far higher).
_PAST_SNIFF_CAP = 250
_PAST_WEAK_KEY_CAP = 450


def _with_trailing(capture: bytes, code: int, count: int) -> bytes:
    """Return ``capture`` followed by ``count`` copies of its first frame with ``code``.

    Models a bus that keeps polling until the capture is read: the session stays at the head
    and the tail grows with every exchange.
    """
    raw = next(
        (raw for raw in framer.iter_frames(capture) if codec.decode(raw).code == code), None
    )
    assert raw is not None, f"no frame with code {code:#04x} in the capture"
    return capture + raw * count


def _with_leading(capture: bytes, code: int, count: int) -> bytes:
    """Return ``count`` copies of the first frame with ``code`` in ``capture``, then ``capture``.

    Models a tap that started recording long before the session it is meant to see.
    """
    raw = next(
        (raw for raw in framer.iter_frames(capture) if codec.decode(raw).code == code), None
    )
    assert raw is not None, f"no frame with code {code:#04x} in the capture"
    return raw * count + capture


def _with_truncated_payload(capture: bytes, code: int, keep: int) -> bytes:
    """Return ``capture`` with the payload of every frame with ``code`` cut to ``keep`` bytes.

    Models a CRC-valid handshake frame whose payload is too short for the verdict parsers:
    each cut frame is re-encoded, so LEN and CRC are recomputed and the framer still accepts
    it. 0x76 is CMD_CHLNG cp->pd and REPLY_CCRYPT pd->cp, so apply it to one direction only.
    """
    out = bytearray()
    cut = 0
    for raw in framer.iter_frames(capture):
        frame = codec.decode(raw)
        if frame.code == code:
            out += codec.encode(replace(frame, data=frame.data[:keep]))
            cut += 1
        else:
            out += raw
    assert cut, f"no frame with code {code:#04x} in the capture"
    return bytes(out)


def _without_ccrypt(capture: bytes) -> bytes:
    """Return a pd->cp ``capture`` with every REPLY_CCRYPT frame dropped (no PD handshake half).

    0x76 is also CMD_CHLNG cp->pd, so this is only ever applied to a pd->cp capture.
    """
    return b"".join(
        raw for raw in framer.iter_frames(capture)
        if codec.decode(raw).code != constants.REPLY_CCRYPT
    )


# LibOSDP 3.0.8's CP refusing a PD that no longer advertises Secure Channel (osdp_cp.c, CAPDET).
_ENFORCE_SECURE = "cp-1  | osdp: CP: SC disabled/incapable; Set PD offline due to ENFORCE_SECURE"


def _enforcing_cp(relayed_pd2cp: bytes, cp_log: str = f"{_ENFORCE_SECURE}\n") -> FakeCompose:
    """A downgrade pair whose attacked CP never brings PD 101 online.

    The baseline under the tap is the healthy Secure Channel session; the attacked bring-up
    logs ``cp_log`` instead of the online sentinels, and the relay's pd->cp capture is
    ``relayed_pd2cp``.
    """
    return FakeCompose(
        bring_up_captures={
            ("downgrade", _TAP): _fixture_pair("downgrade"),
            ("downgrade", _DOWNGRADE): {
                "cp2pd.cap": _fixture_pair("downgrade")["cp2pd.cap"],
                "pd2cp.cap": relayed_pd2cp,
            },
        },
        bring_up_logs={("downgrade", _DOWNGRADE): {"cp": cp_log}},
    )


def _stripped_pd2cp() -> bytes:
    """The downgrade PD's replies as the relay forwards them: CommunicationSecurity removed."""
    return downgrade.strip_sc_capability(Direction.pd_to_cp, _fixture_pair("downgrade")["pd2cp.cap"])


_NOT_ONLINE = "PD 101 online not observed in the cp log within 180 s"


def test_downgrade_refused_by_an_enforcing_cp_is_not_vulnerable(lab_dir: Path) -> None:
    fake = _enforcing_cp(_stripped_pd2cp())
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.NOT_VULNERABLE, result.detail
    assert result.findings == ()
    assert "refused the stripped PD" in result.detail
    assert _ENFORCE_SECURE in result.detail
    assert _bring_ups(fake) == [("downgrade", (_TAP,)), ("downgrade", (_DOWNGRADE,))]
    assert fake.argvs[-1] == [*_base(lab_dir, _DOWNGRADE), "down", "-v"]


def test_downgrade_without_the_enforce_secure_line_is_inconclusive(lab_dir: Path) -> None:
    fake = _enforcing_cp(_stripped_pd2cp(), cp_log="cp-1  | interlock-lab: starting\n")
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail.startswith(_NOT_ONLINE)
    assert "ENFORCE_SECURE" in result.detail
    assert result.findings == ()


def test_downgrade_refusal_with_an_unstripped_pdcap_is_inconclusive(lab_dir: Path) -> None:
    # The CP refused, but the relay never stripped anything: the refusal proves nothing.
    fake = _enforcing_cp(_fixture_pair("downgrade")["pd2cp.cap"])
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail.startswith(_NOT_ONLINE)
    assert "still advertised CommunicationSecurity" in result.detail


def test_downgrade_refusal_without_a_relayed_pdcap_is_inconclusive(lab_dir: Path) -> None:
    fake = _enforcing_cp(_without_pdcap(_stripped_pd2cp()))
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail.startswith(_NOT_ONLINE)
    assert "no REPLY_PDCAP" in result.detail


def test_downgrade_refusal_with_an_empty_relay_capture_is_inconclusive(lab_dir: Path) -> None:
    fake = _enforcing_cp(b"")
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail.startswith(_NOT_ONLINE)
    assert "pd->cp capture is empty" in result.detail


def test_downgrade_refusal_with_a_capped_relay_capture_is_inconclusive(lab_dir: Path) -> None:
    # Every decoded REPLY_PDCAP is stripped, but an unstripped one may lie past the cap.
    fake = _enforcing_cp(_with_trailing(_stripped_pd2cp(), constants.REPLY_ACK, _PAST_SNIFF_CAP))
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail.startswith(_NOT_ONLINE)
    assert "200-frame cap" in result.detail


def test_downgrade_with_no_communication_security_advertised_is_inconclusive(
    lab_dir: Path,
) -> None:
    baseline = _fixture_pair("downgrade")
    baseline["pd2cp.cap"] = _without_pdcap(baseline["pd2cp.cap"])
    fake = FakeCompose(
        bring_up_captures={
            ("downgrade", _TAP): baseline,
            ("downgrade", _DOWNGRADE): _fixture_pair("downgrade"),
        }
    )
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail == "baseline advertised no CommunicationSecurity to strip"


def test_the_pdcap_free_baseline_is_still_secure() -> None:
    """Guard for the test above: dropping REPLY_PDCAP keeps the baseline Secure Channel."""
    pair = _fixture_pair("downgrade")
    frames = [
        (direction, codec.decode(raw))
        for direction, data in (
            (Direction.cp_to_pd, pair["cp2pd.cap"]),
            (Direction.pd_to_cp, _without_pdcap(pair["pd2cp.cap"])),
        )
        for raw in framer.iter_frames(data)
    ]
    assert secure_channel.detect_state(frames).secure


# ---------------------------------------------------------------------------------------------
# The active relay steps: spoof, clear-text replay from the live capture, CVE-2024-52288 on the
# fixed core. Logs change only after the fake records the touch of the step's trigger file.


def _cleartext_frames() -> list[tuple[Direction, codec.OsdpFrame]]:
    pair = _fixture_pair("cleartext")
    return assessment.decode_chunks(
        [(Direction.cp_to_pd, pair["cp2pd.cap"]), (Direction.pd_to_cp, pair["pd2cp.cap"])]
    )


def _seed(frames: object) -> Step:
    """A synthetic first step that leaves ``frames`` where sniff-enumerate leaves its capture."""

    def seed(session: LabSession, context: dict[str, object]) -> StepOutput:
        context["cleartext_frames"] = frames
        return StepOutput(findings=())

    return _step("seed", seed)


def _run_after_seed(lab_dir: Path, fake: FakeCompose, frames: object, key: str) -> StepResult:
    clock = FakeClock()
    session = LabSession(lab_dir, runner=fake, sleep=clock.sleep, clock=clock)
    results = run_assessment(session, steps=(_seed(frames), *_steps(key)), clock=clock)
    return results[1]


def _touch_argv(lab_dir: Path, override: str, path: str) -> list[str]:
    return [*_base(lab_dir, override), "exec", "-T", "attacker", "touch", path]


def test_spoof_unlock_after_arming_is_vulnerable(lab_dir: Path) -> None:
    fake = FakeCompose()
    [result] = _run_steps(lab_dir, fake, "spoof")
    assert result.status is Status.VULNERABLE
    assert _finding_ids(result) == {"ATK-08-spoof-unlock"}
    assert _bring_ups(fake) == [("cleartext", ("docker-compose.spoof.yml",))]
    assert _touch_argv(lab_dir, "docker-compose.spoof.yml", _SPOOF_TRIGGER) in fake.argvs
    assert fake.touches == [_SPOOF_TRIGGER]
    assert fake.argvs[-1] == [*_base(lab_dir, "docker-compose.spoof.yml"), "down", "-v"]


def test_spoof_with_the_pd_already_unlocked_is_inconclusive(lab_dir: Path) -> None:
    fake = FakeCompose(logs={"pd": f"{_PD_LOG}pd-1  | {_UNLOCKED}\n"})
    [result] = _run_steps(lab_dir, fake, "spoof")
    assert result.status is Status.INCONCLUSIVE
    assert "already unlocked" in result.detail
    assert fake.touches == []


def test_spoof_trigger_failing_is_an_error(lab_dir: Path) -> None:
    fake = FakeCompose(touch_returncode=1)
    [result] = _run_steps(lab_dir, fake, "spoof")
    assert result.status is Status.ERROR
    assert result.detail.startswith("LabError: ")
    assert _SPOOF_TRIGGER in result.detail
    assert fake.argvs[-1][-2:] == ["down", "-v"]


def test_spoof_without_a_lock_transition_is_not_vulnerable(lab_dir: Path) -> None:
    fake = FakeCompose(touch_logs={_SPOOF_TRIGGER: {}})
    [result] = _run_steps(lab_dir, fake, "spoof")
    assert result.status is Status.NOT_VULNERABLE
    assert result.detail == "armed; no lock-state transition within 120 s"
    assert fake.touches == [_SPOOF_TRIGGER]


def test_replay_of_the_live_card_read_is_vulnerable(lab_dir: Path) -> None:
    fake = FakeCompose()
    result = _run_after_seed(lab_dir, fake, _cleartext_frames(), "replay")
    assert result.status is Status.VULNERABLE
    assert _finding_ids(result) == {"ATK-05a-replay-card-exchange"}
    # The finding never claims a live byte-exact re-injection without the method beside it.
    [finding] = result.findings
    assert finding.evidence.endswith(assessment.REPLAY_LIVE_NOTE)
    assert "shared POLL-to-CMD_OUT rewrite" in finding.evidence
    assert _bring_ups(fake) == [("cleartext", ("docker-compose.replay.yml",))]
    assert _touch_argv(lab_dir, "docker-compose.replay.yml", _REPLAY_TRIGGER) in fake.argvs
    assert fake.touches == [_REPLAY_TRIGGER]


def test_replay_without_the_sniff_capture_is_inconclusive(lab_dir: Path) -> None:
    fake = FakeCompose()
    [result] = _run_steps(lab_dir, fake, "replay")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail == "no live clear-text capture from the sniff-enumerate step"
    assert fake.touches == []


def test_replay_without_a_captured_card_read_is_inconclusive(lab_dir: Path) -> None:
    frames = [
        (direction, frame)
        for direction, frame in _cleartext_frames()
        if frame.code != constants.REPLY_RAW
    ]
    fake = FakeCompose()
    result = _run_after_seed(lab_dir, fake, frames, "replay")
    assert result.status is Status.INCONCLUSIVE
    assert "REPLY_RAW" in result.detail
    assert fake.touches == []


def test_replay_with_the_pd_already_unlocked_is_inconclusive(lab_dir: Path) -> None:
    fake = FakeCompose(logs={"pd": f"{_PD_LOG}pd-1  | {_UNLOCKED}\n"})
    result = _run_after_seed(lab_dir, fake, _cleartext_frames(), "replay")
    assert result.status is Status.INCONCLUSIVE
    assert "already unlocked" in result.detail
    assert fake.touches == []


def test_replay_after_sniff_enumerate_uses_its_live_capture(lab_dir: Path) -> None:
    fake = FakeCompose()
    results = _run_steps(lab_dir, fake, "sniff-enumerate", "replay")
    assert [r.status for r in results] == [Status.VULNERABLE, Status.VULNERABLE]
    assert _finding_ids(results[1]) == {"ATK-05a-replay-card-exchange"}


# ---------------------------------------------------------------------------------------------
# Long captures: the bus keeps polling until the capture is read, so a direction can run past
# its frame cap. Every capture step keeps its PD evidence, and none calls a long capture clean.


def _long_cleartext_sniff_captures() -> dict[str, bytes]:
    pair = _fixture_pair("cleartext")
    pair["cp2pd.cap"] = _with_trailing(pair["cp2pd.cap"], constants.CMD_POLL, _PAST_SNIFF_CAP)
    return pair


def test_sniff_enumerate_with_cp_to_pd_past_the_cap_still_enumerates_the_pd(
    lab_dir: Path,
) -> None:
    fake = FakeCompose(captures=_long_cleartext_sniff_captures())
    [result] = _run_steps(lab_dir, fake, "sniff-enumerate")
    assert result.status is Status.VULNERABLE
    assert {"ATK-01-sniff-pd-101", "ATK-02-enumerate-pd-101"} <= _finding_ids(result)


def test_replay_after_a_long_sniff_capture_still_finds_the_card_read(lab_dir: Path) -> None:
    fake = FakeCompose(captures=_long_cleartext_sniff_captures())
    results = _run_steps(lab_dir, fake, "sniff-enumerate", "replay")
    assert [r.status for r in results] == [Status.VULNERABLE, Status.VULNERABLE]
    assert _finding_ids(results[1]) == {"ATK-05a-replay-card-exchange"}


def test_downgrade_with_long_captures_is_still_vulnerable(lab_dir: Path) -> None:
    baseline = _fixture_pair("downgrade")
    attacked = _fixture_pair("cleartext")
    for pair in (baseline, attacked):
        pair["cp2pd.cap"] = _with_trailing(pair["cp2pd.cap"], constants.CMD_POLL, _PAST_SNIFF_CAP)
    fake = FakeCompose(
        bring_up_captures={("downgrade", _TAP): baseline, ("downgrade", _DOWNGRADE): attacked}
    )
    [result] = _run_steps(lab_dir, fake, "downgrade")
    assert result.status is Status.VULNERABLE
    assert "ATK-03-downgrade" in _finding_ids(result)


@pytest.mark.usefixtures("weak_key_cap_400")
def test_weak_key_keyset_with_both_directions_past_the_cap_is_still_vulnerable(
    lab_dir: Path,
) -> None:
    pair = _fixture_pair("keyset")
    pair["cp2pd.cap"] = _with_trailing(pair["cp2pd.cap"], constants.CMD_POLL, _PAST_WEAK_KEY_CAP)
    pair["pd2cp.cap"] = _with_trailing(pair["pd2cp.cap"], constants.REPLY_ACK, _PAST_WEAK_KEY_CAP)
    fake = FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair})
    [result] = _run_steps(lab_dir, fake, "weak-key-keyset")
    assert result.status is Status.VULNERABLE
    assert {"ATK-06-weak-key", "ATK-04-keyset"} <= _finding_ids(result)


# Which directions a long-capture case pads: cp->pd with polls, pd->cp with acks.
_LONG_SHAPES = {"cp2pd": ("cp2pd.cap",), "pd2cp": ("pd2cp.cap",), "both": ("cp2pd.cap", "pd2cp.cap")}
_PAD_CODE = {"cp2pd.cap": constants.CMD_POLL, "pd2cp.cap": constants.REPLY_ACK}
_LONG_CAPTURE_CASES = [
    pytest.param(key, bring_up, fixture, padded, count, id=f"{key}-{fixture}-{shape}")
    for key, bring_up, fixtures, count in (
        ("sniff-enumerate", _SNIFF_BRING_UP, ("cleartext",), _PAST_SNIFF_CAP),
        (
            "weak-key-keyset",
            ("sc-scbkd", _TAP),
            ("sc-scbkd", "keyset", "downgrade"),
            _PAST_WEAK_KEY_CAP,
        ),
    )
    for fixture in fixtures
    for shape, padded in _LONG_SHAPES.items()
]


@pytest.mark.usefixtures("weak_key_cap_400")
@pytest.mark.parametrize(("key", "bring_up", "fixture", "padded", "count"), _LONG_CAPTURE_CASES)
def test_a_long_capture_is_never_reported_not_vulnerable(
    lab_dir: Path,
    key: str,
    bring_up: tuple[str, str],
    fixture: str,
    padded: tuple[str, ...],
    count: int,
) -> None:
    pair = _fixture_pair(fixture)
    for basename in padded:
        pair[basename] = _with_trailing(pair[basename], _PAD_CODE[basename], count)
    fake = FakeCompose(bring_up_captures={bring_up: pair})
    [result] = _run_steps(lab_dir, fake, key)
    assert result.status in {Status.VULNERABLE, Status.INCONCLUSIVE}, result.detail


def test_cve_fixed_core_rejecting_the_replayed_rmac_i_is_not_vulnerable(lab_dir: Path) -> None:
    fake = FakeCompose()
    [result] = _run_steps(lab_dir, fake, "cve-2024-52288-fixed")
    assert result.status is Status.NOT_VULNERABLE
    assert _RMAC_I_REJECTED in result.detail
    assert result.detail.startswith("fixed LibOSDP 3.0.8 rejected the replayed REPLY_RMAC_I")
    assert _bring_ups(fake) == [("sc-scbkd", ("docker-compose.cve.yml",))]
    assert fake.touches == [_CVE_TRIGGER]
    assert _touch_argv(lab_dir, "docker-compose.cve.yml", _CVE_TRIGGER) in fake.argvs


def test_cve_fixed_core_re_authorising_is_vulnerable(lab_dir: Path) -> None:
    fake = FakeCompose(touch_logs={_CVE_TRIGGER: {"cp": f"cp-1  | {_CP_AUTHORISED}\n"}})
    [result] = _run_steps(lab_dir, fake, "cve-2024-52288-fixed")
    assert result.status is Status.VULNERABLE
    assert _finding_ids(result) == {"ATK-05b-cve-2024-52288-rmac-replay"}
    assert fake.touches == [_CVE_TRIGGER]


def test_cve_with_neither_rejection_nor_re_authorisation_is_inconclusive(lab_dir: Path) -> None:
    fake = FakeCompose(touch_logs={_CVE_TRIGGER: {}})
    [result] = _run_steps(lab_dir, fake, "cve-2024-52288-fixed")
    assert result.status is Status.INCONCLUSIVE
    assert result.detail == "the replay never reached the REPLY_RMAC_I fix path"
    assert fake.touches == [_CVE_TRIGGER]


def test_cve_without_a_baseline_authorisation_is_inconclusive(lab_dir: Path) -> None:
    fake = FakeCompose(logs={"cp": _CP_LOG})
    [result] = _run_steps(lab_dir, fake, "cve-2024-52288-fixed")
    assert result.status is Status.INCONCLUSIVE
    assert "no genuine baseline authorisation" in result.detail
    assert fake.touches == []


def test_cve_arm_token_issues_exactly_one_inject() -> None:
    assert getattr(assessment, "_ARM_TOKEN", None) == b"arm-inline-relay"


# ---------------------------------------------------------------------------------------------
# The full default set (D-03) and the source guards.


def test_steps_run_every_deterministic_attack_in_a_fixed_order() -> None:
    assert [step.key for step in STEPS] == [
        "sniff-enumerate",
        "fuzz",
        "weak-key-keyset",
        "downgrade",
        "spoof",
        "replay",
        "cve-2024-52288-fixed",
    ]


def test_no_step_uses_the_pinned_vulnerable_cve_lab() -> None:
    for step in STEPS:
        assert step.profile != "cve-replay", step.key
        assert "docker-compose.vuln.yml" not in step.overrides, step.key
    assert "docker-compose.vuln.yml" not in required_files()


def test_replay_method_discloses_what_ran_live() -> None:
    [replay] = _steps("replay")
    assert "relay" in replay.method
    assert "byte-exact" in replay.method
    assert "host unit tests" in replay.method


_FORBIDDEN_IMPORT_PARTS = ("safety", "serial", "open_serial_endpoint", "open_physical_endpoint")


def test_assessment_reads_no_fixture_and_imports_nothing_physical() -> None:
    assert assessment.__file__ is not None
    source = Path(assessment.__file__).read_text(encoding="utf-8")
    # Every finding comes from a live capture: no path to the committed test captures.
    assert "osdp/fixtures" not in source
    assert "FIXTURES_DIR" not in source
    assert '.cap"' not in source
    imported: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported.append(module)
            imported += [f"{module}.{alias.name}" for alias in node.names]
    assert imported, "the scan found no imports at all"
    for name in imported:
        assert not any(part in name for part in _FORBIDDEN_IMPORT_PARTS), name
        assert name != "tests" and not name.startswith("tests."), name


# --- The full report a reader opens (05-06) ----------------------------------------------------

_ALL_ATTACKS = (
    "sniff",
    "enumerate",
    "fuzz",
    "weak-key",
    "keyset",
    "downgrade",
    "spoof",
    "replay",
    "cve-2024-52288",
)
_LONG_DASHES = (chr(0x2014), chr(0x2013))
_GENERATED_AT = "2026-10-26T00:00:00+00:00"


def _full_run(lab_dir: Path, fake: FakeCompose, out: Path) -> tuple[str, dict[str, object]]:
    """Run all seven real steps over ``fake`` and return the Markdown text and the JSON."""
    results = _run_steps(lab_dir, fake, *(step.key for step in STEPS))
    md_path = out / "assessment.md"
    json_path = write_reports(results, md_path, generated_at=_GENERATED_AT)
    markdown = md_path.read_text(encoding="utf-8")
    raw = json_path.read_text(encoding="utf-8")
    for dash in _LONG_DASHES:
        assert dash not in markdown
        assert dash not in raw
    assert len(raw.encode("utf-8")) < 64 * 1024, "the JSON carries more than findings and metadata"
    return markdown, json.loads(raw)


def _section(markdown: str, heading: str) -> list[str]:
    """Return the lines of the ``## heading`` section, up to the next ``## `` heading."""
    lines = markdown.splitlines()
    start = lines.index(f"## {heading}") + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines))
    return lines[start:end]


def _coverage_rows(markdown: str) -> dict[str, list[str]]:
    """Return the Coverage table as attack key -> its cells."""
    rows = [line for line in _section(markdown, "Coverage") if line.startswith("| ")]
    header, *body = rows
    assert header == "| Attack | Step | Result | Enterprise | ICS |"
    cells = [[cell.strip() for cell in row.strip("|").split("|")] for row in body]
    return {row[0]: row for row in cells}


def test_full_report_reads_as_an_attack_mapped_assessment(tmp_path: Path, lab_dir: Path) -> None:
    markdown, document = _full_run(lab_dir, FakeCompose(), tmp_path / "out")

    assert markdown.startswith("# interlock OSDP assessment\n\n" + report.AUTHORIZED_USE_NOTICE)
    headings = [line for line in markdown.splitlines() if line.startswith("## ")]
    order = ["Scope", "Summary", "Coverage", "Findings", "Checks without a finding", "Method notes"]
    positions = [headings.index(f"## {name}") for name in order]
    assert positions == sorted(positions)

    scope = "\n".join(_section(markdown, "Scope"))
    # write_reports was handed no containment result, so the report claims none.
    assert "network-isolated" not in scope
    assert "- **Target:** the bundled lab, compose project interlock-assess." in scope
    assert "- **Containment:** not checked by this run." in scope
    assert document["containment"] == {"checked": False, "detail": "not checked by this run"}
    assert "interlock-assess" in scope
    assert "cleartext, sc-scbkd, downgrade" in scope
    assert "LibOSDP 3.0.8 (fixed)" in scope
    assert "CVE-2024-52288 core is not part of the default run" in scope
    assert "MITRE ATT&CK v20.0" in scope
    assert "T1200 (Hardware Additions)" in scope
    assert _GENERATED_AT in scope

    summary = _section(markdown, "Summary")
    assert "| Severity | Findings |" in summary
    severities = [line.split("|")[1].strip() for line in summary if line.startswith("| ")][1:6]
    assert severities == ["critical", "high", "medium", "low", "info"]
    assert "### Steps" in summary

    rows = _coverage_rows(markdown)
    assert sorted(rows) == sorted(_ALL_ATTACKS)
    assert rows["downgrade"][1:] == [
        "downgrade",
        "ATK-03-downgrade",
        "T1689 (Downgrade Attack)",
        "T0830 (Adversary-in-the-Middle)",
    ]
    assert rows["fuzz"][2] == "no finding"
    assert rows["cve-2024-52288"][1:3] == ["cve-2024-52288-fixed", "no finding"]
    assert rows["sniff"][2] == "ATK-01-sniff-pd-101"
    assert rows["replay"][2] == "ATK-05a-replay-card-exchange"

    # Every finding names its techniques "ID (Name)".
    assert "- **ATT&CK technique:** T1689 (Downgrade Attack)" in markdown
    assert "- **ATT&CK for ICS:** T0830 (Adversary-in-the-Middle)" in markdown

    checks = _section(markdown, "Checks without a finding")
    assert any(line.startswith("- fuzz (not_vulnerable): ") for line in checks)
    assert any(line.startswith("- cve-2024-52288-fixed (not_vulnerable): ") for line in checks)
    notes = "\n".join(_section(markdown, "Method notes"))
    for step in STEPS:
        assert f"- {step.key}: {step.method}" in notes
    assert "live proof via the in-path relay" in notes
    replay_section = markdown.split("## ATK-05a-replay-card-exchange:")[1].split("\n## ")[0]
    assert assessment.REPLAY_LIVE_NOTE in replay_section
    assert "byte-exact" in notes

    assert document["attack_version"] == "20.0"
    assert document["access_vector"] == {"enterprise": "T1200", "name": "Hardware Additions"}
    coverage = document["coverage"]
    assert isinstance(coverage, list) and len(coverage) == 9
    assert [entry["attack"] for entry in coverage] == list(_ALL_ATTACKS)
    downgrade_entry = next(entry for entry in coverage if entry["attack"] == "downgrade")
    assert downgrade_entry == {
        "attack": "downgrade",
        "step": "downgrade",
        "result": "ATK-03-downgrade",
        "finding_ids": ["ATK-03-downgrade"],
        "enterprise": "T1689",
        "ics": "T0830",
    }
    steps = document["steps"]
    assert isinstance(steps, list) and len(steps) == 7
    assert all(step["method"] for step in steps)


def test_an_inconclusive_step_shows_in_coverage_and_in_the_appendix(
    tmp_path: Path, lab_dir: Path
) -> None:
    fake = FakeCompose(
        bring_up_captures={
            ("downgrade", _TAP): _fixture_pair("cleartext"),
            ("downgrade", _DOWNGRADE): _fixture_pair("cleartext"),
        }
    )
    markdown, document = _full_run(lab_dir, fake, tmp_path / "out")

    assert _coverage_rows(markdown)["downgrade"][2] == "inconclusive"
    checks = _section(markdown, "Checks without a finding")
    assert "- downgrade (inconclusive): baseline was not Secure Channel" in checks
    coverage = document["coverage"]
    assert isinstance(coverage, list)
    entry = next(entry for entry in coverage if entry["attack"] == "downgrade")
    assert entry["result"] == "inconclusive" and entry["finding_ids"] == []
    # The other steps' findings are unaffected.
    assert _coverage_rows(markdown)["spoof"][2] == "ATK-08-spoof-unlock"


def test_coverage_marks_an_attack_whose_step_never_ran() -> None:
    rows = assessment.coverage([])
    assert len(rows) == 9
    assert {row.result for row in rows} == {"not run"}


def _step_entry(document: Mapping[str, object], key: str) -> Mapping[str, object]:
    steps = document["steps"]
    assert isinstance(steps, list)
    entry = next(step for step in steps if step["key"] == key)
    assert isinstance(entry, dict)
    return entry


def _coverage_entry(document: Mapping[str, object], attack: str) -> Mapping[str, object]:
    coverage = document["coverage"]
    assert isinstance(coverage, list)
    entry = next(entry for entry in coverage if entry["attack"] == attack)
    assert isinstance(entry, dict)
    return entry


@pytest.mark.usefixtures("weak_key_cap_400")
def test_coverage_reads_inconclusive_for_keyset_cut_by_the_cap(
    tmp_path: Path, lab_dir: Path
) -> None:
    cap = 400
    pair = _fixture_pair("keyset")
    cp_raws = list(framer.iter_frames(pair["cp2pd.cap"]))
    cp_codes = [codec.decode(raw).code for raw in cp_raws]
    pd_codes = [codec.decode(raw).code for raw in framer.iter_frames(pair["pd2cp.cap"])]
    chlng = cp_codes.index(constants.CMD_CHLNG)
    keyset = cp_codes.index(constants.CMD_KEYSET)
    ccrypt = pd_codes.index(constants.REPLY_CCRYPT)
    # Polls between the handshake and the KEYSET push the KEYSET past the cap, nothing else.
    poll = next(raw for raw, code in zip(cp_raws, cp_codes) if code == constants.CMD_POLL)
    pair["cp2pd.cap"] = b"".join([*cp_raws[:keyset], poll * cap, *cp_raws[keyset:]])
    assert chlng < keyset < cap <= keyset + cap
    assert ccrypt < len(pd_codes) < cap

    markdown, document = _full_run(
        lab_dir, FakeCompose(bring_up_captures={("sc-scbkd", _TAP): pair}), tmp_path / "out"
    )
    rows = _coverage_rows(markdown)
    assert rows["weak-key"][2] == "ATK-06-weak-key"
    assert rows["keyset"][2] == "inconclusive"
    entry = _step_entry(document, "weak-key-keyset")
    assert entry["status"] == "vulnerable"
    assert entry["finding_ids"] == ["ATK-06-weak-key"]
    assert entry["capped"] == ["cp->pd"]
    keyset_entry = _coverage_entry(document, "keyset")
    assert keyset_entry["result"] == "inconclusive" and keyset_entry["finding_ids"] == []
    # An uncapped completed step without a finding still reads "no finding".
    assert rows["fuzz"][2] == "no finding"
    assert _step_entry(document, "fuzz")["capped"] == []


def test_coverage_reads_inconclusive_for_enumerate_cut_by_the_cap(
    tmp_path: Path, lab_dir: Path
) -> None:
    # A tap that recorded 200 acks before the session: the PDID and PDCAP replies lie past the
    # default 200-frame cap, so enumerate saw nothing it could call clean.
    pair = _fixture_pair("cleartext")
    pair["pd2cp.cap"] = _with_leading(pair["pd2cp.cap"], constants.REPLY_ACK, 200)
    markdown, document = _full_run(lab_dir, FakeCompose(captures=pair), tmp_path / "out")
    entry = _step_entry(document, "sniff-enumerate")
    assert entry["status"] == "vulnerable"
    assert "ATK-01-sniff-pd-101" in entry["finding_ids"]
    assert not [fid for fid in entry["finding_ids"] if fid.startswith("ATK-02-")]
    assert entry["capped"] == ["pd->cp"]
    rows = _coverage_rows(markdown)
    assert rows["sniff"][2] == "ATK-01-sniff-pd-101"
    assert rows["enumerate"][2] == "inconclusive"
    assert _coverage_entry(document, "enumerate")["result"] == "inconclusive"


# Full-report shape (ASSESS-02) and size and content bounds (T-05-20). ------------------------


def _assess_healthy_lab(tmp_path: Path, lab_dir: Path) -> tuple[str, str]:
    """Run ``osdp assess`` over the healthy fake lab and return (markdown, raw JSON)."""
    md_path = tmp_path / "out" / "assessment.md"
    result = runner.invoke(app, ["osdp", "assess", "-o", str(md_path), "--lab-dir", str(lab_dir)])
    assert result.exit_code == 0, result.output
    json_path = md_path.with_suffix(".json")
    return md_path.read_text(encoding="utf-8"), json_path.read_text(encoding="utf-8")


def test_every_finding_of_a_full_assessment_is_complete_and_mapped(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose
) -> None:
    markdown, raw_json = _assess_healthy_lab(tmp_path, lab_dir)
    findings = json.loads(raw_json)["findings"]
    assert findings
    severities = {severity.value for severity in Severity}
    enterprise_ids = {technique.enterprise for technique in attack_map.MAPPINGS.values()}
    for finding in findings:
        fid = finding["id"]
        assert finding["severity"] in severities, fid
        for field in ("title", "evidence", "remediation", "attack_technique"):
            assert isinstance(finding[field], str) and finding[field].strip(), f"{fid}: {field}"
        assert finding["attack_technique"] in enterprise_ids, fid
        assert fid in markdown, fid


# The healthy fake run writes about 10 kB of Markdown and 13 kB of JSON (2026-10-27); 128 KiB
# is ten times that, so only a report that started dumping captures, frames or logs crosses it.
_REPORT_BYTE_BOUND = 128 * 1024


def test_assessment_reports_stay_bounded_and_carry_no_capture_bytes(
    tmp_path: Path, lab_dir: Path, fake: FakeCompose
) -> None:
    markdown, raw_json = _assess_healthy_lab(tmp_path, lab_dir)
    for name, text in (("markdown", markdown), ("json", raw_json)):
        assert len(text.encode("utf-8")) < _REPORT_BYTE_BOUND, name
    for basename, capture in fake.captures.items():
        assert len(capture) >= 32, basename
        for marker in (capture.hex()[:64], base64.b64encode(capture).decode()[:44]):
            assert marker not in markdown, f"{basename} dumped into markdown"
            assert marker not in raw_json, f"{basename} dumped into json"
