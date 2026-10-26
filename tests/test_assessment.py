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
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from interlock import report
from interlock.cli import app
from interlock.osdp import lab_session

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
