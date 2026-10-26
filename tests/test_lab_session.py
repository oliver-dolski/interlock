"""Host proof of the lab driver behind the assessment (ASSESS-01, no Docker).

A recording fake runner stands in for ``docker compose``: it stores every (argv, env) it is
handed and answers by subcommand, and a fake sleep/clock pair stands in for time, so every path
of ``interlock.osdp.lab_session`` is proven here without a container and without real sleeping.

- the tracer path: one ``scenario("cleartext", ("docker-compose.tap.yml",))`` runs the exact
  ``up`` argv under project interlock-assess with LAB_SCENARIO=cleartext, polls the cp log
  sentinels, reads both tap captures as base64 out of the attacker, then runs ``down -v``.
"""

from __future__ import annotations

import base64
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

from interlock.osdp import tap_capture
from interlock.osdp.lab_session import DEFAULT_PROJECT, LabSession

_PD_ONLINE = "interlock-lab: PD 101 online"
_EVENT = "interlock-lab: event received"
_CP_LOG = f"cp-1  | {_PD_ONLINE}\ncp-1  | {_EVENT}\n"

# Distinct canned capture bytes per container file, keyed by basename.
_CANNED = {
    "cp2pd.cap": b"\xff\x53\x65\x08\x00\x04\x60\x00",
    "pd2cp.cap": b"\xff\x53\xe5\x08\x00\x04\x40\x00",
}

# Flags of the base ``docker compose`` argv that take a value before the subcommand.
_VALUE_FLAGS = {"-p", "-f"}


def _subcommand(argv: Sequence[str]) -> str:
    """Return the compose subcommand of ``argv`` (the first token after the base flags)."""
    tokens = list(argv[2:])
    i = 0
    while i < len(tokens) and tokens[i] in _VALUE_FLAGS:
        i += 2
    return tokens[i]


class _Runner:
    """A recording ``Runner`` seam that answers each docker compose subcommand."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    @property
    def argvs(self) -> list[list[str]]:
        return [argv for argv, _ in self.calls]

    def __call__(
        self, argv: Sequence[str], env: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        self.calls.append((argv, dict(env)))
        sub = _subcommand(argv)
        stdout = ""
        if sub == "logs":
            stdout = _CP_LOG
        elif sub == "exec":
            stdout = base64.b64encode(_CANNED[PurePosixPath(argv[-1]).name]).decode()
        return subprocess.CompletedProcess(argv, 0, stdout, "")


class _Clock:
    """A fake monotonic clock that only advances when the fake sleep is called."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _base(lab: Path, *overrides: str) -> list[str]:
    files = ["-f", str(lab / "docker-compose.yml")]
    for override in overrides:
        files += ["-f", str(lab / override)]
    return ["docker", "compose", "-p", "interlock-assess", *files]


def test_cleartext_tap_scenario_end_to_end(tmp_path: Path) -> None:
    runner = _Runner()
    clock = _Clock()
    session = LabSession(tmp_path, runner=runner, sleep=clock.sleep, clock=clock)

    with session.scenario("cleartext", ("docker-compose.tap.yml",)) as lab:
        assert lab.wait_for_log("cp", _PD_ONLINE, timeout=180)
        assert lab.wait_for_log("cp", _EVENT, timeout=90)
        cp2pd = lab.read_capture(tap_capture.CP2PD_PATH.as_posix())
        pd2cp = lab.read_capture(tap_capture.PD2CP_PATH.as_posix())

    assert cp2pd == _CANNED["cp2pd.cap"]
    assert pd2cp == _CANNED["pd2cp.cap"]

    base = _base(tmp_path, "docker-compose.tap.yml")
    assert DEFAULT_PROJECT == "interlock-assess"
    assert runner.argvs[0] == [
        "docker", "compose", "-p", "interlock-assess",
        "-f", f"{tmp_path}/docker-compose.yml",
        "-f", f"{tmp_path}/docker-compose.tap.yml",
        "up", "-d", "--build", "--force-recreate",
    ]
    assert runner.argvs[1:-1] == [
        [*base, "logs", "--no-color", "cp"],
        [*base, "logs", "--no-color", "cp"],
        [*base, "exec", "-T", "attacker", "python", "-c", runner.argvs[3][-2],
         "/app/capture/cp2pd.cap"],
        [*base, "exec", "-T", "attacker", "python", "-c", runner.argvs[4][-2],
         "/app/capture/pd2cp.cap"],
    ]
    assert runner.argvs[-1] == [*base, "down", "-v"]
    assert runner.calls[0][1]["LAB_SCENARIO"] == "cleartext"
    # Both sentinels were already in the log: no polling sleep was needed.
    assert clock.sleeps == []
