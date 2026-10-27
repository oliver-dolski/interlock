"""Host proof of the lab driver behind the assessment (ASSESS-01, no Docker).

A recording fake runner stands in for ``docker compose``: it stores every (argv, env) it is
handed and answers by subcommand, and a fake sleep/clock pair stands in for time, so every path
of ``interlock.osdp.lab_session`` is proven here without a container and without real sleeping.

- the tracer path: one ``scenario("cleartext", ("docker-compose.tap.yml",))`` runs the exact
  ``up`` argv under project interlock-assess with LAB_SCENARIO=cleartext, polls the cp log
  sentinels, reads both tap captures as base64 out of the attacker, then runs ``down -v``.
- fail closed: a profile or override outside the allow-lists (the vulnerable-core override
  included, D-03) raises ValueError before any docker command runs.
- guaranteed teardown: a raising body, a KeyboardInterrupt and a failed ``up`` all still end in
  ``down -v`` for the same project; a LabError carries a bounded stderr tail, never the env.
- bounded waits and strict reads: wait_for_log gives up at its deadline on the fake clock;
  logs and read_capture reject a non-zero exit, read_capture rejects output that is not base64.
- the small helpers (reset, find_lab_dir, docker_available, make_runner) and an ast scan that
  keeps the module lab-only (D-04).
"""

from __future__ import annotations

import ast
import base64
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from interlock.osdp import lab_session, tap_capture
from interlock.osdp.lab_session import (
    ALLOWED_OVERRIDES,
    DEFAULT_PROJECT,
    LabError,
    LabSession,
    docker_available,
    find_lab_dir,
    make_runner,
)

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
    """A recording ``Runner`` seam that answers each docker compose subcommand.

    By default every subcommand exits 0, ``logs`` carries both cp sentinels and ``exec`` the
    base64 of the canned capture for the requested basename. ``returncodes``, ``stdout`` and
    ``stderr`` override the answer per subcommand (keyed by ``up``, ``down``, ``logs``, ...).
    """

    def __init__(
        self,
        *,
        returncodes: Mapping[str, int] | None = None,
        stdout: Mapping[str, str] | None = None,
        stderr: Mapping[str, str] | None = None,
    ) -> None:
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.returncodes = dict(returncodes or {})
        self.stdout = dict(stdout or {})
        self.stderr = dict(stderr or {})

    @property
    def argvs(self) -> list[list[str]]:
        return [argv for argv, _ in self.calls]

    def __call__(
        self, argv: Sequence[str], env: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        argv = list(argv)
        self.calls.append((argv, dict(env)))
        sub = _subcommand(argv)
        if sub in self.stdout:
            stdout = self.stdout[sub]
        elif sub == "logs":
            stdout = _CP_LOG
        elif sub == "exec":
            stdout = base64.b64encode(_CANNED[PurePosixPath(argv[-1]).name]).decode()
        else:
            stdout = ""
        return subprocess.CompletedProcess(
            argv, self.returncodes.get(sub, 0), stdout, self.stderr.get(sub, "")
        )


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


def _session(lab: Path, runner: _Runner, clock: _Clock | None = None) -> LabSession:
    clock = clock if clock is not None else _Clock()
    return LabSession(lab, runner=runner, sleep=clock.sleep, clock=clock)


def _assert_every_up_torn_down(argvs: list[list[str]], project: str) -> None:
    """Every ``up`` argv is followed later by a ``down -v`` argv for the same project."""
    ups = [i for i, argv in enumerate(argvs) if _subcommand(argv) == "up"]
    assert ups, "no up was recorded"
    for i in ups:
        assert argvs[i][2:4] == ["-p", project]
        assert any(
            argv[2:4] == ["-p", project] and argv[-2:] == ["down", "-v"]
            for argv in argvs[i + 1 :]
        ), f"up at call {i} has no later down -v for {project}"


# --- allow-lists (T-05-01, D-03) ---------------------------------------------------------


def test_vulnerable_override_is_not_allowed() -> None:
    assert "docker-compose.vuln.yml" not in ALLOWED_OVERRIDES


@pytest.mark.parametrize(
    ("profile", "overrides"),
    [
        ("vulnerable", ()),
        ("cleartext", ("docker-compose.vuln.yml",)),
        ("cleartext", ("docker-compose.tap.yml", "docker-compose.vuln.yml")),
        ("cleartext", ("../docker-compose.tap.yml",)),
    ],
)
def test_scenario_outside_allow_lists_raises_before_any_command(
    tmp_path: Path, profile: str, overrides: tuple[str, ...]
) -> None:
    runner = _Runner()
    with (
        pytest.raises(ValueError, match="not allowed|unknown lab profile"),
        _session(tmp_path, runner).scenario(profile, overrides),
    ):
        pytest.fail("the body must not run")
    assert runner.calls == []


# --- guaranteed teardown (T-05-05) -------------------------------------------------------


def test_raising_body_still_tears_down_and_propagates_unchanged(tmp_path: Path) -> None:
    runner = _Runner()
    boom = RuntimeError("body failed")
    with (
        pytest.raises(RuntimeError) as caught,
        _session(tmp_path, runner).scenario("cleartext", ("docker-compose.tap.yml",)),
    ):
        raise boom
    assert caught.value is boom
    assert runner.argvs[-1] == [*_base(tmp_path, "docker-compose.tap.yml"), "down", "-v"]
    _assert_every_up_torn_down(runner.argvs, "interlock-assess")


def test_keyboard_interrupt_in_body_still_tears_down(tmp_path: Path) -> None:
    runner = _Runner()
    with (
        pytest.raises(KeyboardInterrupt),
        _session(tmp_path, runner).scenario("downgrade", ("docker-compose.downgrade.yml",)),
    ):
        raise KeyboardInterrupt
    assert runner.argvs[-1] == [*_base(tmp_path, "docker-compose.downgrade.yml"), "down", "-v"]
    _assert_every_up_torn_down(runner.argvs, "interlock-assess")


def test_failed_up_raises_lab_error_with_stderr_tail_and_tears_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INTERLOCK_TEST_SECRET", "s3cr3t-env-value")
    runner = _Runner(
        returncodes={"up": 17},
        stderr={"up": "x" * 10_000 + "failed to build image cp: exit status 2"},
    )
    with (
        pytest.raises(LabError) as caught,
        _session(tmp_path, runner).scenario("cleartext", ("docker-compose.tap.yml",)),
    ):
        pytest.fail("the body must not run after a failed up")
    message = str(caught.value)
    assert "failed to build image cp: exit status 2" in message
    assert "17" in message
    assert len(message) < 2_500  # a bounded tail, not the whole stderr
    assert "s3cr3t-env-value" not in message  # never the environment (ASVS V7)
    assert runner.argvs[-1] == [*_base(tmp_path, "docker-compose.tap.yml"), "down", "-v"]
    _assert_every_up_torn_down(runner.argvs, "interlock-assess")


# --- bounded waits and strict container reads (T-05-05, T-05-24) -----------------------


def test_wait_for_log_gives_up_at_the_deadline_without_real_sleep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _no_real_sleep(seconds: float) -> None:
        raise AssertionError(f"real time.sleep({seconds}) was called")

    monkeypatch.setattr(time, "sleep", _no_real_sleep)
    runner = _Runner(stdout={"logs": "cp-1  | still starting\n"})
    clock = _Clock()
    with _session(tmp_path, runner, clock).scenario("cleartext") as lab:
        assert lab.wait_for_log("cp", _PD_ONLINE, timeout=5) is False
    assert clock.sleeps == [1.0] * 5
    assert clock.now == 5.0


def test_logs_non_zero_exit_raises_lab_error(tmp_path: Path) -> None:
    runner = _Runner(returncodes={"logs": 1}, stderr={"logs": "no such service: cp"})
    with _session(tmp_path, runner).scenario("cleartext") as lab, pytest.raises(LabError):
        lab.logs("cp")
    _assert_every_up_torn_down(runner.argvs, "interlock-assess")


def test_read_capture_non_zero_exit_raises_lab_error(tmp_path: Path) -> None:
    runner = _Runner(returncodes={"exec": 1}, stdout={"exec": ""})
    with (
        _session(tmp_path, runner).scenario("cleartext", ("docker-compose.tap.yml",)) as lab,
        pytest.raises(LabError),
    ):
        lab.read_capture(tap_capture.CP2PD_PATH.as_posix())


def test_read_capture_rejects_output_that_is_not_base64(tmp_path: Path) -> None:
    runner = _Runner(stdout={"exec": "not base64!"})
    with (
        _session(tmp_path, runner).scenario("cleartext", ("docker-compose.tap.yml",)) as lab,
        pytest.raises(LabError, match="not valid base64"),
    ):
        lab.read_capture(tap_capture.CP2PD_PATH.as_posix())


def test_read_capture_of_an_absent_file_is_empty(tmp_path: Path) -> None:
    runner = _Runner(stdout={"exec": ""})
    with _session(tmp_path, runner).scenario("cleartext", ("docker-compose.tap.yml",)) as lab:
        assert lab.read_capture(tap_capture.PD2CP_PATH.as_posix()) == b""


# --- helpers ------------------------------------------------------------------------------


def test_reset_runs_one_down_and_ignores_a_non_zero_exit(tmp_path: Path) -> None:
    runner = _Runner(returncodes={"down": 1}, stderr={"down": "no such project"})
    _session(tmp_path, runner).reset()
    assert runner.argvs == [[*_base(tmp_path), "down", "-v"]]


def test_inherited_topology_variables_never_reach_compose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A shell left with these would reroute the lab: the cp straight to the pd, or the
    # attacker to a host outside it (WR-03). DOCKER_HOST must survive: it picks the Docker.
    monkeypatch.setenv("CP_UPSTREAM", "pd:10000")
    monkeypatch.setenv("ATTACKER_UPSTREAM", "evil:1")
    monkeypatch.setenv("DOCKER_HOST", "unix:///tmp/d.sock")
    runner = _Runner(stdout={"config": "{}"})
    session = _session(tmp_path, runner)

    session.reset()
    session.check_containment(("docker-compose.spoof.yml",))
    with session.scenario("sc-scbkd", ("docker-compose.tap.yml",)) as lab:
        lab.logs("cp")
        assert lab.env["CP_UPSTREAM"] == "attacker:10000"

    assert [_subcommand(argv) for argv in runner.argvs] == ["down", "config", "up", "logs", "down"]
    for argv, env in runner.calls:
        assert env["CP_UPSTREAM"] == "attacker:10000", argv
        assert env["ATTACKER_UPSTREAM"] == "pd:10000", argv
        assert env["DOCKER_HOST"] == "unix:///tmp/d.sock", argv
    assert [env["LAB_SCENARIO"] for _, env in runner.calls[2:]] == ["sc-scbkd"] * 3


def test_find_lab_dir_returns_the_first_ancestor_with_both_compose_files(
    tmp_path: Path,
) -> None:
    lab = tmp_path / "lab"
    half = lab / "half"
    start = half / "deep" / "er"
    start.mkdir(parents=True)
    (lab / "docker-compose.yml").write_text("services: {}\n")
    (lab / "docker-compose.tap.yml").write_text("services: {}\n")
    (half / "docker-compose.yml").write_text("services: {}\n")  # only one of the two
    assert find_lab_dir(start) == lab.resolve()
    assert find_lab_dir(lab) == lab.resolve()


def test_find_lab_dir_returns_none_without_compose_files(tmp_path: Path) -> None:
    start = tmp_path / "nothing" / "here"
    start.mkdir(parents=True)
    assert find_lab_dir(start) is None


def test_docker_available_follows_shutil_which(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        lab_session.shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None
    )
    assert docker_available() is True
    monkeypatch.setattr(lab_session.shutil, "which", lambda name: None)
    assert docker_available() is False


def test_make_runner_runs_a_list_argv_from_the_lab_dir_without_a_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def _fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 0, "", "")

    monkeypatch.setattr(lab_session.subprocess, "run", _fake_run)
    argv = ("docker", "compose", "-p", "interlock-assess", "ps")
    env = {"LAB_SCENARIO": "cleartext", "PATH": "/usr/bin"}
    result = make_runner(tmp_path)(argv, env)

    assert result.returncode == 0
    assert len(seen) == 1
    args, kwargs = seen[0]
    assert args == (list(argv),)
    assert isinstance(args[0], list)
    assert kwargs["cwd"] == tmp_path
    assert kwargs["env"] == env
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    # Docker prints UTF-8; the platform default (cp1252 on Windows) must not decide.
    assert kwargs["encoding"] == "utf-8"
    assert kwargs["errors"] == "replace"
    assert kwargs["check"] is False
    assert not kwargs.get("shell")


# --- lab-only by construction (D-04) -------------------------------------------------------

_FORBIDDEN_IMPORT_PARTS = ("safety", "serial", "open_serial_endpoint", "open_physical_endpoint")


def test_lab_session_imports_nothing_physical_and_nothing_from_tests() -> None:
    assert lab_session.__file__ is not None
    tree = ast.parse(Path(lab_session.__file__).read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
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
