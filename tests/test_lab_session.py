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
import copy
import json
import subprocess
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from interlock.osdp import lab_session, tap_capture
from interlock.osdp.lab_session import (
    ALLOWED_OVERRIDES,
    DEFAULT_PROJECT,
    LabError,
    LabSession,
    containment_violations,
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


# --- containment rules (WR-07, T-06-38) ---------------------------------------------------

# The shape of ``docker compose config --format json`` over the bundled files (probed on
# v5.5.0), with a placeholder bind source: a real dump carries absolute host paths.
_CLEAN_CONFIG: dict[str, Any] = {
    "name": "interlock-assess",
    "networks": {"labnet": {"name": "interlock-assess_labnet", "internal": True}},
    "services": {
        "pd": {"networks": {"labnet": None}, "environment": {"LAB_SCENARIO": "cleartext"}},
        "attacker": {
            "networks": {"labnet": None},
            "environment": {"ATTACKER_UPSTREAM": "pd:10000", "PYTHONPATH": "/app/src"},
            "volumes": [
                {"type": "bind", "source": "/lab/src", "target": "/app/src", "read_only": True}
            ],
        },
        "cp": {
            "networks": {"labnet": None},
            "environment": {"LAB_SCENARIO": "cleartext", "CP_UPSTREAM": "attacker:10000"},
        },
    },
}


# The lab dir the placeholder bind source of _CLEAN_CONFIG sits in.
_LAB_DIR = Path("/lab")


def _planted(service: str, key: str, value: object) -> dict[str, Any]:
    """Return a deep copy of ``_CLEAN_CONFIG`` with ``key: value`` set on one service."""
    config = copy.deepcopy(_CLEAN_CONFIG)
    config["services"][service][key] = value
    return config


def test_clean_config_has_no_containment_violation() -> None:
    assert containment_violations(_CLEAN_CONFIG, _LAB_DIR) == []


@pytest.mark.parametrize(
    ("service", "key", "value"),
    [
        ("attacker", "ports", ["8000:10000"]),
        ("pd", "expose", ["10000"]),
        ("pd", "devices", ["/dev/ttyUSB0:/dev/ttyUSB0"]),
        ("attacker", "privileged", True),
        ("cp", "network_mode", "host"),
        ("attacker", "cap_add", ["NET_ADMIN"]),
        ("pd", "pid", "host"),
        ("cp", "ipc", "host"),
    ],
)
def test_containment_violation_per_service_key(service: str, key: str, value: object) -> None:
    violations = containment_violations(_planted(service, key, value), _LAB_DIR)
    assert len(violations) == 1, violations
    assert service in violations[0]
    assert key in violations[0]


@pytest.mark.parametrize(("key", "value"), [("privileged", False), ("cap_add", [])])
def test_falsy_service_keys_are_not_containment_violations(key: str, value: object) -> None:
    assert containment_violations(_planted("attacker", key, value), _LAB_DIR) == []


def test_check_containment_reports_a_planted_device_end_to_end(tmp_path: Path) -> None:
    planted = _in_lab(tmp_path)
    planted["services"]["pd"]["devices"] = ["/dev/ttyUSB0:/dev/ttyUSB0"]
    runner = _Runner(stdout={"config": json.dumps(planted)})

    violations = _session(tmp_path, runner).check_containment(("docker-compose.spoof.yml",))

    assert runner.argvs == [
        [*_base(tmp_path, "docker-compose.spoof.yml"), "config", "--format", "json"]
    ]
    assert len(violations) == 1, violations
    assert "pd" in violations[0]
    assert "devices" in violations[0]


def _cp_on_default(config: dict[str, Any]) -> None:
    config["services"]["cp"]["networks"]["default"] = None


def _labnet_not_internal(config: dict[str, Any]) -> None:
    config["networks"]["labnet"]["internal"] = False


def _labnet_internal_missing(config: dict[str, Any]) -> None:
    del config["networks"]["labnet"]["internal"]


def _writable_bind(config: dict[str, Any]) -> None:
    del config["services"]["attacker"]["volumes"][0]["read_only"]


def _cp_past_the_attacker(config: dict[str, Any]) -> None:
    config["services"]["cp"]["environment"]["CP_UPSTREAM"] = "pd:10000"


@pytest.mark.parametrize(
    ("breach", "where", "key"),
    [
        (_cp_on_default, "cp", "networks"),
        (_labnet_not_internal, "labnet", "internal"),
        (_labnet_internal_missing, "labnet", "internal"),
        (_writable_bind, "attacker", "volumes"),
        (_cp_past_the_attacker, "cp", "CP_UPSTREAM"),
    ],
)
def test_containment_violation_per_topology_breach(
    breach: Callable[[dict[str, Any]], None], where: str, key: str
) -> None:
    config = copy.deepcopy(_CLEAN_CONFIG)
    breach(config)
    violations = containment_violations(config, _LAB_DIR)
    assert len(violations) == 1, violations
    assert where in violations[0]
    assert key in violations[0]


def test_containment_violation_never_names_a_host_path() -> None:
    source = "/home/operator/interlock/src"
    volumes = [{"type": "bind", "source": source, "target": "/app/src"}]
    violations = containment_violations(_planted("attacker", "volumes", volumes), _LAB_DIR)
    assert len(violations) == 1, violations
    assert "attacker" in violations[0] and "volumes" in violations[0]
    assert not any(source in text or "/home/operator" in text for text in violations)


def _no_services(config: dict[str, Any]) -> None:
    del config["services"]


def _services_a_list(config: dict[str, Any]) -> None:
    config["services"] = ["pd", "attacker", "cp"]


def _service_a_string(config: dict[str, Any]) -> None:
    config["services"]["pd"] = "pd"


def _volume_a_string(config: dict[str, Any]) -> None:
    config["services"]["attacker"]["volumes"] = ["./src:/app/src"]


@pytest.mark.parametrize(
    "malform", [_no_services, _services_a_list, _service_a_string, _volume_a_string]
)
def test_malformed_config_is_a_containment_violation_not_an_exception(
    malform: Callable[[dict[str, Any]], None],
) -> None:
    config = copy.deepcopy(_CLEAN_CONFIG)
    malform(config)
    assert containment_violations(config, _LAB_DIR) != []


@pytest.mark.parametrize("kind", [["bind"], {"x": 1}, [], {}, [None], None, 1, "BIND"])
def test_mount_type_of_the_wrong_type_is_a_containment_violation_not_an_exception(
    kind: object,
) -> None:
    volumes = [{"type": kind, "source": "/lab/src", "target": "/app/src", "read_only": True}]
    violations = containment_violations(_planted("attacker", "volumes", volumes), _LAB_DIR)
    assert len(violations) == 1, violations
    assert "attacker" in violations[0] and "volumes" in violations[0]
    assert repr(kind) not in violations[0] and "/lab/src" not in violations[0]


@pytest.mark.parametrize("service", ["pd", "attacker", "cp"])
@pytest.mark.parametrize("networks", [[], {}, "missing"])
def test_service_on_no_network_is_a_containment_violation(
    service: str, networks: object
) -> None:
    config = _planted(service, "networks", networks)
    if networks == "missing":
        del config["services"][service]["networks"]
    violations = containment_violations(config, _LAB_DIR)
    assert len(violations) == 1, violations
    assert service in violations[0] and "networks" in violations[0]


@pytest.mark.parametrize(
    ("service", "key", "value", "expected"),
    [
        ("cp", "environment", ["LAB_SCENARIO=cleartext", "CP_UPSTREAM=pd:10000"], 1),
        ("cp", "environment", ["LAB_SCENARIO=cleartext", "CP_UPSTREAM=attacker:10000"], 0),
        ("pd", "networks", ["labnet"], 0),
        ("pd", "networks", ["labnet", "default"], 1),
    ],
)
def test_list_form_environment_and_networks_are_read_like_mappings_for_containment(
    service: str, key: str, value: list[str], expected: int
) -> None:
    violations = containment_violations(_planted(service, key, value), _LAB_DIR)
    assert len(violations) == expected, violations
    if expected:
        assert service in violations[0]


def test_check_containment_turns_a_failed_config_into_a_bounded_violation(
    tmp_path: Path,
) -> None:
    stderr = "x" * 5000 + "service pd: no such file"
    runner = _Runner(returncodes={"config": 1}, stderr={"config": stderr})

    violations = _session(tmp_path, runner).check_containment(("docker-compose.tap.yml",))

    assert len(violations) == 1, violations
    assert "config" in violations[0] and "exit 1" in violations[0]
    assert violations[0].endswith("service pd: no such file")
    assert len(violations[0]) < 2100


def test_check_containment_turns_output_that_is_not_json_into_a_violation(
    tmp_path: Path,
) -> None:
    runner = _Runner(stdout={"config": "not json"})
    violations = _session(tmp_path, runner).check_containment(("docker-compose.tap.yml",))
    assert len(violations) == 1, violations
    assert "JSON" in violations[0]


def test_check_containment_rejects_a_foreign_override_before_any_command(
    tmp_path: Path,
) -> None:
    runner = _Runner(stdout={"config": json.dumps(_CLEAN_CONFIG)})
    with pytest.raises(ValueError, match="not allowed"):
        _session(tmp_path, runner).check_containment(("docker-compose.vuln.yml",))
    assert runner.calls == []


def test_containment_sentence_names_every_rule() -> None:
    sentence = lab_session.containment_sentence(
        ["docker-compose.yml", *sorted(ALLOWED_OVERRIDES)]
    )
    assert len(lab_session.CONTAINMENT_RULES) >= 7
    for rule in lab_session.CONTAINMENT_RULES:
        assert rule in sentence, rule


# --- deny by default: keys, mount sources, builds and networks (WR-07 follow-up) ----------

# A host path planted in values: no violation text may carry it (T-06-40).
_HOST = "/home/operator"

# ``docker compose config --format json`` over docker-compose.yml plus each allowed override,
# captured on Compose v5.5.0 with the lab dir replaced by @LAB_DIR@.
_RESOLVED_FIXTURE = Path(__file__).parent / "fixtures" / "lab_compose_config.json"


def _with_lab_dir(node: Any, lab: Path) -> Any:
    """Return ``node`` with every @LAB_DIR@ in its strings replaced by ``lab``."""
    if isinstance(node, dict):
        return {key: _with_lab_dir(value, lab) for key, value in node.items()}
    if isinstance(node, list):
        return [_with_lab_dir(value, lab) for value in node]
    if isinstance(node, str):
        return node.replace("@LAB_DIR@", str(lab))
    return node


def _lab(tmp_path: Path) -> Path:
    lab = tmp_path / "lab"
    (lab / "src").mkdir(parents=True)
    return lab


def _in_lab(lab: Path) -> dict[str, Any]:
    """Return ``_CLEAN_CONFIG`` with its bind source inside ``lab``, the session's lab dir."""
    config = copy.deepcopy(_CLEAN_CONFIG)
    config["services"]["attacker"]["volumes"][0]["source"] = str(lab / "src")
    return config


def _checked(lab: Path, config: Mapping[str, Any]) -> list[str]:
    """Run ``check_containment`` over ``config`` as the resolved output for ``lab``."""
    runner = _Runner(stdout={"config": json.dumps(config)})
    return _session(lab, runner).check_containment(("docker-compose.tap.yml",))


def _assert_one_naming(violations: list[str], where: str, key: str) -> None:
    assert len(violations) == 1, violations
    assert where in violations[0] and key in violations[0], violations
    assert _HOST not in violations[0], violations


def test_bind_in_lab_config_is_contained(tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    assert _checked(lab, _in_lab(lab)) == []


@pytest.mark.parametrize(
    ("service", "key", "value"),
    [
        ("attacker", "security_opt", ["apparmor=unconfined", "seccomp=unconfined"]),
        ("pd", "userns_mode", "host"),
        ("cp", "uts", "host"),
        ("attacker", "cgroup", "host"),
        ("pd", "device_cgroup_rules", ["c 188:* rmw"]),
        ("attacker", "volumes_from", ["helper"]),
        ("cp", "use_api_socket", True),
        ("attacker", "logging", {"driver": "syslog", "options": {"syslog-address": _HOST}}),
        ("pd", "x-anything", f"{_HOST}/secret"),
    ],
)
def test_service_key_outside_the_allow_list_is_a_containment_violation(
    tmp_path: Path, service: str, key: str, value: object
) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["services"][service][key] = value
    _assert_one_naming(_checked(lab, config), service, key)


@pytest.mark.parametrize(
    "source",
    [
        "/var/run/docker.sock",
        f"{_HOST}/.ssh",
        "@OUTSIDE@",
        "@LAB@/src/../../outside",
        "@LAB@/escape",
    ],
)
def test_read_only_bind_from_outside_the_lab_dir_is_a_containment_violation(
    tmp_path: Path, source: str
) -> None:
    lab = _lab(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    if source.endswith("/escape"):
        try:
            (lab / "escape").symlink_to(outside, target_is_directory=True)
        except OSError as exc:  # Windows without the symlink privilege
            pytest.skip(f"cannot create a symlink here: {exc}")
    config = _in_lab(lab)
    volume = config["services"]["attacker"]["volumes"][0]
    volume["source"] = source.replace("@OUTSIDE@", str(outside)).replace("@LAB@", str(lab))
    assert volume["read_only"] is True
    violations = _checked(lab, config)
    _assert_one_naming(violations, "attacker", "volumes")
    assert not any(str(tmp_path) in text or "docker.sock" in text for text in violations)


@pytest.mark.parametrize("relative", ["src", ".", "lab/osdp"])
def test_read_only_bind_from_inside_the_lab_dir_is_contained(
    tmp_path: Path, relative: str
) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["services"]["attacker"]["volumes"][0]["source"] = str(lab / relative)
    assert _checked(lab, config) == []


def test_tmpfs_and_plain_named_volume_mounts_are_contained(tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["volumes"] = {"captures": {"name": "interlock-assess_captures"}}
    config["services"]["attacker"]["volumes"] += [
        {"type": "volume", "source": "captures", "target": "/app/capture"},
        {"type": "tmpfs", "target": "/tmp"},
    ]
    assert _checked(lab, config) == []


def test_mount_type_beyond_bind_volume_and_tmpfs_is_a_containment_violation(
    tmp_path: Path,
) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["services"]["pd"]["volumes"] = [
        {"type": "npipe", "source": r"\\.\pipe\docker_engine", "target": r"\\.\pipe\docker_engine"}
    ]
    violations = _checked(lab, config)
    _assert_one_naming(violations, "pd", "volumes")
    assert not any("pipe" in text for text in violations)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("external", True),
        ("driver", "nfs"),
        ("driver_opts", {"type": "none", "o": "bind", "device": _HOST}),
    ],
)
def test_named_volume_backed_by_anything_but_a_plain_volume_is_a_containment_violation(
    tmp_path: Path, key: str, value: object
) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["volumes"] = {"captures": {"name": "interlock-assess_captures", key: value}}
    config["services"]["attacker"]["volumes"].append(
        {"type": "volume", "source": "captures", "target": "/app/capture"}
    )
    _assert_one_naming(_checked(lab, config), "captures", key)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("external", True),
        ("driver", "macvlan"),
        ("driver_opts", {"parent": "eth0"}),
        ("attachable", True),
    ],
)
def test_network_that_is_not_a_plain_compose_bridge_is_a_containment_violation(
    tmp_path: Path, key: str, value: object
) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["networks"]["labnet"][key] = value
    _assert_one_naming(_checked(lab, config), "labnet", key)


@pytest.mark.parametrize(
    "name", ["bridge", "host", "interlock-lab_labnet", "interlock-assess_other", ""]
)
def test_network_named_onto_anything_but_its_compose_name_is_a_containment_violation(
    tmp_path: Path, name: str
) -> None:
    # A name that is not {project}_{key} can join a network compose did not create.
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["networks"]["labnet"]["name"] = name
    _assert_one_naming(_checked(lab, config), "labnet", "name")


@pytest.mark.parametrize("name", ["operator-data", "interlock-assess_other", "captures"])
def test_named_volume_named_onto_anything_but_its_compose_name_is_a_containment_violation(
    tmp_path: Path, name: str
) -> None:
    # A volume created outside compose (say, a bind of / as a local volume) is mounted as is.
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["volumes"] = {"captures": {"name": name}}
    config["services"]["attacker"]["volumes"].append(
        {"type": "volume", "source": "captures", "target": "/app/capture"}
    )
    _assert_one_naming(_checked(lab, config), "captures", "name")


def test_network_without_a_name_is_contained(tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    del config["networks"]["labnet"]["name"]
    assert _checked(lab, config) == []


@pytest.mark.parametrize("project", [None, "", 5, ["interlock-assess"]])
def test_config_without_a_project_name_is_a_containment_violation(
    tmp_path: Path, project: object
) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    if project is None:
        del config["name"]
    else:
        config["name"] = project
    violations = _checked(lab, config)
    assert len(violations) == 1, violations
    assert violations[0].startswith("name:"), violations


def test_explicit_bridge_driver_is_contained(tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["networks"]["labnet"]["driver"] = "bridge"
    assert _checked(lab, config) == []


@pytest.mark.parametrize(
    "build",
    [
        {"context": "@LAB_DIR@", "dockerfile": "Dockerfile", "network": "host"},
        {"context": "@LAB_DIR@", "dockerfile": "Dockerfile", "ssh": ["default"]},
        {"context": "@LAB_DIR@", "dockerfile": "Dockerfile", "additional_contexts": {"h": _HOST}},
        {"context": _HOST, "dockerfile": "Dockerfile"},
        {"context": "@LAB_DIR@", "dockerfile": f"{_HOST}/Dockerfile"},
        "@LAB_DIR@",
        # Remote contexts: compose keeps them unresolved, and joined onto the lab dir as a
        # relative path they would resolve inside it.
        {"context": "https://github.com/x/y.git#main", "dockerfile": "Dockerfile"},
        {"context": "git@github.com:x/y.git", "dockerfile": "Dockerfile"},
        {"context": "git://example.org/y.git", "dockerfile": "Dockerfile"},
        {"context": "github.com/x/y", "dockerfile": "Dockerfile"},
        {"context": "@LAB_DIR@/src#main", "dockerfile": "Dockerfile"},
        # compose prints a local context absolute; anything relative is not its output.
        {"context": "src", "dockerfile": "Dockerfile"},
    ],
)
def test_build_beyond_a_plain_lab_dir_build_is_a_containment_violation(
    tmp_path: Path, build: object
) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["services"]["cp"]["build"] = _with_lab_dir(build, lab)
    _assert_one_naming(_checked(lab, config), "cp", "build")


def test_unlisted_top_level_section_is_a_containment_violation(tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    config = _in_lab(lab)
    config["secrets"] = {"shadow": {"file": "/etc/shadow"}}
    violations = _checked(lab, config)
    assert len(violations) == 1, violations
    assert "secrets" in violations[0]
    assert "/etc/shadow" not in violations[0]


def test_every_bundled_compose_file_set_resolves_contained(tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    resolved = json.loads(_RESOLVED_FIXTURE.read_text(encoding="utf-8"))
    assert set(resolved) == ALLOWED_OVERRIDES
    for override, config in sorted(resolved.items()):
        runner = _Runner(stdout={"config": json.dumps(_with_lab_dir(config, lab))})
        violations = _session(lab, runner).check_containment((override,))
        assert violations == [], f"{override}: {violations}"


# JSON values of every kind that are wrong almost anywhere in a resolved config.
_MALFORMED: tuple[object, ...] = (
    None, [], {}, ["bind"], {"x": 1}, [["x"]], [{"x": 1}], [None], 0, 1.5, True, "", "a\x00b",
)


def _node_paths(node: object, path: tuple[object, ...] = ()) -> Iterator[tuple[object, ...]]:
    """Yield the path to every node below ``node`` (dict keys and list indexes)."""
    if path:
        yield path
    if isinstance(node, dict):
        children: Iterable[tuple[object, object]] = node.items()
    elif isinstance(node, list):
        children = enumerate(node)
    else:
        children = ()
    for key, child in children:
        yield from _node_paths(child, (*path, key))


@pytest.mark.parametrize("override", sorted(ALLOWED_OVERRIDES))
def test_containment_violations_is_total_over_every_malformed_node(
    tmp_path: Path, override: str
) -> None:
    lab = _lab(tmp_path)
    resolved = json.loads(_RESOLVED_FIXTURE.read_text(encoding="utf-8"))
    clean = _with_lab_dir(resolved[override], lab)
    for path in _node_paths(clean):
        for value in _MALFORMED:
            config = copy.deepcopy(clean)
            parent = config
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = value
            violations = containment_violations(config, lab)
            assert isinstance(violations, list), path
            assert all(isinstance(text, str) for text in violations), path


def test_containment_sentence_claims_only_what_the_rules_check() -> None:
    sentence = lab_session.containment_sentence(
        ["docker-compose.yml", *sorted(ALLOWED_OVERRIDES)]
    )
    assert "no real hardware is reachable" not in sentence
    assert "lab dir" in sentence
    assert "not covered" in sentence


# --- lab-only by construction (D-04)-------------------------------------------------------

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
