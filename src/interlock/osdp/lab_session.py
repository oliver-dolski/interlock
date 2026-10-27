"""Host-side driver for the bundled OSDP lab, used by the assessment (ASSESS-01).

``LabSession`` brings one lab scenario up with ``docker compose`` under its own compose
project (``interlock-assess``, never the ``interlock-lab`` project the @lab suite uses, so an
assessment cannot collide with a running ``pytest -m lab``), hands back a ``LabHandle`` for
polling service logs and reading capture files out of the attacker container, and always runs
``docker compose down -v`` afterwards, also when the caller's body raises or ``up`` fails.

Lab-only by design (D-04): it drives only the compose files bundled at the lab root, the
scenario must be one of ``LAB_PROFILES`` and every override one of ``ALLOWED_OVERRIDES``, both
checked before any command runs. The pinned-vulnerable core override is deliberately absent
from the allow-list (D-03). Every command is a list argv handed to ``subprocess.run`` without a
shell. It adds no published port and changes no compose file, so SAFE-01 containment is
unchanged: captures leave the attacker container only as base64 over ``docker compose exec``.
``check_containment`` proves that per file set before anything runs: it resolves the files with
``docker compose config`` and reports every ``CONTAINMENT_RULES`` violation (WR-07). Every
compose call runs with the bus topology pinned (``_PINNED_TOPOLOGY``), so a CP_UPSTREAM or
ATTACKER_UPSTREAM left in the operator's shell cannot reroute the lab (WR-03).

The runner, sleep and clock are injectable, so the host suite proves every path without Docker.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

# Runs one docker command (list argv, explicit env) and returns its captured text result.
Runner = Callable[[Sequence[str], Mapping[str, str]], "subprocess.CompletedProcess[str]"]

# Own compose project: never "interlock-lab", which tests/lab/conftest.py brings up.
DEFAULT_PROJECT = "interlock-assess"

# Mirrors lab/osdp/scenarios.Scenario (the LAB_SCENARIO values the lab drivers accept).
LAB_PROFILES = frozenset({"cleartext", "sc-scbkd", "downgrade", "cve-replay"})

# Overrides the assessment may layer on docker-compose.yml. docker-compose.vuln.yml (the
# pinned-vulnerable libosdp core) is deliberately absent (D-03).
ALLOWED_OVERRIDES = frozenset(
    {
        "docker-compose.tap.yml",
        "docker-compose.fuzz.yml",
        "docker-compose.downgrade.yml",
        "docker-compose.spoof.yml",
        "docker-compose.replay.yml",
        "docker-compose.cve.yml",
    }
)

COMPOSE_FILE = "docker-compose.yml"
_TAP_FILE = "docker-compose.tap.yml"

# The bus topology the lab is wired for (WR-03). docker-compose.yml interpolates both from the
# environment with these defaults, so a value left in the operator's shell would reroute the
# lab, e.g. the cp straight to the pd past the attacker. Pinned for every compose call.
_PINNED_TOPOLOGY = {"CP_UPSTREAM": "attacker:10000", "ATTACKER_UPSTREAM": "pd:10000"}

# What the preflight proves of every resolved compose file set before anything runs (WR-07).
# The report's Containment line names exactly these, so it never claims an unchecked rule.
CONTAINMENT_RULES: tuple[str, ...] = ("every network internal", "no published ports")

# Upper bound on the stderr carried into a LabError, so a noisy build cannot flood a report.
_STDERR_TAIL = 2000

# Read an in-container capture as base64 so binary survives the text pipe; an absent file
# prints "" (decoded on the host as b"").
_READ_CAPTURE = (
    "import base64, os, sys\n"
    "p = sys.argv[1]\n"
    "data = open(p, 'rb').read() if os.path.exists(p) else b''\n"
    "sys.stdout.write(base64.b64encode(data).decode())\n"
)


class LabError(RuntimeError):
    """A lab docker command failed or returned output the driver cannot trust."""


def _failure(what: str, result: subprocess.CompletedProcess[str]) -> str:
    """Describe a failed command by name, exit code and a bounded stderr tail (never the env)."""
    tail = (result.stderr or "").strip()[-_STDERR_TAIL:]
    return f"docker compose {what} failed (exit {result.returncode}): {tail}"


def _lab_env(profile: str | None) -> dict[str, str]:
    """Return the environment for a compose call: the topology pinned, LAB_SCENARIO if given.

    The rest of ``os.environ`` is kept, since DOCKER_HOST, DOCKER_CONTEXT and PATH decide which
    Docker the call reaches. The process env beats any env file, so pinning here is enough.
    """
    env = {key: value for key, value in os.environ.items() if key not in _PINNED_TOPOLOGY}
    env.update(_PINNED_TOPOLOGY)
    if profile is not None:
        env["LAB_SCENARIO"] = profile
    return env


def _check_overrides(overrides: Sequence[str]) -> None:
    """Raise unless ``overrides`` is a sequence of names from ``ALLOWED_OVERRIDES``."""
    if isinstance(overrides, str):
        raise TypeError("overrides must be a sequence of file names, not a single string")
    for override in overrides:
        if override not in ALLOWED_OVERRIDES:
            raise ValueError(f"compose override {override!r} is not allowed; expected "
                             f"one of {sorted(ALLOWED_OVERRIDES)}")


def containment_violations(config: Mapping[str, object]) -> list[str]:
    """Return every containment rule a resolved ``docker compose config`` document breaks.

    Pure and total: a missing or malformed section is itself a violation, never an exception.
    Each text names the network or service and the key, never a value, so no host path from
    the resolved config can reach a message or a report.
    """
    violations: list[str] = []
    networks = config.get("networks")
    if not isinstance(networks, Mapping):
        violations.append("networks: missing or not a mapping")
    else:
        for name, network in networks.items():
            if not isinstance(network, Mapping) or network.get("internal") is not True:
                violations.append(f"network {name}: internal is not true")
    services = config.get("services")
    if not isinstance(services, Mapping):
        violations.append("services: missing or not a mapping")
    else:
        for name, service in services.items():
            if not isinstance(service, Mapping):
                violations.append(f"service {name}: not a mapping")
            elif service.get("ports"):
                violations.append(f"service {name}: ports publishes a port to the host")
    return violations


def containment_sentence(files: Sequence[str]) -> str:
    """Describe the containment check the preflight ran over ``files`` (base file first)."""
    base, *overrides = files
    return (
        f"checked before the run with docker compose config over {base} plus each of "
        f"{len(overrides)} overrides: {', '.join(CONTAINMENT_RULES)}; no real hardware is "
        "reachable from the assessment"
    )


def make_runner(lab_dir: Path) -> Runner:
    """Return a ``Runner`` that runs each argv from ``lab_dir``, never through a shell."""

    def run(argv: Sequence[str], env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(argv),
            cwd=lab_dir,
            env=dict(env),
            capture_output=True,
            text=True,
            # Docker prints UTF-8; the platform default (cp1252 on Windows) would crash on it.
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    return run


def docker_available() -> bool:
    """Return True when a ``docker`` executable is on PATH."""
    return shutil.which("docker") is not None


def find_lab_dir(start: Path) -> Path | None:
    """Return the first of ``start`` and its parents holding the bundled compose files."""
    here = Path(start).resolve()
    for candidate in (here, *here.parents):
        if (candidate / COMPOSE_FILE).is_file() and (candidate / _TAP_FILE).is_file():
            return candidate
    return None


@dataclass(frozen=True)
class LabHandle:
    """A running lab scenario: read service logs, run compose subcommands, read captures."""

    base_cmd: tuple[str, ...]
    env: Mapping[str, str]
    runner: Runner
    sleep: Callable[[float], None]
    clock: Callable[[], float]

    def compose(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run an arbitrary ``docker compose`` subcommand against this stack (no exit check)."""
        return self.runner([*self.base_cmd, *args], self.env)

    def logs(self, service: str) -> str:
        """Return the accumulated stdout+stderr logs for ``service``."""
        result = self.compose("logs", "--no-color", service)
        if result.returncode != 0:
            raise LabError(_failure(f"logs {service}", result))
        return result.stdout + result.stderr

    def wait_for_log(self, service: str, needle: str, timeout: float = 120.0) -> bool:
        """Poll ``service`` logs once a second until ``needle`` appears or ``timeout`` elapses."""
        deadline = self.clock() + timeout
        while self.clock() < deadline:
            if needle in self.logs(service):
                return True
            self.sleep(1.0)
        return needle in self.logs(service)

    def read_capture(self, container_path: str) -> bytes:
        """Return the bytes of a file inside the attacker container (b"" when it is absent).

        ``container_path`` is a POSIX path string (pass ``Path.as_posix()``), so the argv is the
        same on every host OS.
        """
        result = self.compose(
            "exec", "-T", "attacker", "python", "-c", _READ_CAPTURE, container_path
        )
        if result.returncode != 0:
            raise LabError(_failure(f"exec attacker (read {container_path})", result))
        try:
            return base64.b64decode(result.stdout.strip(), validate=True)
        except ValueError as exc:
            raise LabError(
                f"reading {container_path} returned {len(result.stdout)} characters "
                "that are not valid base64"
            ) from exc


class LabSession:
    """Bring bundled lab scenarios up and down under one compose project."""

    def __init__(
        self,
        lab_dir: Path,
        *,
        project: str = DEFAULT_PROJECT,
        runner: Runner | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.lab_dir = Path(lab_dir).resolve()
        self.project = project
        self._runner = runner if runner is not None else make_runner(self.lab_dir)
        self._sleep = sleep
        self._clock = clock

    def _base_cmd(self, overrides: Sequence[str]) -> list[str]:
        files = ["-f", str(self.lab_dir / COMPOSE_FILE)]
        for override in overrides:
            files += ["-f", str(self.lab_dir / override)]
        return ["docker", "compose", "-p", self.project, *files]

    def check_containment(self, overrides: Sequence[str]) -> list[str]:
        """Resolve the base file plus ``overrides`` and return its containment violations.

        Runs ``docker compose config --format json`` (the docker CLI, no container started)
        with the pinned topology. Fails closed: a non-zero exit or output that is not a JSON
        object is itself a violation. An empty list means every ``CONTAINMENT_RULES`` holds.
        """
        _check_overrides(overrides)
        argv = [*self._base_cmd(overrides), "config", "--format", "json"]
        result = self._runner(argv, _lab_env("cleartext"))
        if result.returncode != 0:
            return [_failure("config", result)]
        try:
            parsed = json.loads(result.stdout)
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict):
            return ["docker compose config did not print a JSON object"]
        return containment_violations(parsed)

    def reset(self) -> None:
        """Run ``down -v`` once for the project to clear leftovers of an interrupted run."""
        self._runner([*self._base_cmd(()), "down", "-v"], _lab_env(None))

    @contextmanager
    def scenario(self, profile: str, overrides: Sequence[str] = ()) -> Iterator[LabHandle]:
        """Bring ``profile`` up with ``overrides``, yield a handle, always tear it down."""
        if isinstance(overrides, str):
            raise TypeError("overrides must be a sequence of file names, not a single string")
        if profile not in LAB_PROFILES:
            raise ValueError(f"unknown lab profile {profile!r}; expected one of "
                             f"{sorted(LAB_PROFILES)}")
        _check_overrides(overrides)

        base_cmd = self._base_cmd(overrides)
        env = _lab_env(profile)
        try:
            # --force-recreate is load-bearing for two-phase runs (downgrade: baseline then
            # attacked in one project). A second bring-up only swaps the attacker service;
            # without force-recreate the cp/pd containers keep running and the CP never
            # re-homes onto the new attacker, so its capture stays empty. Forcing recreation
            # restarts the whole stack, so each phase is a genuine fresh session through the
            # current attacker. Harmless for single bring-ups.
            proc = self._runner([*base_cmd, "up", "-d", "--build", "--force-recreate"], env)
            if proc.returncode != 0:
                raise LabError(_failure(f"up ({profile})", proc))
            yield LabHandle(
                base_cmd=tuple(base_cmd),
                env=env,
                runner=self._runner,
                sleep=self._sleep,
                clock=self._clock,
            )
        finally:
            self._runner([*base_cmd, "down", "-v"], env)
