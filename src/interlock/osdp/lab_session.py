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

The runner, sleep and clock are injectable, so the host suite proves every path without Docker.
"""

from __future__ import annotations

import base64
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


def make_runner(lab_dir: Path) -> Runner:
    """Return a ``Runner`` that runs each argv from ``lab_dir``, never through a shell."""

    def run(argv: Sequence[str], env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(argv),
            cwd=lab_dir,
            env=dict(env),
            capture_output=True,
            text=True,
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

    def reset(self) -> None:
        """Run ``down -v`` once for the project to clear leftovers of an interrupted run."""
        self._runner([*self._base_cmd(()), "down", "-v"], dict(os.environ))

    @contextmanager
    def scenario(self, profile: str, overrides: Sequence[str] = ()) -> Iterator[LabHandle]:
        """Bring ``profile`` up with ``overrides``, yield a handle, always tear it down."""
        if isinstance(overrides, str):
            raise TypeError("overrides must be a sequence of file names, not a single string")
        if profile not in LAB_PROFILES:
            raise ValueError(f"unknown lab profile {profile!r}; expected one of "
                             f"{sorted(LAB_PROFILES)}")
        for override in overrides:
            if override not in ALLOWED_OVERRIDES:
                raise ValueError(f"compose override {override!r} is not allowed; expected "
                                 f"one of {sorted(ALLOWED_OVERRIDES)}")

        base_cmd = self._base_cmd(overrides)
        env = {**os.environ, "LAB_SCENARIO": profile}
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
