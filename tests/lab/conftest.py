"""Pytest fixtures for the Docker-backed OSDP lab integration tests.

The ``compose_up`` fixture brings the lab up with ``docker compose`` under a
fixed project name, yields a handle for reading service logs, and guarantees
``docker compose down -v`` teardown even when a test fails.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
PROJECT_NAME = "interlock-lab"


@dataclass
class ComposeHandle:
    """Handle to a running lab stack for reading logs within a test."""

    base_cmd: list[str]
    env: dict[str, str]

    def logs(self, service: str) -> str:
        """Return the accumulated stdout+stderr logs for ``service``."""
        result = subprocess.run(
            [*self.base_cmd, "logs", "--no-color", service],
            cwd=REPO_ROOT,
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout + result.stderr

    def wait_for_log(self, service: str, needle: str, timeout: float = 120.0) -> bool:
        """Poll ``service`` logs until ``needle`` appears or ``timeout`` elapses."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in self.logs(service):
                return True
            time.sleep(1.0)
        return needle in self.logs(service)


ComposeUp = Callable[..., ComposeHandle]


@pytest.fixture
def compose_up() -> Iterator[ComposeUp]:
    """Yield a factory that brings the lab up and tears it down after the test."""
    started: list[ComposeHandle] = []

    def _up(scenario: str, *, overrides: Sequence[str] = ()) -> ComposeHandle:
        files = ["-f", str(COMPOSE_FILE)]
        for override in overrides:
            files += ["-f", str(REPO_ROOT / override)]
        base_cmd = ["docker", "compose", "-p", PROJECT_NAME, *files]
        env = {**os.environ, "LAB_SCENARIO": scenario}
        proc = subprocess.run(
            [*base_cmd, "up", "-d", "--build"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"docker compose up failed ({proc.returncode}):\n"
                f"{proc.stdout}\n{proc.stderr}"
            )
        handle = ComposeHandle(base_cmd=base_cmd, env=env)
        started.append(handle)
        return handle

    try:
        yield _up
    finally:
        for handle in started:
            subprocess.run(
                [*handle.base_cmd, "down", "-v"],
                cwd=REPO_ROOT,
                env=handle.env,
                capture_output=True,
                text=True,
                check=False,
            )
