"""SAFE-01 containment gate: no published host ports, no egress, clean restart (SC4)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from conftest import ComposeUp

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

# Attempt to reach a public address from inside the lab. On the internal network
# there is no gateway, so the connection must fail; a success means egress leaked.
EGRESS_PROBE = (
    "import socket\n"
    "socket.setdefaulttimeout(3)\n"
    "try:\n"
    "    socket.create_connection(('1.1.1.1', 53))\n"
    "    print('LEAK')\n"
    "except OSError:\n"
    "    print('ISOLATED')\n"
)


def _rendered_config() -> dict:
    """Return the fully rendered compose config as parsed JSON."""
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def _assert_no_published_ports(config: dict) -> None:
    """Fail if any service declares a ``ports:`` mapping."""
    for name, service in config.get("services", {}).items():
        assert not service.get("ports"), f"service {name} publishes host ports"


def _ps_service_states(raw: str) -> dict[str, str]:
    """Parse ``docker compose ps --format json`` (array or JSON-lines) to service->state."""
    raw = raw.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        rows = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    return {row["Service"]: row.get("State", row.get("Status", "")) for row in rows}


@pytest.mark.lab
def test_network_internal_and_no_published_ports() -> None:
    config = _rendered_config()
    labnet = config.get("networks", {}).get("labnet", {})
    assert labnet.get("internal") is True
    _assert_no_published_ports(config)


@pytest.mark.lab
def test_no_egress_from_pd(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext")
    result = lab.compose("exec", "-T", "pd", "python", "-c", EGRESS_PROBE)
    output = result.stdout + result.stderr
    assert "ISOLATED" in output, f"egress probe did not report ISOLATED: {output!r}"
    assert "LEAK" not in output


@pytest.mark.lab
def test_clean_restart_stays_isolated(compose_up: ComposeUp) -> None:
    lab = compose_up("cleartext")
    assert lab.compose("down", "-v").returncode == 0
    assert lab.compose("up", "-d").returncode == 0

    ps = lab.compose("ps", "--format", "json")
    assert ps.returncode == 0
    states = _ps_service_states(ps.stdout)
    assert {"pd", "cp"} <= set(states), f"services missing after restart: {states}"
    for service, state in states.items():
        assert state == "running", f"{service} not running after restart: {state}"

    _assert_no_published_ports(_rendered_config())
