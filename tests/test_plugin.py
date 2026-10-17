"""Unit coverage for the findings model and the plugin contract (CORE-03)."""

from __future__ import annotations

import dataclasses

import pytest

from interlock.plugin import Finding, Plugin, Severity
from interlock.plugins.demo import DemoPlugin


def test_finding_is_frozen() -> None:
    finding = Finding(
        id="X-1",
        title="t",
        severity=Severity.INFO,
        evidence="e",
        attack_technique="T0000",
        remediation="r",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.title = "changed"  # type: ignore[misc]


def test_severity_members_have_lowercase_values() -> None:
    assert Severity.INFO.value == "info"
    assert Severity.LOW.value == "low"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.HIGH.value == "high"
    assert Severity.CRITICAL.value == "critical"


def test_demo_plugin_satisfies_plugin_protocol() -> None:
    assert isinstance(DemoPlugin(), Plugin)
