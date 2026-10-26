"""Unit coverage for the findings model and the plugin contract (CORE-03)."""

from __future__ import annotations

import dataclasses

import pytest

from interlock.plugin import Finding, Plugin, Severity, finding_from_dict, finding_to_dict
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


def _ics_finding() -> Finding:
    return Finding(
        id="X-2",
        title="t",
        severity=Severity.HIGH,
        evidence="e",
        attack_technique="T1689",
        remediation="r",
        attack_technique_ics="T0830",
    )


def test_finding_without_ics_id_defaults_to_none() -> None:
    finding = Finding(
        id="X-1",
        title="t",
        severity=Severity.INFO,
        evidence="e",
        attack_technique="T0000",
        remediation="r",
    )
    assert finding.attack_technique_ics is None
    assert DemoPlugin().run()[0].attack_technique_ics is None


@pytest.mark.parametrize("finding", [DemoPlugin().run()[0], _ics_finding()])
def test_finding_dict_round_trip(finding: Finding) -> None:
    assert finding_from_dict(finding_to_dict(finding)) == finding


def test_finding_to_dict_has_exactly_the_contract_keys() -> None:
    assert set(finding_to_dict(_ics_finding())) == {
        "id",
        "title",
        "severity",
        "evidence",
        "attack_technique",
        "attack_technique_ics",
        "remediation",
    }
    assert finding_to_dict(_ics_finding())["severity"] == "high"


def _mutated(**changes: object) -> dict[str, object]:
    data = finding_to_dict(_ics_finding())
    data.update(changes)
    return data


def test_finding_from_dict_rejects_unknown_severity() -> None:
    with pytest.raises(ValueError, match="severity"):
        finding_from_dict(_mutated(severity="urgent"))


def test_finding_from_dict_rejects_non_str_field() -> None:
    with pytest.raises(ValueError, match="evidence"):
        finding_from_dict(_mutated(evidence=5))


def test_finding_from_dict_rejects_missing_key() -> None:
    data = finding_to_dict(_ics_finding())
    del data["remediation"]
    with pytest.raises(ValueError, match="remediation"):
        finding_from_dict(data)


def test_finding_from_dict_rejects_extra_key() -> None:
    with pytest.raises(ValueError, match="extra"):
        finding_from_dict(_mutated(extra="x"))


def test_finding_from_dict_rejects_non_str_ics_id() -> None:
    with pytest.raises(ValueError, match="attack_technique_ics"):
        finding_from_dict(_mutated(attack_technique_ics=830))
