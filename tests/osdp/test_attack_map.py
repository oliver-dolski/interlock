"""The ATT&CK map is the one source of every technique id the OSDP attacks cite (ASSESS-02).

Docker-free (no ``lab`` marker). Proves the map itself (version, keys, id shape, no
deprecated or redirecting id, one name per id, stdlib-only imports so it loads inside the
lab image) and that each attack module's constants and emitted Findings carry exactly the
mapped Enterprise (primary) and ICS (secondary) ids.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from interlock import report
from interlock.osdp import attack_map, constants
from interlock.osdp.attack_map import ACCESS_VECTOR, ATTACK_VERSION, MAPPINGS, technique_names
from interlock.osdp.attacks import downgrade
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.transport import Direction
from interlock.plugin import Finding, Severity

_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# Ids that ATT&CK v19 deprecated or turned into redirects: T1562.010 -> T1689 (Enterprise),
# T0812 -> T1694.001, T0855 -> T1692.001, T0856 -> T1692.002 (ICS).
_DEPRECATED = {"T1562.010", "T0812", "T0855", "T0856"}

_ATTACK_KEYS = {
    "sniff",
    "enumerate",
    "weak-key",
    "keyset",
    "downgrade",
    "replay",
    "cve-2024-52288",
    "spoof",
    "fuzz",
}

_STDLIB_ROOTS = {"__future__", "dataclasses", "typing", "collections"}
_STDLIB_MODULES = {"__future__", "dataclasses", "typing", "collections.abc"}

# Lab PD address under every profile (lab/osdp/pd_driver.py).
_PD_ADDRESS = 101


def _all_ids() -> list[str]:
    ids: list[str] = []
    for technique in (*MAPPINGS.values(), ACCESS_VECTOR):
        ids.append(technique.enterprise)
        if technique.ics is not None:
            ids.append(technique.ics)
    return ids


def _assert_complete(finding: Finding, key: str) -> None:
    """A finding carries every report field and exactly the mapped ids for ``key``."""
    assert finding.title
    assert finding.evidence
    assert finding.remediation
    assert isinstance(finding.severity, Severity)
    assert _ID_PATTERN.match(finding.attack_technique), finding.attack_technique
    assert finding.attack_technique == MAPPINGS[key].enterprise
    assert finding.attack_technique_ics == MAPPINGS[key].ics


# --------------------------------------------------------------------------------------
# The map itself.
# --------------------------------------------------------------------------------------


def test_attack_version_is_pinned_to_v20() -> None:
    assert ATTACK_VERSION == "20.0"


def test_mappings_hold_exactly_the_nine_attack_keys() -> None:
    assert set(MAPPINGS) == _ATTACK_KEYS


def test_every_id_has_the_attack_id_shape() -> None:
    for technique_id in _all_ids():
        assert _ID_PATTERN.match(technique_id), technique_id


def test_every_mapping_has_an_enterprise_primary_and_paired_ics_fields() -> None:
    for key, technique in MAPPINGS.items():
        assert technique.enterprise and technique.enterprise_name, key
        assert (technique.ics is None) == (technique.ics_name is None), key


def test_access_vector_is_hardware_additions_without_ics() -> None:
    assert ACCESS_VECTOR.enterprise == "T1200"
    assert ACCESS_VECTOR.enterprise_name == "Hardware Additions"
    assert ACCESS_VECTOR.ics is None
    assert ACCESS_VECTOR.ics_name is None


def test_no_deprecated_or_redirecting_id_is_used() -> None:
    assert _DEPRECATED.isdisjoint(_all_ids())


def test_technique_names_gives_each_id_one_consistent_name() -> None:
    names = technique_names()
    for technique in (*MAPPINGS.values(), ACCESS_VECTOR):
        assert names[technique.enterprise] == technique.enterprise_name
        if technique.ics is not None:
            assert names[technique.ics] == technique.ics_name
    assert set(names) == set(_all_ids())


def test_attack_map_imports_only_the_standard_library() -> None:
    """The map loads inside the minimal lab image, so nothing outside the stdlib."""
    assert attack_map.__file__ is not None
    tree = ast.parse(Path(attack_map.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name in _STDLIB_MODULES, alias.name
                assert alias.name.split(".")[0] in _STDLIB_ROOTS, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import in attack_map"
            assert node.module in _STDLIB_MODULES, node.module


# --------------------------------------------------------------------------------------
# ATK-03 downgrade, end to end: map -> module constant -> Finding -> Markdown.
# --------------------------------------------------------------------------------------


_Frames = list[tuple[Direction, OsdpFrame]]


def _downgrade_pair() -> tuple[_Frames, _Frames]:
    """Return a secure baseline (advertising 0x09) and a clear-text attacked session."""
    secure = OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=constants.PKT_CONTROL_CRC | constants.PKT_CONTROL_SCB,
        scb=bytes([0x03, constants.SCS_16, 0x00]),
        code=constants.REPLY_CCRYPT,
        data=b"",
        use_crc=True,
    )
    pdcap = OsdpFrame(
        had_mark=True,
        address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG,
        control=constants.PKT_CONTROL_CRC | 0x01,
        scb=b"",
        code=constants.REPLY_PDCAP,
        data=bytes([0x02, 1, 1, 0x04, 2, 1, 0x05, 1, 1, 0x06, 1, 1, 0x09, 1, 1]),
        use_crc=True,
    )
    poll = OsdpFrame(
        had_mark=True, address=_PD_ADDRESS, control=0x05, scb=b"", code=constants.CMD_POLL,
        data=b"", use_crc=True,
    )
    ack = OsdpFrame(
        had_mark=True, address=_PD_ADDRESS | constants.ADDR_REPLY_FLAG, control=0x05, scb=b"",
        code=constants.REPLY_ACK, data=b"", use_crc=True,
    )
    baseline = [(Direction.pd_to_cp, secure), (Direction.pd_to_cp, pdcap)]
    attacked = [(Direction.cp_to_pd, poll), (Direction.pd_to_cp, ack)]
    return baseline, attacked


def test_downgrade_constants_come_from_the_map() -> None:
    assert downgrade._TECHNIQUE == "T1689"
    assert downgrade._TECHNIQUE == MAPPINGS["downgrade"].enterprise
    assert downgrade._ICS_TECHNIQUE == MAPPINGS["downgrade"].ics == "T0830"


def test_downgrade_finding_carries_the_mapped_ids() -> None:
    baseline, attacked = _downgrade_pair()
    findings = downgrade.run_downgrade(baseline, attacked)
    assert len(findings) == 1, findings
    assert findings[0].attack_technique == "T1689"
    assert findings[0].attack_technique_ics == "T0830"
    _assert_complete(findings[0], "downgrade")


def test_downgrade_finding_renders_technique_names_in_markdown(tmp_path) -> None:
    baseline, attacked = _downgrade_pair()
    findings = downgrade.run_downgrade(baseline, attacked)
    report_path = tmp_path / "report.md"

    report.write_markdown(findings, report_path, technique_names=technique_names())

    text = report_path.read_text(encoding="utf-8")
    assert "T1689 (Downgrade Attack)" in text
    assert "T0830 (Adversary-in-the-Middle)" in text
