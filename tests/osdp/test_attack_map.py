"""The ATT&CK map is the one source of every technique id the OSDP attacks cite (ASSESS-02).

Docker-free (no ``lab`` marker). Proves the map itself (version, keys, id shape, no
deprecated or redirecting id, one name per id, stdlib-only imports so it loads inside the
lab image) and that each attack module's constants and emitted Findings carry exactly the
mapped Enterprise (primary) and ICS (secondary) ids.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
import re
from pathlib import Path
from types import ModuleType

import pytest

from interlock import report
from interlock.osdp import attack_map, codec, constants, framer
from interlock.osdp import attacks as attacks_package
from interlock.osdp.attack_map import ACCESS_VECTOR, ATTACK_VERSION, MAPPINGS, technique_names
from interlock.osdp.attacks import downgrade, fuzz, keyset, replay, sniff, spoof, weak_key
from interlock.osdp.attacks import enumerate as enumerate_attack
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

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Which module constants consume which MAPPINGS key: (module, Enterprise constant, ICS constant).
_MODULE_CONSTANTS: dict[str, list[tuple[ModuleType, str, str]]] = {
    "sniff": [(sniff, "_TECHNIQUE", "_ICS_TECHNIQUE")],
    "enumerate": [(enumerate_attack, "_TECHNIQUE", "_ICS_TECHNIQUE")],
    "weak-key": [(weak_key, "_TECHNIQUE", "_ICS_TECHNIQUE")],
    "keyset": [(keyset, "_TECHNIQUE", "_ICS_TECHNIQUE")],
    "downgrade": [(downgrade, "_TECHNIQUE", "_ICS_TECHNIQUE")],
    "replay": [(replay, "_TECHNIQUE", "_ICS_TECHNIQUE")],
    "cve-2024-52288": [(replay, "_CVE_TECHNIQUE", "_CVE_ICS_TECHNIQUE")],
    "spoof": [(spoof, "_TECHNIQUE", "_ICS_TECHNIQUE")],
    "fuzz": [(fuzz, "_TECHNIQUE", "_ICS_TECHNIQUE")],
}


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


# --------------------------------------------------------------------------------------
# Module constants read from the map.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(_MODULE_CONSTANTS))
def test_module_constants_equal_the_map(key: str) -> None:
    for module, enterprise_name, ics_name in _MODULE_CONSTANTS[key]:
        assert getattr(module, enterprise_name, None) == MAPPINGS[key].enterprise, (
            f"{module.__name__}.{enterprise_name}"
        )
        assert getattr(module, ics_name, None) == MAPPINGS[key].ics, (
            f"{module.__name__}.{ics_name}"
        )


# --------------------------------------------------------------------------------------
# Passive attacks over the committed fixtures: Findings carry the mapped ids.
# --------------------------------------------------------------------------------------


def _load_session(profile: str) -> _Frames:
    """Frame and decode both per-direction vectors of ``profile`` into tagged pairs."""
    session: _Frames = []
    for direction, suffix in (
        (Direction.cp_to_pd, "cp2pd"),
        (Direction.pd_to_cp, "pd2cp"),
    ):
        raw = (FIXTURES_DIR / f"{profile}_{suffix}.cap").read_bytes()
        assert raw, f"{profile}_{suffix}.cap is empty; regenerate it from the lab"
        session.extend((direction, codec.decode(frame)) for frame in framer.iter_frames(raw))
    return session


def test_sniff_findings_carry_the_mapped_ids() -> None:
    findings = sniff.run_sniff(_load_session("cleartext"))
    assert findings
    for finding in findings:
        assert finding.attack_technique == "T1040"
        assert finding.attack_technique_ics == "T0842"
        _assert_complete(finding, "sniff")


def test_enumerate_finding_carries_the_mapped_ids() -> None:
    findings = enumerate_attack.run_enumerate(_load_session("cleartext"))
    matches = [f for f in findings if f.id == f"ATK-02-enumerate-pd-{_PD_ADDRESS}"]
    assert len(matches) == 1, findings
    assert matches[0].attack_technique == "T1018"
    assert matches[0].attack_technique_ics == "T0888"
    _assert_complete(matches[0], "enumerate")


def test_weak_key_finding_carries_the_mapped_ids() -> None:
    findings = weak_key.run_weak_key(_load_session("sc-scbkd"))
    assert [f.id for f in findings] == ["ATK-06-weak-key"]
    assert findings[0].attack_technique == "T1110.002"
    assert findings[0].attack_technique_ics == "T1694.001"
    _assert_complete(findings[0], "weak-key")


def test_keyset_finding_carries_the_mapped_ids() -> None:
    findings = keyset.run_keyset(_load_session("keyset"))
    assert [f.id for f in findings] == ["ATK-04-keyset"]
    assert findings[0].attack_technique == "T1040"
    assert findings[0].attack_technique_ics == "T0842"
    _assert_complete(findings[0], "keyset")


# --------------------------------------------------------------------------------------
# Active attacks driven by fakes: Findings carry the mapped ids.
# --------------------------------------------------------------------------------------


def _flipping_probe() -> tuple[list[bytes], replay.Inject, replay.LockStateProbe]:
    """Return (injected log, inject, probe): locked until the first injection, then unlocked."""
    injected: list[bytes] = []

    def inject(frame_bytes: bytes) -> None:
        injected.append(frame_bytes)

    return injected, inject, lambda: bool(injected)


def test_replay_finding_carries_the_replay_ids() -> None:
    _injected, inject, probe = _flipping_probe()
    findings = replay.run_replay([b"\x53\x01"], inject, probe)
    assert [f.id for f in findings] == ["ATK-05a-replay-card-exchange"]
    assert findings[0].attack_technique == "T1557"
    assert findings[0].attack_technique_ics == "T1692.002"
    _assert_complete(findings[0], "replay")


def test_cve_replay_finding_carries_the_cve_ids() -> None:
    _injected, inject, probe = _flipping_probe()
    findings = replay.run_cve_replay([b"\x53\x01"], inject, probe)
    assert [f.id for f in findings] == ["ATK-05b-cve-2024-52288-rmac-replay"]
    assert findings[0].attack_technique == "T1557"
    assert findings[0].attack_technique_ics == "T0830"
    _assert_complete(findings[0], "cve-2024-52288")


def test_replay_and_cve_replay_share_enterprise_but_not_ics() -> None:
    assert MAPPINGS["replay"].enterprise == MAPPINGS["cve-2024-52288"].enterprise == "T1557"
    assert MAPPINGS["replay"].ics != MAPPINGS["cve-2024-52288"].ics


def test_spoof_finding_carries_the_mapped_ids() -> None:
    state = {"unlocked": False}

    def inject() -> None:
        state["unlocked"] = True

    findings = spoof.run_spoof(inject, lambda: state["unlocked"])
    assert [f.id for f in findings] == ["ATK-08-spoof-unlock"]
    assert findings[0].attack_technique == "T1565.002"
    assert findings[0].attack_technique_ics == "T1692.001"
    _assert_complete(findings[0], "spoof")


def test_fuzz_finding_carries_the_mapped_ids() -> None:
    findings = fuzz.run_fuzz(fuzz.craft_poll(), lambda _frame: False, stop_on_failure=True)
    assert len(findings) == 1, findings
    assert findings[0].id.startswith("ATK-07-fuzz-")
    assert findings[0].attack_technique == "T1499.004"
    assert findings[0].attack_technique_ics == "T0814"
    _assert_complete(findings[0], "fuzz")


# --------------------------------------------------------------------------------------
# Coverage: every map key is consumed, and no attack module keeps an id of its own.
# --------------------------------------------------------------------------------------


def test_every_mapping_key_is_consumed_by_a_module_constant() -> None:
    assert set(_MODULE_CONSTANTS) == set(MAPPINGS)


def test_no_attack_module_holds_a_technique_constant_outside_the_map() -> None:
    """A technique constant that the table does not list (a new attack, a stray literal) fails."""
    listed = {
        (module.__name__, name)
        for entries in _MODULE_CONSTANTS.values()
        for module, enterprise_name, ics_name in entries
        for name in (enterprise_name, ics_name)
    }
    found: set[tuple[str, str]] = set()
    for info in pkgutil.iter_modules(attacks_package.__path__):
        module = importlib.import_module(f"{attacks_package.__name__}.{info.name}")
        for name in vars(module):
            if name.endswith("TECHNIQUE"):
                found.add((module.__name__, name))
    assert found == listed


_ICS_ID = re.compile(r"^T0\d{3}$")


def test_enterprise_ids_are_never_ics_ids() -> None:
    # Since v19 new ICS ids are T16xx (T0812 -> T1694.001), so an ICS id is not always T0xxx;
    # what must hold is that no legacy T0xxx id sits on the Enterprise side and that no ICS id
    # doubles as an Enterprise id of the map.
    enterprise_ids = {technique.enterprise for technique in MAPPINGS.values()}
    for key, technique in MAPPINGS.items():
        assert not _ICS_ID.match(technique.enterprise), f"{key}: {technique.enterprise} is ICS"
        if technique.ics is not None:
            assert technique.ics not in enterprise_ids, f"{key}: {technique.ics} is Enterprise"
