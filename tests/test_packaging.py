"""PUB-01 packaging contract: metadata, licence, attribution and the text rules the dists carry.

The package is built for PyPI but never uploaded from here. These tests hold the metadata,
the Apache-2.0 licence shared by the series and the MITRE ATT&CK attribution to fixed values,
so a later edit cannot quietly drop a field a reader of the package page relies on.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest

from interlock.osdp import attack_map

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
LICENSE = REPO_ROOT / "LICENSE"
NOTICE = REPO_ROOT / "NOTICE"

# SHA-256 of the Apache-2.0 LICENSE shared by wayside, substation and rail-breach (LF endings).
SERIES_LICENSE_SHA256 = "69e3b0d972e8e64d43b432a14610fe76dab871bebdaf4f32b9d90fcd34f3b8c8"

# Built from code points so this file never holds the characters it forbids.
_LONG_DASHES = (chr(0x2014), chr(0x2013))

# The commit-msg hook is the guard that rejects long dashes, so it has to spell them.
_LONG_DASH_EXEMPT = frozenset({".githooks/commit-msg"})


def _project() -> dict[str, Any]:
    with PYPROJECT.open("rb") as handle:
        data: dict[str, Any] = tomllib.load(handle)
    return data


def test_version_stays_0_1_0() -> None:
    assert _project()["project"]["version"] == "0.1.0"


def test_license_is_an_spdx_expression_without_a_trove_classifier() -> None:
    project = _project()["project"]
    assert project["license"] == "Apache-2.0"
    licence_classifiers = [c for c in project["classifiers"] if c.startswith("License ::")]
    assert not licence_classifiers, licence_classifiers


def test_metadata_fields_for_the_package_page() -> None:
    project = _project()["project"]
    assert project["readme"] == "README.md"
    assert project["authors"] == [{"name": "Oliver Dolski", "email": "oliver.dolski1@gmail.com"}]
    assert "osdp" in project["keywords"]
    assert "Topic :: Security" in project["classifiers"]
    assert set(project["urls"]) == {"Homepage", "Source", "Issues", "Documentation"}


def test_wheel_ships_only_the_interlock_package() -> None:
    wheel = _project()["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["packages"] == ["src/interlock"]


def test_license_is_the_series_apache_text() -> None:
    data = LICENSE.read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(data).hexdigest() == SERIES_LICENSE_SHA256


def test_notice_carries_copyright_and_mitre_attribution() -> None:
    text = NOTICE.read_text(encoding="utf-8")
    required = [
        "Copyright 2026 Oliver Dolski",
        f"version {attack_map.ATTACK_VERSION}",
        "src/interlock/osdp/attack_map.py",
        (
            "© 2026 The MITRE Corporation. This work is reproduced and distributed with the "
            "permission of The MITRE Corporation."
        ),
        "The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license",
        "MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.",
        "Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        "not affiliated with The MITRE Corporation",
        "osdp-dev/libosdp",
        "Neither is vendored",
    ]
    missing = [line for line in required if line not in text]
    assert not missing, missing
    assert text.endswith("\n")


def _tracked_text_files() -> list[Path]:
    git = shutil.which("git")
    if git is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("git or the repository is unavailable")
    listed = subprocess.run(
        [git, "-C", str(REPO_ROOT), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.decode()
    paths = [REPO_ROOT / name for name in listed.split("\0") if name]
    return [p for p in paths if p.is_file() and b"\0" not in p.read_bytes()]


def test_tracked_text_files_have_no_long_dash() -> None:
    files = _tracked_text_files()
    assert any(path.name == "README.md" for path in files), "scan found no text files"
    offenders = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{number}"
        for path in files
        if path.relative_to(REPO_ROOT).as_posix() not in _LONG_DASH_EXEMPT
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        )
        if any(dash in line for dash in _LONG_DASHES)
    ]
    assert not offenders, "long dash in a tracked file:\n" + "\n".join(offenders)
