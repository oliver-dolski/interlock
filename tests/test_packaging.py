"""PUB-01 packaging contract: metadata, licence, attribution and the text rules the dists carry.

The package is built for PyPI but never uploaded from here. These tests hold the metadata,
the Apache-2.0 licence shared by the series and the MITRE ATT&CK attribution to fixed values,
so a later edit cannot quietly drop a field a reader of the package page relies on.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import shutil
import subprocess
import tarfile
import tomllib
import zipfile
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


# The sdist allow-list, as probed against hatchling: everything a source user needs, nothing else.
_PROBED_ONLY_INCLUDE = [
    "src/interlock",
    "tests",
    "lab",
    "docs",
    "Dockerfile",
    "Dockerfile.vuln",
    "lab.sh",
    "docker-compose.yml",
    "docker-compose.tap.yml",
    "docker-compose.fuzz.yml",
    "docker-compose.downgrade.yml",
    "docker-compose.spoof.yml",
    "docker-compose.replay.yml",
    "docker-compose.cve.yml",
    "docker-compose.vuln.yml",
    "docker-compose.lockstate.yml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "pyproject.toml",
]

_VERSION = "0.1.0"
_SDIST_ROOT = f"interlock-{_VERSION}"
_DIST_INFO = f"interlock-{_VERSION}.dist-info"
_CLEAN_SDIST = [
    "src/interlock/__init__.py",
    "tests/test_packaging.py",
    "lab/osdp/scenarios.py",
    "docs/plugin-authoring.md",
    "Dockerfile",
    "lab.sh",
    "docker-compose.yml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "pyproject.toml",
    "PKG-INFO",
    ".gitignore",
]
_CLEAN_WHEEL = [
    "interlock/__init__.py",
    f"{_DIST_INFO}/METADATA",
    f"{_DIST_INFO}/RECORD",
    f"{_DIST_INFO}/licenses/LICENSE",
    f"{_DIST_INFO}/licenses/NOTICE",
]


def _sdist_table() -> dict[str, Any]:
    table: dict[str, Any] = _project()["tool"]["hatch"]["build"]["targets"]["sdist"]
    return table


def _check_dist() -> Any:
    path = REPO_ROOT / "scripts" / "check_dist.py"
    spec = importlib.util.spec_from_file_location("check_dist", path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_sdist(path: Path, members: list[str]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for member in members:
            info = tarfile.TarInfo(f"{_SDIST_ROOT}/{member}")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))


def _write_wheel(path: Path, members: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for member in members:
            archive.writestr(member, b"x")


def _dist_dir(
    tmp_path: Path,
    sdist: list[str] | None = None,
    wheel: list[str] | None = None,
) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_sdist(dist / f"{_SDIST_ROOT}.tar.gz", _CLEAN_SDIST if sdist is None else sdist)
    whl = dist / f"interlock-{_VERSION}-py3-none-any.whl"
    _write_wheel(whl, _CLEAN_WHEEL if wheel is None else wheel)
    return dist


def test_sdist_only_includes_the_probed_allow_list() -> None:
    table = _sdist_table()
    assert table["only-include"] == _PROBED_ONLY_INCLUDE
    assert "docs/media" in table["exclude"]


def test_gate_allow_list_mirrors_only_include() -> None:
    expected = set(_sdist_table()["only-include"]) | {"PKG-INFO", ".gitignore"}
    assert set(_check_dist().ALLOWED_SDIST_ROOTS) == expected


def test_gate_passes_a_clean_dist_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _gate_on_this_checkout().main([str(_dist_dir(tmp_path))]) == 0
    assert "check_dist: ok" in capsys.readouterr().out


def test_gate_rejects_an_extra_sdist_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist = _dist_dir(tmp_path, sdist=[*_CLEAN_SDIST, "notes.md"])
    assert _gate_on_this_checkout().main([str(dist)]) == 1
    captured = capsys.readouterr()
    assert "notes.md" in captured.out + captured.err
    assert "check_dist: ok" not in captured.out


def test_gate_rejects_docs_media(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dist = _dist_dir(tmp_path, sdist=[*_CLEAN_SDIST, "docs/media/demo.gif"])
    assert _gate_on_this_checkout().main([str(dist)]) == 1
    captured = capsys.readouterr()
    assert "docs/media/demo.gif" in captured.out + captured.err


# A file the tree hides only through an ignore or exclude list, which the build does not read,
# can sit at any depth under a root the sdist carries (WR-03). The gate names none of them: it
# refuses every member git does not track, and every dotfile, __pycache__ dir and bytecode
# file by its shape, tracked or not.
_TRACKED_CLEAN = frozenset(
    {member for member in _CLEAN_SDIST if member != "PKG-INFO"}
    | {f"src/{member}" for member in _CLEAN_WHEEL if member.startswith("interlock/")}
)


def _gate(monkeypatch: pytest.MonkeyPatch, tracked: frozenset[str] | None) -> Any:
    """Return the gate module with ``tracked`` standing in for ``git ls-files``."""
    gate = _check_dist()
    monkeypatch.setattr(gate, "tracked_files", lambda repo: tracked)
    return gate


def _gate_on_this_checkout() -> Any:
    """Return the gate module as CI runs it, reading this checkout's tracked files through git."""
    git = shutil.which("git")
    if git is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("git or the repository is unavailable")
    return _check_dist()


@pytest.mark.parametrize(
    "member",
    ["tests/NOTES.md", "docs/examples/notes/plan.md", "lab/osdp/STATE.md", "src/interlock/x.py"],
)
def test_gate_rejects_an_sdist_member_git_does_not_track(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], member: str
) -> None:
    dist = _dist_dir(tmp_path, sdist=[*_CLEAN_SDIST, member])
    assert _gate(monkeypatch, _TRACKED_CLEAN).main([str(dist)]) == 1
    captured = capsys.readouterr()
    assert member in captured.err
    assert "check_dist: ok" not in captured.out


@pytest.mark.parametrize(
    "member",
    [
        "tests/.tool/settings.json",
        "lab/.state/STATE.md",
        "docs/examples/x/__pycache__/a.cpython-311.pyc",
        "src/interlock/stale.pyc",
        "src/interlock/stale.pyo",
        "src/interlock/.idea/workspace.xml",
        "docs/.notes",
        "tests/.gitignore",
    ],
)
def test_gate_rejects_dotfiles_and_bytecode_in_the_sdist_even_when_tracked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], member: str
) -> None:
    dist = _dist_dir(tmp_path, sdist=[*_CLEAN_SDIST, member])
    assert _gate(monkeypatch, _TRACKED_CLEAN | {member}).main([str(dist)]) == 1
    captured = capsys.readouterr()
    assert member in captured.err
    assert "check_dist: ok" not in captured.out


@pytest.mark.parametrize(
    "member",
    [
        "interlock/NOTES.md",
        "interlock/.tool/settings.json",
        "interlock/__pycache__/cli.cpython-311.pyc",
        "interlock/stale.pyc",
    ],
)
def test_gate_rejects_an_untracked_or_generated_file_in_the_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], member: str
) -> None:
    dist = _dist_dir(tmp_path, wheel=[*_CLEAN_WHEEL, member])
    # Tracked or not, a dotfile or bytecode fails by shape; NOTES.md fails as untracked.
    tracked = _TRACKED_CLEAN | ({f"src/{member}"} if member != "interlock/NOTES.md" else set())
    assert _gate(monkeypatch, tracked).main([str(dist)]) == 1
    assert member in capsys.readouterr().err


def test_gate_passes_a_clean_dist_whose_members_git_tracks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _gate(monkeypatch, _TRACKED_CLEAN).main([str(_dist_dir(tmp_path))]) == 0
    assert "check_dist: ok" in capsys.readouterr().out


def test_gate_fails_closed_when_git_cannot_list_tracked_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _gate(monkeypatch, None).main([str(_dist_dir(tmp_path))]) == 1
    captured = capsys.readouterr()
    assert "tracked" in captured.err
    assert "check_dist: ok" not in captured.out


def test_gate_reads_the_tracked_files_of_this_checkout() -> None:
    tracked = _gate_on_this_checkout().tracked_files(REPO_ROOT)
    assert tracked is not None
    assert {"pyproject.toml", "scripts/check_dist.py", "src/interlock/__init__.py"} <= tracked


def test_build_excludes_dotfiles_and_bytecode_from_both_archives() -> None:
    targets = _project()["tool"]["hatch"]["build"]["targets"]
    expected = {"__pycache__", "*.pyc", "*.pyo", ".*"}
    for target in ("sdist", "wheel"):
        assert expected <= set(targets[target].get("exclude", [])), target


def test_gate_requires_notice_at_the_sdist_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist = _dist_dir(tmp_path, sdist=[m for m in _CLEAN_SDIST if m != "NOTICE"])
    assert _gate_on_this_checkout().main([str(dist)]) == 1
    captured = capsys.readouterr()
    assert "NOTICE" in captured.out + captured.err


def test_gate_rejects_a_wheel_member_outside_the_package(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist = _dist_dir(tmp_path, wheel=[*_CLEAN_WHEEL, "lab/osdp/scenarios.py"])
    assert _gate_on_this_checkout().main([str(dist)]) == 1
    captured = capsys.readouterr()
    assert "lab/osdp/scenarios.py" in captured.out + captured.err


def test_gate_requires_licence_files_in_the_wheel(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = [m for m in _CLEAN_WHEEL if not m.endswith("/licenses/NOTICE")]
    assert _gate_on_this_checkout().main([str(_dist_dir(tmp_path, wheel=wheel))]) == 1
    captured = capsys.readouterr()
    assert "licenses/NOTICE" in captured.out + captured.err


@pytest.mark.parametrize("count", [0, 2])
def test_gate_requires_exactly_one_sdist(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], count: int
) -> None:
    dist = _dist_dir(tmp_path)
    if count == 0:
        (dist / f"{_SDIST_ROOT}.tar.gz").unlink()
    else:
        _write_sdist(dist / "interlock-0.2.0.tar.gz", _CLEAN_SDIST)
    assert _check_dist().main([str(dist)]) == 1
    captured = capsys.readouterr()
    assert "exactly one sdist" in captured.out + captured.err
