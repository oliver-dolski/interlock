"""Gate what the interlock distributions may contain, before CI passes them or anyone uploads.

The sdist is built from a working tree, and a working tree can hold files that must never be
published. The build is told what to include (pyproject `only-include`); this gate checks the
archives it actually produced against the same allow-list. It never lists what to keep out:
anything not named here fails.

Usage: python scripts/check_dist.py [DIST_DIR]   (default: dist)
Exit 0 and "check_dist: ok" when both archives pass, 1 with every offending path otherwise.
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

# Mirrors [tool.hatch.build.targets.sdist] only-include in pyproject.toml, plus the two files
# hatchling adds on its own: the generated PKG-INFO and the .gitignore it read.
ALLOWED_SDIST_ROOTS = frozenset(
    {
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
        "PKG-INFO",
        ".gitignore",
    }
)

# Excluded from the docs root: recordings for the repository page, not for the archive.
EXCLUDED_SDIST_PREFIXES = ("docs/media/",)

LICENCE_FILES = ("LICENSE", "NOTICE")


def _single(dist: Path, pattern: str, kind: str, problems: list[str]) -> Path | None:
    found = sorted(dist.glob(pattern))
    if len(found) != 1:
        names = ", ".join(p.name for p in found) or "none"
        problems.append(f"expected exactly one {kind} ({pattern}) in {dist}, found: {names}")
        return None
    return found[0]


def _allowed_in_sdist(rel: str, is_dir: bool) -> bool:
    if rel.startswith(EXCLUDED_SDIST_PREFIXES) or rel + "/" in EXCLUDED_SDIST_PREFIXES:
        return False
    for root in ALLOWED_SDIST_ROOTS:
        if rel == root or rel.startswith(root + "/"):
            return True
        if is_dir and root.startswith(rel + "/"):
            return True
    return False


def check_sdist(sdist: Path) -> list[str]:
    """Return every sdist member outside the allow-list, and any missing licence file."""
    prefix = sdist.name.removesuffix(".tar.gz") + "/"
    problems: list[str] = []
    present: set[str] = set()
    with tarfile.open(sdist, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name
            if name == prefix.rstrip("/"):
                continue
            if not name.startswith(prefix):
                problems.append(f"sdist path outside {prefix}: {name}")
                continue
            rel = name.removeprefix(prefix).rstrip("/")
            present.add(rel)
            if not _allowed_in_sdist(rel, member.isdir()):
                problems.append(f"sdist path not allowed: {rel}")
    problems.extend(
        f"sdist lacks {name} at its root" for name in LICENCE_FILES if name not in present
    )
    return problems


def check_wheel(wheel: Path) -> list[str]:
    """Return every wheel member outside the package and its dist-info, and missing licences."""
    name, version = wheel.name.split("-")[:2]
    dist_info = f"{name}-{version}.dist-info/"
    allowed = (f"{name}/", dist_info)
    with zipfile.ZipFile(wheel) as archive:
        members = archive.namelist()
    problems = [f"wheel path not allowed: {m}" for m in members if not m.startswith(allowed)]
    problems.extend(
        f"wheel lacks {dist_info}licenses/{licence}"
        for licence in LICENCE_FILES
        if f"{dist_info}licenses/{licence}" not in members
    )
    return problems


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    dist = Path(args[0] if args else "dist")
    if not dist.is_dir():
        print(f"check_dist: {dist} is not a directory", file=sys.stderr)
        return 1
    problems: list[str] = []
    sdist = _single(dist, "interlock-*.tar.gz", "sdist", problems)
    wheel = _single(dist, "interlock-*.whl", "wheel", problems)
    if sdist is not None:
        problems.extend(check_sdist(sdist))
    if wheel is not None:
        problems.extend(check_wheel(wheel))
    if problems:
        for problem in problems:
            print(f"check_dist: {problem}", file=sys.stderr)
        return 1
    print("check_dist: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
