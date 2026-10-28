"""The published evidence stays honest and leak-free (D-14, D-16).

The README shows a terminal recording of ``interlock osdp assess`` and quotes the report of
the same run. The recording's source is a committed VHS tape, ``docs/media/assess.tape``, so
anyone can regenerate it from the repository root. These tests pin that the tape stays the
regenerable source of exactly that command, with its setup hidden, and that it never carries
the recorder's local identity: no absolute home path, no user name, no host name.
"""

from __future__ import annotations

import getpass
import re
import socket
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TAPE = REPO_ROOT / "docs" / "media" / "assess.tape"

_LOCAL_PATH_MARKERS = ("/Users/", "/home/", "C:\\", "~/")
# Shorter names (for example "ci" or "vm") match ordinary words and would make the check noise.
_MIN_IDENTITY_LEN = 4
_TYPE_LINE = re.compile(r'^Type "(.*)"$')


def _tape_lines() -> list[str]:
    assert TAPE.is_file(), f"{TAPE} is missing"
    return [line.strip() for line in TAPE.read_text(encoding="utf-8").splitlines()]


def _local_identities() -> list[str]:
    names = [getpass.getuser(), socket.gethostname().split(".", 1)[0]]
    return [name for name in names if len(name) >= _MIN_IDENTITY_LEN]


def _identity_leaks(text: str) -> list[str]:
    leaks = [marker for marker in _LOCAL_PATH_MARKERS if marker in text]
    for name in _local_identities():
        if re.search(rf"\b{re.escape(name)}\b", text, re.IGNORECASE):
            leaks.append(name)
    return leaks


def test_tape_is_the_regenerable_source() -> None:
    lines = _tape_lines()
    assert "Output docs/media/assess.gif" in lines
    assert "Require interlock" in lines

    first_type = next(i for i, line in enumerate(lines) if line.startswith("Type "))
    assert "Hide" in lines[:first_type], "the setup must be typed while capture is hidden"

    visible = True
    shown_after_setup = False
    visible_typed: list[str] = []
    for line in lines:
        if line == "Hide":
            visible = False
        elif line == "Show":
            visible = True
            shown_after_setup = True
        else:
            match = _TYPE_LINE.match(line)
            if match and visible:
                assert shown_after_setup, "a Show must come before the visible command"
                visible_typed.append(match.group(1))
    assert visible_typed == ["interlock osdp assess"]

    assert any(line.startswith("Wait+Screen") and "Wrote JSON report" in line for line in lines), (
        "the tape must wait for the run to finish"
    )


def test_tape_leaks_no_local_identity() -> None:
    leaks = _identity_leaks(TAPE.read_text(encoding="utf-8"))
    assert not leaks, f"the tape carries local identity: {leaks}"
