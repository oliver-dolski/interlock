"""The published evidence stays honest and leak-free (D-14, D-16).

The README shows a terminal recording of ``interlock osdp assess`` and quotes the report of
the same run. The recording's source is a committed VHS tape, ``docs/media/assess.tape``, so
anyone can regenerate it from the repository root. These tests pin that the tape stays the
regenerable source of exactly that command, with its setup hidden, and that it never carries
the recorder's local identity: no absolute home path, no user name, no host name.

The example reports in ``docs/examples`` are the unedited output of that recorded run. They
are pinned as a completed, post-fix run: every step finished with the healthy-lab verdict,
the authorized-use notice and the ATT&CK version are present, containment was checked, the
spoof and replay findings carry their severities, and the same identity rules apply. A
failing check here means a new recording, never an edit of the evidence.
"""

from __future__ import annotations

import getpass
import json
import re
import socket
from pathlib import Path
from typing import Any

from interlock import report

REPO_ROOT = Path(__file__).resolve().parents[1]
TAPE = REPO_ROOT / "docs" / "media" / "assess.tape"
RECORDING = REPO_ROOT / "docs" / "media" / "assess.gif"
EXAMPLE_MD = REPO_ROOT / "docs" / "examples" / "assessment.md"
EXAMPLE_JSON = REPO_ROOT / "docs" / "examples" / "assessment.json"
_MAX_RECORDING_BYTES = 8 * 1024 * 1024

# The verdicts of a healthy lab after D-17 (tests/lab/test_assess_end_to_end.py); anything
# else, inconclusive or error in particular, means the recorded run was not a clean one.
_HEALTHY_LAB_STATUSES = {
    "sniff-enumerate": "vulnerable",
    "fuzz": "not_vulnerable",
    "weak-key-keyset": "vulnerable",
    "downgrade": "vulnerable",
    "spoof": "vulnerable",
    "replay": "vulnerable",
    "cve-2024-52288-fixed": "not_vulnerable",
}

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


def _example_json() -> dict[str, Any]:
    assert EXAMPLE_JSON.is_file(), f"{EXAMPLE_JSON} is missing"
    data: dict[str, Any] = json.loads(EXAMPLE_JSON.read_text(encoding="utf-8"))
    return data


def _example_md() -> str:
    assert EXAMPLE_MD.is_file(), f"{EXAMPLE_MD} is missing"
    return EXAMPLE_MD.read_text(encoding="utf-8")


def test_example_report_is_a_completed_run() -> None:
    statuses = {step["key"]: step["status"] for step in _example_json()["steps"]}
    assert statuses == _HEALTHY_LAB_STATUSES


def test_example_report_carries_the_notice_and_framework() -> None:
    markdown = _example_md()
    assert markdown.startswith(f"# interlock OSDP assessment\n\n{report.AUTHORIZED_USE_NOTICE}\n")
    assert "MITRE ATT&CK v20.0" in markdown
    assert "**Containment:** checked before the run" in markdown

    data = _example_json()
    assert data["notice"] == report.AUTHORIZED_USE_NOTICE
    assert data["containment"]["checked"] is True


def test_example_report_severities() -> None:
    findings = _example_json()["findings"]
    severity = {finding["id"]: finding["severity"] for finding in findings}
    assert severity["ATK-08-spoof-unlock"] == "critical"
    assert severity["ATK-05a-replay-card-exchange"] == "high"
    for finding in findings:
        for field in ("severity", "evidence", "attack_technique", "remediation"):
            assert finding.get(field), f"{finding['id']} has no {field}"


def test_example_report_leaks_no_local_identity() -> None:
    for path in (EXAMPLE_MD, EXAMPLE_JSON):
        leaks = _identity_leaks(path.read_text(encoding="utf-8"))
        assert not leaks, f"{path.name} carries local identity: {leaks}"


def test_recording_is_a_gif_of_reasonable_size() -> None:
    assert RECORDING.is_file(), f"{RECORDING} is missing"
    data = RECORDING.read_bytes()
    assert data.startswith(b"GIF89a")
    assert len(data) < _MAX_RECORDING_BYTES
