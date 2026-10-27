"""The OSDP assessment orchestrator behind ``interlock osdp assess`` (ASSESS-01).

An assessment is an ordered tuple of ``Step``s. Each step brings one bundled lab scenario up
through the 05-07 wrapper (``with session.scenario(profile, overrides) as lab:``), proves its
lab precondition from the lab's own log sentinels, runs the existing Phase 4 verdict functions over
live lab output and returns the findings. ``run_assessment`` runs every step in order and
records one ``StepResult`` per step with an explicit ``Status``:

- findings -> ``vulnerable``; no findings -> ``not_vulnerable`` (only after the step proved
  its precondition and ran to completion);
- ``Inconclusive`` raised by the step (an unmet precondition: PD never online, empty capture,
  a capture that decodes to no OSDP frame, a missing handshake half) -> ``inconclusive``,
  never a silent clean result;
- any other ``Exception`` -> ``error`` with ``"TypeName: message"``; the traceback goes to
  stderr only, never into a report. ``KeyboardInterrupt`` is not caught, so Ctrl-C unwinds
  through the scenario's ``finally`` and the lab is still torn down.

One failing step never loses the findings of the others. ``write_reports`` writes the Markdown
and the JSON report through ``interlock.report``, so both carry the authorized-use notice.

Lab-only by design (D-04): the only lab access is ``LabSession``; this module imports nothing
from the physical (SAFE-02) path and never reads committed test fixtures. Every finding comes
from a live capture or a live oracle.
"""

from __future__ import annotations

import enum
import json
import subprocess
import sys
import time
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from rich.console import Console
from rich.table import Table

import interlock
from interlock import report
from interlock.osdp import attack_map, constants, lab_session, secure_channel
from interlock.osdp.attacks import downgrade, replay, spoof
from interlock.osdp.attacks.enumerate import run_enumerate
from interlock.osdp.attacks.fuzz import LIBOSDP_REJECTION_MARKERS
from interlock.osdp.attacks.keyset import run_keyset
from interlock.osdp.attacks.sniff import decode_chunks, run_sniff
from interlock.osdp.attacks.weak_key import run_weak_key
from interlock.osdp.codec import OsdpFrame
from interlock.osdp.lab_session import LabError, LabSession
from interlock.osdp.tap_capture import CP2PD_PATH, PD2CP_PATH
from interlock.osdp.transport import Direction
from interlock.plugin import Finding, Severity, finding_from_dict

_console = Console()

# cp log sentinels printed by the lab drivers (lab/osdp), with the waits the @lab suite uses.
PD_ONLINE = "interlock-lab: PD 101 online"
EVENT_RECEIVED = "interlock-lab: event received"
_PD_ONLINE_TIMEOUT = 180.0
_EVENT_TIMEOUT = 90.0

# pd log sentinel printed once the lab PD is about to accept() (the fuzz override idles the CP).
PD_LISTENING = "interlock-lab: PD listening on 0.0.0.0:10000"
_PD_LISTENING_TIMEOUT = 120.0

# Upper bound on container output carried into an error detail.
_OUTPUT_TAIL = 2000

REPORT_TITLE = "interlock OSDP assessment"


class Status(str, enum.Enum):
    """The outcome of one assessment step."""

    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class Inconclusive(Exception):
    """A step's lab precondition was not proven, so no verdict can be given."""


@dataclass(frozen=True)
class StepOutput:
    """What a step function returns: its findings and an optional detail line."""

    findings: tuple[Finding, ...]
    detail: str = ""


@dataclass(frozen=True)
class Step:
    """One assessment step: a lab scenario, the function that runs it and how it is reported.

    ``attacks`` pairs each attack key the step covers with that attack's finding-id prefix.
    """

    key: str
    title: str
    profile: str
    overrides: tuple[str, ...]
    run: Callable[[LabSession, dict[str, object]], StepOutput]
    method: str
    clean_detail: str
    attacks: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class StepResult:
    """The recorded outcome of one step."""

    key: str
    title: str
    profile: str
    overrides: tuple[str, ...]
    status: Status
    findings: tuple[Finding, ...]
    detail: str
    method: str
    duration_s: float


def _require_log(
    lab: lab_session.LabHandle, needle: str, timeout: float, what: str, *, service: str = "cp"
) -> None:
    """Raise ``Inconclusive`` unless ``service``'s log shows ``needle`` within ``timeout`` s."""
    if not lab.wait_for_log(service, needle, timeout=timeout):
        raise Inconclusive(f"{what} not observed in the {service} log within {timeout:.0f} s")


def _output_tail(result: subprocess.CompletedProcess[str]) -> str:
    """Return the bounded tail of a command's stdout and stderr, for an error detail."""
    return ((result.stdout or "") + (result.stderr or "")).strip()[-_OUTPUT_TAIL:]


# sniff-enumerate: the cleartext lab with interlock's read-only TCP tap in the attacker position.
_SNIFF_PROFILE = "cleartext"
_SNIFF_OVERRIDES = ("docker-compose.tap.yml",)


Frames = list[tuple[Direction, OsdpFrame]]

_DIRECTION_LABEL: dict[Direction, str] = {
    Direction.cp_to_pd: "cp->pd",
    Direction.pd_to_cp: "pd->cp",
}


@dataclass(frozen=True)
class _Capture:
    """Both decoded tap captures of one bring-up, and where decoding stopped at the cap.

    ``frames`` holds the cp->pd frames, then the pd->cp frames. ``capped`` names, in that
    order, every direction whose decode returned ``max_frames`` frames: exactly the cap counts
    as cut, so a clean verdict never rests on a capture that may continue past it.
    """

    frames: Frames
    captured_bytes: int
    max_frames: int
    capped: tuple[str, ...]

    @property
    def cap_note(self) -> str:
        """Name the directions that reached the frame cap, or "" when none did."""
        if not self.capped:
            return ""
        return f"decoding stopped at the {self.max_frames}-frame cap in {' and '.join(self.capped)}"

    @property
    def detail(self) -> str:
        """Frame counts per direction and captured bytes; counts and labels only."""
        counts = {direction: 0 for direction in _DIRECTION_LABEL}
        for direction, _ in self.frames:
            counts[direction] += 1
        detail = (
            f"{counts[Direction.cp_to_pd]} cp->pd and {counts[Direction.pd_to_cp]} pd->cp "
            f"frames decoded from {self.captured_bytes} captured bytes"
        )
        return f"{detail}; {self.cap_note}" if self.cap_note else detail


def _decode_direction(direction: Direction, data: bytes, *, max_frames: int) -> Frames:
    """Decode one direction's capture on its own, under its own ``max_frames`` cap.

    Raises ``Inconclusive`` when the bytes hold no OSDP frame: a non-empty capture that decodes
    to nothing proves nothing, the same as an empty one.
    """
    frames = decode_chunks([(direction, data)], max_frames=max_frames)
    if not frames:
        raise Inconclusive(
            f"the {_DIRECTION_LABEL[direction]} tap capture decoded to no OSDP frame"
        )
    return frames


def _capture_session(lab: lab_session.LabHandle, *, max_frames: int = 200) -> _Capture:
    """Gate on a full session, read both per-direction captures and decode them.

    Each direction is decoded under its own ``max_frames`` cap, so a long cp->pd capture (the
    CP polls until the capture is read) can never starve the pd->cp half. Returns a
    ``_Capture`` with the frames, cp->pd first, the captured byte count and the directions that
    reached the cap. Raises ``Inconclusive`` when the PD never came online, no card-read event
    was seen, or a capture is empty or decodes to no OSDP frame.
    """
    _require_log(lab, PD_ONLINE, _PD_ONLINE_TIMEOUT, "PD 101 online")
    _require_log(lab, EVENT_RECEIVED, _EVENT_TIMEOUT, "card-read event")
    cp2pd = lab.read_capture(CP2PD_PATH.as_posix())
    pd2cp = lab.read_capture(PD2CP_PATH.as_posix())
    if not cp2pd:
        raise Inconclusive("the cp->pd tap capture is empty")
    if not pd2cp:
        raise Inconclusive("the pd->cp tap capture is empty")
    decoded = {
        direction: _decode_direction(direction, data, max_frames=max_frames)
        for direction, data in ((Direction.cp_to_pd, cp2pd), (Direction.pd_to_cp, pd2cp))
    }
    return _Capture(
        frames=[*decoded[Direction.cp_to_pd], *decoded[Direction.pd_to_cp]],
        captured_bytes=len(cp2pd) + len(pd2cp),
        max_frames=max_frames,
        capped=tuple(
            _DIRECTION_LABEL[direction]
            for direction, frames in decoded.items()
            if len(frames) >= max_frames
        ),
    )


def _sniff_enumerate(session: LabSession, context: dict[str, object]) -> StepOutput:
    """Read both live tap captures and fold them into ATK-01 and ATK-02 findings."""
    with session.scenario(_SNIFF_PROFILE, _SNIFF_OVERRIDES) as lab:
        capture = _capture_session(lab)
    context["cleartext_frames"] = capture.frames
    findings = [*run_sniff(capture.frames), *run_enumerate(capture.frames)]
    return StepOutput(findings=tuple(findings), detail=capture.detail)


# fuzz: the cleartext lab under docker-compose.fuzz.yml (the CP idles so the PD's single
# accept() is free; the attacker idles with ./src mounted read-only at /app/src).
_FUZZ_PROFILE = "cleartext"
_FUZZ_OVERRIDES = ("docker-compose.fuzz.yml",)

# The line protocol between the in-container sweep and the host parser. Only lines that start
# with one of these exact prefixes are read; any other container output is ignored.
_FINDING_PREFIX = "INTERLOCK-FINDING "
_INCONCLUSIVE_PREFIX = "INTERLOCK-INCONCLUSIVE "
_DONE_PREFIX = "INTERLOCK-FUZZ-DONE "

# Runs inside the attacker container, whose image has no rich, typer or cryptography: the
# standard library, interlock.plugin and interlock.osdp.attacks.fuzz only.
_FUZZ_SCRIPT = (
    "import json\n"
    "from interlock.osdp.attacks.fuzz import FuzzBaselineError, fuzz_lab\n"
    "from interlock.plugin import finding_to_dict\n"
    "try:\n"
    "    findings = fuzz_lab(('pd', 10000))\n"
    "except FuzzBaselineError as exc:\n"
    "    print('INTERLOCK-INCONCLUSIVE ' + ' '.join(str(exc).split()))\n"
    "    raise SystemExit(0)\n"
    "for finding in findings:\n"
    "    print('INTERLOCK-FINDING ' + json.dumps(finding_to_dict(finding)))\n"
    "print('INTERLOCK-FUZZ-DONE ' + str(len(findings)))\n"
)


def _parse_fuzz_output(stdout: str) -> list[Finding]:
    """Parse the sweep's prefixed lines into findings; never trust unprefixed output.

    An ``INTERLOCK-INCONCLUSIVE`` line raises ``Inconclusive`` (the PD never answered the
    baseline poll). Each ``INTERLOCK-FINDING`` line must be a JSON finding document that
    ``finding_from_dict`` accepts (``ValueError`` otherwise). The ``INTERLOCK-FUZZ-DONE`` line
    must appear exactly once and its count must equal the parsed findings (``ValueError``
    otherwise); a sweep that never reported completion is inconclusive.
    """
    findings: list[Finding] = []
    done: int | None = None
    for line in stdout.splitlines():
        if line.startswith(_INCONCLUSIVE_PREFIX):
            raise Inconclusive(line[len(_INCONCLUSIVE_PREFIX) :].strip())
        if line.startswith(_FINDING_PREFIX):
            findings.append(finding_from_dict(json.loads(line[len(_FINDING_PREFIX) :])))
        elif line.startswith(_DONE_PREFIX):
            if done is not None:
                raise ValueError("the fuzz sweep reported completion more than once")
            done = int(line[len(_DONE_PREFIX) :])
    if done is None:
        raise Inconclusive("fuzz sweep did not report completion")
    if done != len(findings):
        raise ValueError(
            f"the fuzz sweep reported {done} findings but {len(findings)} finding lines parsed"
        )
    return findings


def _fuzz(session: LabSession, context: dict[str, object]) -> StepOutput:
    """Run the deterministic fuzz sweep inside the idle attacker and parse its findings."""
    with session.scenario(_FUZZ_PROFILE, _FUZZ_OVERRIDES) as lab:
        _require_log(lab, PD_LISTENING, _PD_LISTENING_TIMEOUT, "PD listening", service="pd")
        result = lab.compose(
            "exec", "-T", "-e", "PYTHONPATH=/app/src", "attacker", "python", "-c", _FUZZ_SCRIPT
        )
        if result.returncode != 0:
            raise LabError(
                f"the fuzz sweep in the attacker failed (exit {result.returncode}): "
                f"{_output_tail(result)}"
            )
        findings = _parse_fuzz_output(result.stdout)
        if findings:
            return StepOutput(
                findings=tuple(findings),
                detail="the PD stopped answering valid polls during the corruption sweep",
            )
        pd_log = lab.logs("pd").lower()
    if not any(marker in pd_log for marker in LIBOSDP_REJECTION_MARKERS):
        raise Inconclusive("the corruptions never reached the PD parser")
    return StepOutput(
        findings=(),
        detail=(
            "baseline poll answered; all nine corruptions handled; the PD answered every "
            "follow-up poll"
        ),
    )


# weak-key-keyset: the install-mode sc-scbkd lab under the read-only tap.
_WEAK_KEY_PROFILE = "sc-scbkd"
_WEAK_KEY_OVERRIDES = ("docker-compose.tap.yml",)
# The frame cap is per direction; 400 keeps CMD_KEYSET in reach on the install-mode bus.
_WEAK_KEY_MAX_FRAMES = 400


def _weak_key_keyset(session: LabSession, context: dict[str, object]) -> StepOutput:
    """Check the live Secure Channel handshake for SCBK-D and decrypt any KEYSET on the bus."""
    with session.scenario(_WEAK_KEY_PROFILE, _WEAK_KEY_OVERRIDES) as lab:
        capture = _capture_session(lab, max_frames=_WEAK_KEY_MAX_FRAMES)
    frames = capture.frames
    cp_codes = {frame.code for direction, frame in frames if direction is Direction.cp_to_pd}
    pd_codes = {frame.code for direction, frame in frames if direction is Direction.pd_to_cp}
    if constants.CMD_CHLNG not in cp_codes:
        raise Inconclusive(
            "no Secure Channel handshake captured (no CMD_CHLNG cp->pd), so neither the key "
            "check nor the KEYSET decryption had anything to work on"
        )
    if constants.REPLY_CCRYPT not in pd_codes:
        raise Inconclusive(
            "no REPLY_CCRYPT pd->cp captured (the PD half of the Secure Channel handshake), so "
            "no key verdict is possible"
        )
    findings = [*run_weak_key(frames), *run_keyset(frames)]
    if not findings and capture.capped:
        raise Inconclusive(
            f"no known weak key matched the captured handshake, but {capture.cap_note}, so the "
            "matching handshake may lie past it"
        )
    return StepOutput(findings=tuple(findings), detail=capture.detail)


# downgrade: the downgrade profile twice, untouched under the tap, then under the relay.
_DOWNGRADE_PROFILE = "downgrade"
_DOWNGRADE_BASELINE = ("docker-compose.tap.yml",)
_DOWNGRADE_ATTACKED = ("docker-compose.downgrade.yml",)


def _downgrade(session: LabSession, context: dict[str, object]) -> StepOutput:
    """Capture an untouched secure session, then one through the stripping relay; compare."""
    with session.scenario(_DOWNGRADE_PROFILE, _DOWNGRADE_BASELINE) as lab:
        baseline = _capture_session(lab).frames
    if not secure_channel.detect_state(baseline).secure:
        raise Inconclusive("baseline was not Secure Channel")
    if not downgrade._advertises_communication_security(baseline):
        raise Inconclusive("baseline advertised no CommunicationSecurity to strip")

    with session.scenario(_DOWNGRADE_PROFILE, _DOWNGRADE_ATTACKED) as lab:
        attacked = _capture_session(lab).frames
    findings = downgrade.run_downgrade(baseline, attacked)
    if findings:
        return StepOutput(
            findings=tuple(findings),
            detail="the Secure Channel baseline was forced to clear-text by the in-path rewrite",
        )
    if secure_channel.detect_state(attacked).secure:
        return StepOutput(
            findings=(),
            detail=(
                "the attacked session stayed Secure Channel: the in-path rewrite did not force "
                "clear-text"
            ),
        )
    raise Inconclusive("the downgrade verdict found no proof either way")


# The single lock-state sentinel the lab PD prints (lab/osdp/pd_driver.py), and its wait.
LOCK_UNLOCKED = "interlock-lab: LOCK state=UNLOCKED"
_LOCK_TIMEOUT = 120.0


def _unlocked(lab: lab_session.LabHandle) -> bool:
    """Return True when the PD's own log shows the lock-state sentinel."""
    return LOCK_UNLOCKED in lab.logs("pd")


def _arm(lab: lab_session.LabHandle, trigger: Path) -> None:
    """Touch ``trigger`` in the attacker, arming its relay; a failed touch is a ``LabError``."""
    path = PurePosixPath(trigger).as_posix()
    result = lab.compose("exec", "-T", "attacker", "touch", path)
    if result.returncode != 0:
        raise LabError(
            f"arming {path} in the attacker failed (exit {result.returncode}): "
            f"{_output_tail(result)}"
        )


def _require_locked(lab: lab_session.LabHandle) -> None:
    """Raise ``Inconclusive`` when the PD is already unlocked before the step arms anything."""
    if _unlocked(lab):
        raise Inconclusive(
            "the PD was already unlocked before arming, so no transition could be attributed "
            "to the attack"
        )


def _arm_once(lab: lab_session.LabHandle, trigger: Path) -> Callable[..., None]:
    """Return an inject that arms ``trigger`` on its first call and waits for the unlock.

    The relay serves the live rewrite itself; later calls (one per captured frame) only
    re-check, so the wait is bounded once rather than once per frame.
    """
    armed = False

    def inject(*_frame: bytes) -> None:
        nonlocal armed
        if armed:
            return
        _arm(lab, trigger)
        armed = True
        lab.wait_for_log("pd", LOCK_UNLOCKED, timeout=_LOCK_TIMEOUT)

    return inject


_NO_TRANSITION = f"armed; no lock-state transition within {_LOCK_TIMEOUT:.0f} s"

# spoof: the cleartext lab with the inline unlock-spoof relay, disarmed until its trigger.
_SPOOF_PROFILE = "cleartext"
_SPOOF_OVERRIDES = ("docker-compose.spoof.yml",)


def _spoof(session: LabSession, context: dict[str, object]) -> StepOutput:
    """Arm the unlock-spoof relay and watch the PD's lock state flip."""
    with session.scenario(_SPOOF_PROFILE, _SPOOF_OVERRIDES) as lab:
        _require_log(lab, PD_ONLINE, _PD_ONLINE_TIMEOUT, "PD 101 online")
        _require_locked(lab)
        findings = spoof.run_spoof(_arm_once(lab, spoof._TRIGGER_PATH), lambda: _unlocked(lab))
    if findings:
        return StepOutput(
            findings=tuple(findings),
            detail="the PD was locked before arming and logged UNLOCKED after the forged CMD_OUT",
        )
    return StepOutput(findings=(), detail=_NO_TRANSITION)


# replay: the cleartext lab with the inline replay relay, disarmed until its trigger.
_REPLAY_PROFILE = "cleartext"
_REPLAY_OVERRIDES = ("docker-compose.replay.yml",)


# The replay verdict's evidence describes the byte-exact re-injection; in this run the live
# unlock came through the shared relay rewrite, so the finding says so next to its evidence.
REPLAY_LIVE_NOTE = (
    "Assessment run: the live unlock was triggered through the in-path relay's shared "
    "POLL-to-CMD_OUT rewrite on the replay trigger; the byte-exact re-injection of the "
    "captured REPLY_RAW is proven by host unit tests, not on the live bus."
)


def _replay(session: LabSession, context: dict[str, object]) -> StepOutput:
    """Replay the card read captured live by sniff-enumerate and watch the PD's lock state."""
    frames = context.get("cleartext_frames")
    if not isinstance(frames, list):
        raise Inconclusive("no live clear-text capture from the sniff-enumerate step")
    captured = replay.capture_card_exchange(frames)
    if not captured:
        raise Inconclusive("the live clear-text capture holds no REPLY_RAW card read to replay")

    with session.scenario(_REPLAY_PROFILE, _REPLAY_OVERRIDES) as lab:
        _require_log(lab, PD_ONLINE, _PD_ONLINE_TIMEOUT, "PD 101 online")
        _require_locked(lab)
        findings = replay.run_replay(
            captured, _arm_once(lab, replay._TRIGGER_PATH), lambda: _unlocked(lab)
        )
    if findings:
        return StepOutput(
            findings=tuple(
                replace(finding, evidence=f"{finding.evidence} {REPLAY_LIVE_NOTE}")
                for finding in findings
            ),
            detail=(
                f"{len(captured)} card read(s) captured live; the PD was locked before arming "
                "and logged UNLOCKED after"
            ),
        )
    return StepOutput(findings=(), detail=_NO_TRANSITION)


# cve-2024-52288-fixed: the sc-scbkd lab on the fixed LibOSDP core with the inline cve relay.
_CVE_PROFILE = "sc-scbkd"
_CVE_OVERRIDES = ("docker-compose.cve.yml",)
CP_AUTHORISED = "interlock-lab: CP authorised unlock on card read"
# The fixed core's own rejection of an out-of-state REPLY_RMAC_I (libosdp osdp_cp.c).
RMAC_I_REJECTED = "Out of order REPLY_RMAC_I"
_CVE_BASELINE_TIMEOUT = 90.0
_CVE_OUTCOME_TIMEOUT = 90.0
_CVE_POLL_INTERVAL = 2.0

# The relay replays the live secure frames in-band; run_cve_replay only needs one element so
# it issues exactly one inject (the arm and the bounded wait), not the wire frames themselves.
_ARM_TOKEN = b"arm-inline-relay"


def _cve_fixed(session: LabSession, context: dict[str, object]) -> StepOutput:
    """Replay REPLY_RMAC_I at the fixed core; only its own rejection line proves the fix."""
    with session.scenario(_CVE_PROFILE, _CVE_OVERRIDES) as lab:
        _require_log(lab, PD_ONLINE, _PD_ONLINE_TIMEOUT, "PD 101 online")
        if not lab.wait_for_log("cp", CP_AUTHORISED, timeout=_CVE_BASELINE_TIMEOUT):
            raise Inconclusive("no genuine baseline authorisation")
        baseline = lab.logs("cp").count(CP_AUTHORISED)

        def arm(_token: bytes) -> None:
            _arm(lab, replay._CVE_TRIGGER_PATH)
            deadline = lab.clock() + _CVE_OUTCOME_TIMEOUT
            while lab.clock() < deadline:
                cp_log = lab.logs("cp")
                if RMAC_I_REJECTED in cp_log or cp_log.count(CP_AUTHORISED) > baseline:
                    return
                lab.sleep(_CVE_POLL_INTERVAL)

        findings = replay.run_cve_replay(
            [_ARM_TOKEN], arm, lambda: lab.logs("cp").count(CP_AUTHORISED) > baseline
        )
        cp_log = lab.logs("cp")
    if findings:
        return StepOutput(
            findings=tuple(findings),
            detail=(
                f"the fixed core re-authorised: {cp_log.count(CP_AUTHORISED)} authorisations "
                f"after a baseline of {baseline}"
            ),
        )
    rejection = next((line for line in cp_log.splitlines() if RMAC_I_REJECTED in line), None)
    if rejection is None:
        raise Inconclusive("the replay never reached the REPLY_RMAC_I fix path")
    return StepOutput(
        findings=(),
        detail=f'fixed LibOSDP 3.0.8 rejected the replayed REPLY_RMAC_I: "{rejection.strip()}"',
    )


STEPS: tuple[Step, ...] = (
    Step(
        key="sniff-enumerate",
        title="Passive bus sniffing and device enumeration",
        profile=_SNIFF_PROFILE,
        overrides=_SNIFF_OVERRIDES,
        run=_sniff_enumerate,
        method=(
            "The read-only TCP tap in the attacker position records both directions of one "
            "cleartext CP-PD session; the captures are decoded with the interlock OSDP codec "
            "and folded into the PD topology (sniff) and the PD identity and capabilities "
            "(enumerate)."
        ),
        clean_detail="The live captures decoded to no PD topology, identity or capabilities.",
        attacks=(("sniff", "ATK-01-"), ("enumerate", "ATK-02-")),
    ),
    Step(
        key="fuzz",
        title="Command fuzzing of the PD parser",
        profile=_FUZZ_PROFILE,
        overrides=_FUZZ_OVERRIDES,
        run=_fuzz,
        method=(
            "active: the nine deterministic corruptions sent from the idle attacker over one "
            "persistent connection to the PD (cp idle, docker-compose.fuzz.yml); liveness "
            "proven by a follow-up valid poll after each"
        ),
        clean_detail="The PD answered every follow-up poll after each corruption.",
        attacks=(("fuzz", "ATK-07-fuzz-"),),
    ),
    Step(
        key="weak-key-keyset",
        title="Weak Secure Channel key and KEYSET recovery",
        profile=_WEAK_KEY_PROFILE,
        overrides=_WEAK_KEY_OVERRIDES,
        run=_weak_key_keyset,
        method=(
            "passive: read-only TCP tap on the install-mode Secure Channel bus; AES-verified "
            "SCBK-D check and KEYSET payload decryption on the host"
        ),
        clean_detail=(
            "The captured handshake used no known weak key and no KEYSET payload decrypted."
        ),
        attacks=(("weak-key", "ATK-06-"), ("keyset", "ATK-04-")),
    ),
    Step(
        key="downgrade",
        title="Secure Channel downgrade to clear-text",
        profile=_DOWNGRADE_PROFILE,
        overrides=(*_DOWNGRADE_BASELINE, *_DOWNGRADE_ATTACKED),
        run=_downgrade,
        method=(
            "before/after pair: untouched session via the tap, then the inline relay stripping "
            "CommunicationSecurity from REPLY_PDCAP"
        ),
        clean_detail="The attacked session stayed Secure Channel.",
        attacks=(("downgrade", "ATK-03-"),),
    ),
    Step(
        key="spoof",
        title="Unlock spoofing by command injection",
        profile=_SPOOF_PROFILE,
        overrides=_SPOOF_OVERRIDES,
        run=_spoof,
        method=(
            "active: inline rewrite relay turns an in-flight CMD_POLL into a forged CMD_OUT on "
            "a trigger file; oracle is the PD's own lock-state log line"
        ),
        clean_detail=_NO_TRANSITION,
        attacks=(("spoof", "ATK-08-"),),
    ),
    Step(
        key="replay",
        title="Clear-text card-read replay",
        profile=_REPLAY_PROFILE,
        overrides=_REPLAY_OVERRIDES,
        run=_replay,
        method=(
            "active: the card read comes from the sniff-enumerate step's live capture; live "
            "proof via the in-path relay, which serves the same POLL-to-CMD_OUT rewrite as "
            "spoof on the replay trigger; the byte-exact re-injection of the captured "
            "REPLY_RAW is proven by host unit tests (tests/osdp/test_attacks_replay.py), not "
            "on the live bus"
        ),
        clean_detail=_NO_TRANSITION,
        attacks=(("replay", "ATK-05a-"),),
    ),
    Step(
        key="cve-2024-52288-fixed",
        title="CVE-2024-52288 REPLY_RMAC_I replay against the fixed LibOSDP core",
        profile=_CVE_PROFILE,
        overrides=_CVE_OVERRIDES,
        run=_cve_fixed,
        method=(
            "active: inline relay replays the live-captured REPLY_RMAC_I-first secure blob "
            "aligned to the CP's 2-bit sequence; oracle is the controller's re-authorisation "
            "count and its rejection line; the pinned-vulnerable core is not part of the "
            "default run (D-03)"
        ),
        clean_detail="The fixed core rejected the replayed REPLY_RMAC_I.",
        attacks=(("cve-2024-52288", "ATK-05b-"),),
    ),
)


def _describe(exc: BaseException) -> str:
    """Return ``"TypeName: message"`` for ``exc`` (no traceback, no environment)."""
    return f"{type(exc).__name__}: {exc}"


def run_assessment(
    session: LabSession,
    *,
    steps: Sequence[Step] = STEPS,
    clock: Callable[[], float] = time.monotonic,
    on_step: Callable[[int, int, StepResult], None] | None = None,
) -> list[StepResult]:
    """Run every step in order and return one ``StepResult`` per step.

    The project is reset once first (``down -v``) to clear leftovers of an interrupted run.
    ``on_step(index, total, result)`` is called after each step, ``index`` counting from 1.
    """
    session.reset()
    context: dict[str, object] = {}
    results: list[StepResult] = []
    total = len(steps)
    for index, step in enumerate(steps, start=1):
        started = clock()
        findings: tuple[Finding, ...] = ()
        try:
            output = step.run(session, context)
        except Inconclusive as exc:
            status, detail = Status.INCONCLUSIVE, str(exc)
        except Exception as exc:  # noqa: BLE001 - one failing step must not lose the others
            traceback.print_exc(file=sys.stderr)
            status, detail = Status.ERROR, _describe(exc)
        else:
            findings = tuple(output.findings)
            if findings:
                status, detail = Status.VULNERABLE, output.detail
            else:
                status, detail = Status.NOT_VULNERABLE, output.detail or step.clean_detail
        result = StepResult(
            key=step.key,
            title=step.title,
            profile=step.profile,
            overrides=step.overrides,
            status=status,
            findings=findings,
            detail=detail,
            method=step.method,
            duration_s=round(clock() - started, 1),
        )
        results.append(result)
        if on_step is not None:
            on_step(index, total, result)
    return results


def exit_code(results: Sequence[StepResult]) -> int:
    """Return 1 when any step is inconclusive or error, else 0."""
    incomplete = {Status.INCONCLUSIVE, Status.ERROR}
    return 1 if any(result.status in incomplete for result in results) else 0


def required_files(steps: Sequence[Step] = STEPS) -> tuple[str, ...]:
    """Return the compose files the steps need under the lab dir, base file first."""
    files = [lab_session.COMPOSE_FILE]
    for step in steps:
        for override in step.overrides:
            if override not in files:
                files.append(override)
    return tuple(files)


_COLUMNS = ("Step", "Profile", "Status", "Findings", "Duration (s)")


def _row(result: StepResult) -> tuple[str, str, str, str, str]:
    return (
        result.key,
        result.profile,
        result.status.value,
        str(len(result.findings)),
        f"{result.duration_s:.1f}",
    )


def _steps_table(results: Sequence[StepResult]) -> list[str]:
    """Return the Markdown "### Steps" table summarising every step."""
    lines = ["### Steps", "", "| " + " | ".join(_COLUMNS) + " |", "|" + "---|" * len(_COLUMNS)]
    for result in results:
        lines.append("| " + " | ".join(_row(result)) + " |")
    lines.append("")
    return lines


# Highest severity first, as a reader triages.
_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
_COMPLETED = {Status.VULNERABLE, Status.NOT_VULNERABLE}
_NO_FINDING = "no finding"
_NOT_RUN = "not run"
_ACCESS_VECTOR_REASON = (
    "every bus attack presumes a device inserted on the RS-485 segment; no ICS technique "
    "fits better"
)


def _named(technique_id: str | None, name: str | None) -> str:
    """Return "ID (Name)", or "-" when the attack has no technique in that matrix."""
    if technique_id is None:
        return "-"
    return f"{technique_id} ({name})" if name else technique_id


@dataclass(frozen=True)
class CoverageRow:
    """One attack's outcome: the step that ran it, its finding ids or the step's status."""

    attack: str
    step: str
    result: str
    finding_ids: tuple[str, ...]
    technique: attack_map.Technique


def coverage(results: Sequence[StepResult], steps: Sequence[Step] = STEPS) -> list[CoverageRow]:
    """Return one row per (attack key, finding-id prefix) of ``steps``, in run order.

    The result is the comma-joined finding ids carrying the attack's prefix; "no finding" when
    the step completed without one; otherwise the step's own status (inconclusive or error),
    so a negative is never hidden inside a vulnerable step. An attack whose step is absent
    from ``results`` reads "not run".
    """
    by_key = {result.key: result for result in results}
    rows: list[CoverageRow] = []
    for step in steps:
        result = by_key.get(step.key)
        for attack, prefix in step.attacks:
            ids: tuple[str, ...] = ()
            if result is None:
                outcome = _NOT_RUN
            else:
                ids = tuple(f.id for f in result.findings if f.id.startswith(prefix))
                if ids:
                    outcome = ", ".join(ids)
                elif result.status in _COMPLETED:
                    outcome = _NO_FINDING
                else:
                    outcome = result.status.value
            rows.append(CoverageRow(attack, step.key, outcome, ids, attack_map.MAPPINGS[attack]))
    return rows


def _scope(results: Sequence[StepResult], generated_at: str) -> list[str]:
    profiles = ", ".join(dict.fromkeys(result.profile for result in results)) or "none"
    vector = _named(attack_map.ACCESS_VECTOR.enterprise, attack_map.ACCESS_VECTOR.enterprise_name)
    target = (
        "the bundled, network-isolated lab (no published ports), compose project "
        f"{lab_session.DEFAULT_PROJECT}; no real hardware is reachable from the assessment"
    )
    core = (
        "LibOSDP 3.0.8 (fixed); the pinned-vulnerable CVE-2024-52288 core is not part of the "
        "default run"
    )
    framework = (
        f"MITRE ATT&CK v{attack_map.ATTACK_VERSION}: Enterprise primary, ICS secondary where a "
        "technique fits"
    )
    return [
        "## Scope",
        "",
        f"- **Target:** {target}.",
        f"- **Profiles run:** {profiles}",
        f"- **Core under test:** {core}.",
        f"- **Framework:** {framework}.",
        f"- **Access vector:** {vector}, engagement-level: {_ACCESS_VECTOR_REASON}.",
        f"- **Generated at:** {generated_at}",
        "",
    ]


def _summary(results: Sequence[StepResult]) -> list[str]:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for result in results:
        for finding in result.findings:
            counts[finding.severity] += 1
    lines = [
        "## Summary",
        "",
        "| Severity | Findings |",
        "|---|---|",
        *(f"| {severity.value} | {count} |" for severity, count in counts.items()),
        "",
    ]
    return lines + _steps_table(results)


_COVERAGE_COLUMNS = ("Attack", "Step", "Result", "Enterprise", "ICS")


def _coverage_table(rows: Sequence[CoverageRow]) -> list[str]:
    lines = [
        "## Coverage",
        "",
        "| " + " | ".join(_COVERAGE_COLUMNS) + " |",
        "|" + "---|" * len(_COVERAGE_COLUMNS),
    ]
    for row in rows:
        technique = row.technique
        cells = (
            row.attack,
            row.step,
            row.result,
            _named(technique.enterprise, technique.enterprise_name),
            _named(technique.ics, technique.ics_name),
        )
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def _appendix(results: Sequence[StepResult]) -> list[str]:
    lines = ["## Checks without a finding", ""]
    clean = [result for result in results if not result.findings]
    lines.extend(f"- {r.key} ({r.status.value}): {r.detail}" for r in clean)
    if not clean:
        lines.append("- none: every step produced at least one finding")
    lines += ["", "## Method notes", ""]
    lines.extend(f"- {result.key}: {result.method}" for result in results)
    lines.append("")
    return lines


def _coverage_dict(row: CoverageRow) -> dict[str, object]:
    technique = row.technique
    return {
        "attack": row.attack,
        "step": row.step,
        "result": row.result,
        "finding_ids": list(row.finding_ids),
        "enterprise": technique.enterprise,
        "ics": technique.ics,
    }


def _step_dict(result: StepResult) -> dict[str, object]:
    return {
        "key": result.key,
        "title": result.title,
        "profile": result.profile,
        "overrides": list(result.overrides),
        "status": result.status.value,
        "detail": result.detail,
        "method": result.method,
        "duration_s": result.duration_s,
        "finding_ids": [finding.id for finding in result.findings],
    }


def write_reports(results: Sequence[StepResult], md_path: Path, *, generated_at: str) -> Path:
    """Write the Markdown report to ``md_path`` and the JSON next to it; return the JSON path.

    The Markdown reads: title and authorized-use notice, Scope (lab target, profiles, core,
    ATT&CK version, access vector), Summary (severity counts, step table), Coverage (every
    attack's result and techniques), Findings in step order with "ID (Name)" techniques, then
    the checks without a finding and every step's method note. The JSON mirrors it for CI.
    Neither report carries raw capture bytes, tracebacks or environment data.
    """
    findings = [finding for result in results for finding in result.findings]
    rows = coverage(results)
    report.write_markdown(
        findings,
        md_path,
        title=REPORT_TITLE,
        preamble=[
            *_scope(results, generated_at),
            *_summary(results),
            *_coverage_table(rows),
            "## Findings",
            "",
        ],
        appendix=_appendix(results),
        technique_names=attack_map.technique_names(),
    )
    json_path = md_path.with_suffix(".json")
    vector = attack_map.ACCESS_VECTOR
    report.write_json(
        findings,
        json_path,
        metadata={
            "tool": {"name": "interlock", "version": interlock.__version__},
            "generated_at": generated_at,
            "target": {"kind": "lab", "project": lab_session.DEFAULT_PROJECT},
            "attack_version": attack_map.ATTACK_VERSION,
            "access_vector": {"enterprise": vector.enterprise, "name": vector.enterprise_name},
            "coverage": [_coverage_dict(row) for row in rows],
            "steps": [_step_dict(result) for result in results],
        },
    )
    return json_path


def render_step_table(results: Sequence[StepResult]) -> None:
    """Print the per-step summary as a rich table to the terminal."""
    table = Table(title=REPORT_TITLE)
    for column in _COLUMNS:
        table.add_column(column)
    for result in results:
        table.add_row(*_row(result))
    _console.print(table)
