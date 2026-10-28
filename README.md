# interlock

[![CI](https://github.com/oliver-dolski/interlock/actions/workflows/ci.yml/badge.svg)](https://github.com/oliver-dolski/interlock/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

interlock is a red-team platform for OT, edge and physical-security devices, built as a small
core plus protocol plugins. Its first module assesses OSDP, the RS-485 protocol between
access-control panels and the card readers on the door, against a bundled, network-isolated
lab: one command runs every attack in the module and writes a report with each finding mapped
to MITRE ATT&CK. It exists because OSDP has no open offensive tooling, while the readers and
panels that speak it guard real doors.

## What a finding looks like

This block is from [`docs/examples/assessment.md`](docs/examples/assessment.md), the unedited
report of one run against the bundled lab:

```text
## ATK-08-spoof-unlock: OSDP PD unlocked by a forged CMD_OUT injected onto the bus

- **Severity:** critical
- **ATT&CK technique:** T1565.002 (Data Manipulation: Transmitted Data Manipulation)
- **ATT&CK for ICS:** T1692.001 (Unauthorized Message: Command Message)
- **Evidence:** The PD's lock-state signal was LOCKED before the injection and flipped to UNLOCKED immediately after a forged CMD_OUT (output permanently ON) was injected cp->pd through the in-path MITM seam, carrying the live session's own sequence number so it was accepted as a legitimate command.
- **Remediation:** Enable OSDP Secure Channel with MAC+encryption (SCS_17/18) so an in-path attacker cannot forge or inject accepted commands; without channel integrity, any party on the bus can command the PD's outputs directly.
```

Three things in that block are the point:

- The oracle is the **PD's own lock-state line**, not the attacker's belief. The finding is
  raised because the reader under attack logged LOCKED and then UNLOCKED, not because the
  injection was sent.
- The forged CMD_OUT carries the **live session's sequence number**. It is spliced into the
  running CP-PD exchange, so the PD accepts it as the next legitimate command.
- The finding maps to **ATT&CK v20**: Enterprise as the primary technique, with an ICS
  technique as the secondary where one fits.

## What you see

![interlock osdp assess against the bundled lab](docs/media/assess.gif)

The recording is regenerated from [`docs/media/assess.tape`](docs/media/assess.tape); the
minutes between the first step and the end of the run are cut.

## Authorized use only

Authorized use only. interlock runs against its bundled, network-isolated lab by default. Use it on real equipment only with the owner's written authorization; physical mode is gated by --physical, a disclaimer and a typed scope confirmation. This tool ships no vendor default production keys; the only built-in key is the public OSDP specification default SCBK-D.

Unauthorized access to a system is a criminal offence in most jurisdictions.

## Quickstart (lab)

Prerequisites: Python 3.11 or newer and Docker with the compose plugin. The first run builds
the lab images and compiles LibOSDP from source, which takes several minutes.

The lab compose files ship with the repository, not with the Python package, and interlock is
not published to PyPI yet, so start from a clone and run the commands from its root.

macOS and Linux (zsh):

```zsh
git clone https://github.com/oliver-dolski/interlock.git
cd interlock
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/interlock osdp assess
```

Windows (PowerShell 5.1, Docker Desktop):

```powershell
git clone https://github.com/oliver-dolski/interlock.git
cd interlock
py -m venv .venv
.venv\Scripts\pip install -e .
.venv\Scripts\interlock osdp assess
```

CI runs the unit tests on Windows; the Windows lab path has not yet been run on a Windows machine.

## Capabilities and ATT&CK v20

Each capability is an `interlock osdp` subcommand (the CVE replay is `replay --mode cve`), and
`interlock osdp assess` runs all of them against the lab. The ids and names come from
[`src/interlock/osdp/attack_map.py`](src/interlock/osdp/attack_map.py), and a test fails if
this table drifts from it.

<!-- attack:start -->
| Capability | Enterprise | ICS |
|---|---|---|
| Passive bus sniffing and PD topology (`sniff`) | T1040 Network Sniffing | T0842 Network Sniffing |
| PD identity and capability enumeration (`enumerate`) | T1018 Remote System Discovery | T0888 Remote System Information Discovery |
| Default Secure Channel key detection, SCBK-D (`weak-key`) | T1110.002 Brute Force: Password Cracking | T1694.001 Insecure Credentials: Default Credentials |
| Install-mode KEYSET key recovery (`keyset`) | T1040 Network Sniffing | T0842 Network Sniffing |
| Secure Channel downgrade by capability rewrite (`downgrade`) | T1689 Downgrade Attack | T0830 Adversary-in-the-Middle |
| Clear-text card-read replay (`replay`) | T1557 Adversary-in-the-Middle | T1692.002 Unauthorized Message: Reporting Message |
| Secure Channel replay behind an out-of-order REPLY_RMAC_I (`cve-2024-52288`) | T1557 Adversary-in-the-Middle | T0830 Adversary-in-the-Middle |
| Forged CMD_OUT unlock injection (`spoof`) | T1565.002 Data Manipulation: Transmitted Data Manipulation | T1692.001 Unauthorized Message: Command Message |
| Frame fuzzing for PD crashes (`fuzz`) | T1499.004 Endpoint Denial of Service: Application or System Exploitation | T0814 Denial of Service |
<!-- attack:end -->

The engagement-level access vector is T1200 Hardware Additions: every bus attack presumes a
device inserted on the RS-485 segment. Enterprise is the primary matrix, because OSDP is
physical access control rather than an industrial process; the ICS technique is a secondary
mapping where one fits.

## Output

`interlock osdp assess` writes two reports to the current directory:

- `interlock-assessment.md` - the step table and each finding with its ATT&CK technique, for
  people.
- `interlock-assessment.json` - the same findings as structured data, for tools.

Options:

- `-o`, `--output PATH` - the Markdown report path; the JSON report is written next to it with
  the same name and a `.json` suffix.
- `--lab-dir DIR` - the directory holding the lab compose files, when you run from somewhere
  other than the repository.

Exit codes:

- `0` - every assessment step completed and every attack in the report was decided.
- `1` - the reports were written, but at least one step or attack was inconclusive or failed.
- `2` - preflight failed (no Docker, no lab directory, a missing compose file, a `.json`
  output path or a failed containment check) and nothing was written.

## Safety and scope

- The default target is the bundled lab. `interlock osdp assess` has no `--physical` or
  `--device` option and imports nothing from the physical path.
- Before every run, the preflight resolves each compose file pair with `docker compose config`
  and refuses to start unless every containment rule holds: every network internal, no
  published or exposed ports, no devices, not privileged, no host networking or namespaces, no
  added capabilities, every bind mount read-only and from inside the lab dir, the CP routed
  through the attacker. The report's Containment line states what the rules add up to: "so no
  lab container gets a host device, host privileges or namespaces, a host path outside the lab
  dir or any network but the internal labnet (not covered: the image build steps and the Docker
  daemon's own configuration)".
- The CVE-2024-52288 step runs live against the fixed LibOSDP 3.0.8 core and quotes its own
  "Out of order REPLY_RMAC_I" rejection. The pinned-vulnerable v2.4.0 core is opt-in through
  [`docker-compose.vuln.yml`](docker-compose.vuln.yml) and is not part of the default run.
- A CP that enforces Secure Channel refuses the downgrade; host tests prove this path, since
  no bundled profile enforces it. The step recognises the refusal by the CP's own
  `ENFORCE_SECURE` log line, which only the host tests exercise.
- The replay finding is a met precondition: a clear-text card read captured live and an
  in-path unlock accepted on the live bus. The byte-exact replay is proven by host unit tests,
  not on the live bus.
- A test scans every Python file under `src/`, `lab/` and `tests/` for 16-byte key literals
  and allows only the public SCBK-D and two lab and test keys. That is a check, not a guarantee.

## Physical mode

The attack commands `enumerate`, `keyset`, `downgrade`, `replay`, `spoof` and `fuzz` take
`--physical` to work on a real serial bus instead of the lab. It is gated by a disclaimer and a
typed confirmation of the scope (`--target`) you are authorized to assess, and it needs the
owner's written authorization before you use it. `assess` has no physical mode. The physical
path has not been validated on real RS-485 hardware yet.

## Extending

A protocol is a plugin: an installed package that declares entry points, picked up with no edit
to interlock itself. [`docs/plugin-authoring.md`](docs/plugin-authoring.md) covers the
contract: `interlock.plugins` names a class that returns findings, and `interlock.commands`
names a factory for a protocol's own subcommand group. A minimal plugin you can copy is in
[`docs/examples/minimal-plugin`](docs/examples/minimal-plugin).

## Tests

The fast suite needs no Docker; the lab suite needs Docker and runs the attacks against the
lab.

```zsh
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -m "not lab"
.venv/bin/python -m pytest -m lab
```

```powershell
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\python -m pytest -m "not lab"
.venv\Scripts\python -m pytest -m lab
```

CI runs ruff and mypy, the unit suite on Ubuntu and Windows with Python 3.11 and 3.15, a build
of the sdist and wheel checked against the file allow-list and `twine check --strict`, and a lab
smoke run of `interlock osdp assess` on Ubuntu. The full lab suite runs on manual dispatch.

## License

Apache-2.0, see [LICENSE](LICENSE). Attribution, including the MITRE designation, is in
[NOTICE](NOTICE).

Technique identifiers and names come from MITRE ATT&CK® Enterprise and MITRE ATT&CK® for ICS
v20.0 and are used under the MITRE ATT&CK
[Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). © 2026
The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.
interlock is an independent project and is not affiliated with The MITRE Corporation.
