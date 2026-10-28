# interlock

interlock is an extensible red-team platform for OT, edge and physical-security devices, built
as a small core plus protocol plugins. Its first module assesses OSDP access control against a
bundled, network-isolated lab.

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

## Authorized use only

Authorized use only. interlock runs against its bundled, network-isolated lab by default. Use it on real equipment only with the owner's written authorization; physical mode is gated by --physical, a disclaimer and a typed scope confirmation. This tool ships no vendor default production keys; the only built-in key is the public OSDP specification default SCBK-D.

Unauthorized access to a system is a criminal offence in most jurisdictions.

## Quickstart (lab)

Prerequisites: Python 3.11 or newer and Docker with the compose plugin. The first run builds
the lab images and compiles LibOSDP from source, which takes several minutes. Run the commands
from the repository root, where the lab compose files live.

macOS and Linux (zsh):

```zsh
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/interlock osdp assess
```

Windows (PowerShell 5.1, Docker Desktop):

```powershell
py -m venv .venv
.venv\Scripts\pip install -e .
.venv\Scripts\interlock osdp assess
```

The Windows path has not yet been run on a Windows machine.

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

- `0` - every assessment step completed.
- `1` - the reports were written, but at least one step was inconclusive or failed.
- `2` - preflight failed (no Docker, no lab directory, a missing compose file or a `.json`
  output path) and nothing was written.

The full project README, the plugin-authoring guide and the findings write-up arrive with the
publication phase.
