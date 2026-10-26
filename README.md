# interlock

interlock is an extensible red-team platform for OT, edge and physical-security devices, built
as a small core plus protocol plugins. Its first module assesses OSDP access control against a
bundled, network-isolated lab.

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
