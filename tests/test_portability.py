"""The unit path must import on Windows, where termios and friends do not exist (D-08).

The CLI builds its command groups at import, so one POSIX-only module imported at module
scope anywhere under the osdp group takes the whole CLI down on Windows, and with it every
CLI test and the collection of tests/lab. These tests run the CLI in a fresh interpreter
with the POSIX terminal modules blocked, which is the shape of the Windows stdlib.
"""

from __future__ import annotations

import subprocess
import sys

# The POSIX terminal modules the Windows stdlib does not ship.
_BLOCKED = ("termios", "tty", "fcntl", "pty")

_SCRIPT = """
import sys
for name in {blocked!r}:
    sys.modules[name] = None
from interlock.cli import app
app({argv!r})
"""


def _run_cli_without_posix_terminal(argv: list[str]) -> subprocess.CompletedProcess[str]:
    script = _SCRIPT.format(blocked=_BLOCKED, argv=argv)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )


def test_cli_imports_without_posix_terminal_modules() -> None:
    top = _run_cli_without_posix_terminal(["--help"])
    assert top.returncode == 0, top.stderr
    assert "skipping command group" not in top.stderr, top.stderr
    assert "osdp" in top.stdout

    osdp = _run_cli_without_posix_terminal(["osdp", "--help"])
    assert osdp.returncode == 0, osdp.stderr
    assert "assess" in osdp.stdout
