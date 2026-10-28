"""Test-wide switches that keep the CLI output plain text under any CI colour variable.

CI runners set ``GITHUB_ACTIONS``, ``FORCE_COLOR`` or ``PY_COLORS``. typer reads them once, when
``typer.rich_utils`` is first imported, and then renders help through a forced terminal; rich
picks a colour system when a console is created. Both happen at the CLI import during
collection, so the switches are set here, before pytest imports any test module. The tests
assert plain text while a real terminal user keeps the colour, so the switches live in the
tests and never in the CLI. Subprocesses inherit ``os.environ``, so a CLI started in a fresh
interpreter reads the same.
"""

from __future__ import annotations

import os

# typer's own switch for its help and error console; it overrides the three CI variables.
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"
# rich 14 and later check this before FORCE_COLOR for every other console.
os.environ["TTY_COMPATIBLE"] = "0"
