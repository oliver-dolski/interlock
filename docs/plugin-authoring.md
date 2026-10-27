# Writing an interlock plugin

interlock is a core plus plugins. The core lists plugins, runs them and writes reports; every
protocol lives in a plugin. Adding a protocol is an additive contribution: you ship a package
that declares entry points, and the core picks it up with no edit to interlock itself.

This guide covers what a plugin is, the four parts a complete protocol module brings, the safety
obligations every plugin inherits, a minimal example you can copy, and the OSDP module as the
full worked example.

## What a plugin is

A plugin is an installed Python package that declares entry points in its own `pyproject.toml`.
interlock reads two entry-point groups:

- `interlock.plugins` names a class. interlock instantiates it with no arguments and keys it by
  its `name` attribute. The class has a `name`, a one-line `summary` and a
  `run(target=None, options=None)` method that returns a `list[Finding]`. `interlock plugins`
  lists it, and `interlock run <name>` runs it, prints the findings and writes a Markdown report.
- `interlock.commands` names a zero-argument factory that returns a `typer.Typer`. interlock
  calls the factory and attaches the group as `interlock <entry-point name>`, so a protocol gets
  its own subcommands (`interlock osdp sniff`, `interlock osdp assess` and so on). A
  `typer.Typer` instance registered directly is accepted too; it is attached as is and never
  called, because calling a Typer runs the CLI.

The names `plugins` and `run` are reserved for the core commands; a command group registered
under either name is not attached. A broken entry (an import that fails, a factory that raises,
a factory that returns something other than a `typer.Typer`) is skipped with one line on stderr
starting `interlock: skipping`, and the rest of the CLI keeps working.

Installing a plugin means trusting its code: interlock imports it in the same process. Only
installed entry points load. There is no loading from an arbitrary path and no download.

The discovery code is `src/interlock/registry.py` (`ENTRY_POINT_GROUP`, `COMMANDS_GROUP`) and
`src/interlock/cli.py` (where command groups are attached). interlock declares its own entry
points the same way, in `pyproject.toml`: the in-tree `demo` plugin in `interlock.plugins` and
the `osdp` command group in `interlock.commands`.

## The four-part contract

`interlock run` only needs the plugin class. A complete protocol module brings four parts, so
that a reader can reproduce every finding without owning the hardware. The OSDP module shows all
four.

### Lab

A software lab that runs the protocol's devices in containers, so every attack has a target
that is not someone else's equipment. Build it with docker compose: put the services on an
internal network, publish no ports, and drive it under its own compose project so it cannot
collide with another run. Check containment before a run instead of assuming it.

In OSDP the lab is a peripheral device and a control panel built on LibOSDP, talking over TCP:
`lab/osdp/pd_driver.py`, `lab/osdp/cp_driver.py` and the scenarios in `lab/osdp/scenarios.py`,
built by `Dockerfile` and wired by `docker-compose.yml` (internal network, no `ports:`) plus one
`docker-compose.*.yml` override per scenario. The host side is
`src/interlock/osdp/lab_session.py`: it runs the lab under its own compose project and checks
the resolved compose model for containment before the assessment starts. The lab needs a
checkout of the repository; it does not ship inside the wheel.

### Attack and assessment

Each capability is a library function that returns a `list[Finding]`, plus one CLI command that
calls it. Keep the function usable without the CLI, so an assessment can chain capabilities and
a test can call them directly.

An assessment is fail-closed. A step reports `not_vulnerable` only with positive proof that the
target refused the attack (a rejection the target logs, for example). A step that could not tell
reports `inconclusive` or `error`, never a clean result.

In OSDP every attack is one module in `src/interlock/osdp/attacks/` with a `run_*` library
function and a `register(app)` function that adds its subcommand.
`src/interlock/osdp/attacks/__init__.py` holds `build_osdp_app`, the `interlock.commands`
factory, which discovers every sibling module that exposes `register()`, so a new attack is a new
file. The one-command assessment, with its fail-closed statuses, is
`src/interlock/osdp/assessment.py`, and `src/interlock/osdp/attacks/assess.py` is its command.

### ATT&CK mapping

Keep every MITRE ATT&CK id the module cites in one module, as the single source, and pin the
ATT&CK version it was mapped against. A finding's `attack_technique` is the primary Enterprise
technique id. `attack_technique_ics` is an optional secondary ATT&CK for ICS id, set only where
an ICS technique genuinely fits.

In OSDP that module is `src/interlock/osdp/attack_map.py`: `MAPPINGS` from attack to technique,
`ATTACK_VERSION` (`"20.0"`), `ACCESS_VECTOR` for the engagement-level technique (T1200, a device
added to the bus) and `technique_names()` for the report.

### Report via Finding

Every result is a `Finding` from `src/interlock/plugin.py`: `id`, `title`, `severity` (a
`Severity` member: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `evidence`,
`attack_technique`, `remediation` and the optional `attack_technique_ics`. `finding_to_dict` and
`finding_from_dict` give a strict plain-dict form, for JSON and for findings read back from a lab
container.

Write reports through `src/interlock/report.py`. `write_markdown` and `write_json` put the
authorized-use notice (`AUTHORIZED_USE_NOTICE`) at the top of every report, and neither can turn
it off. `interlock run` uses `write_markdown`, so a plugin that only has `run()` gets the notice
for free.

## Safety obligations every plugin inherits

interlock is dual-use: it can open doors. Every plugin keeps the same rules the OSDP module
follows.

- **Lab-only by default.** With no extra flag, every capability targets the bundled lab.
- **Real hardware only through a consent gate.** A capability that can reach real equipment
  does so only behind an explicit flag (`--physical` in OSDP), a disclaimer and a typed scope
  confirmation that must match exactly. Route it through a gate like
  `src/interlock/osdp/attacks/safety.py`, where `open_physical_endpoint` is the single helper
  that opens a real port and there is no environment variable or option that skips the prompt.
- **No vendor default production keys.** Do not ship them in code, tests or fixtures. The
  repository's `tests/test_safe03.py` scans tracked Python files for 16-byte key literals outside
  a short allow-list. That test is a check, not a guarantee, so review key material yourself.
- **The authorized-use notice in every report.** Use `report.write_markdown` and
  `report.write_json`, or carry `AUTHORIZED_USE_NOTICE` verbatim in any other format you write.

Use the tool only on equipment you own or are authorized in writing to assess. Unauthorized
access to another party's system is a criminal offence (for example art. 267 k.k. in Poland).

## Minimal worked example

`docs/examples/minimal-plugin` is a complete third-party plugin. It does nothing offensive and
touches no network, port or device: it returns one informational finding and adds one command
that prints text. A test installs it and runs it through the real CLI, and checks that the two
files below are identical to the ones in that directory, so this page cannot drift from working
code.

Its `pyproject.toml` declares both entry points:

<!-- example:start docs/examples/minimal-plugin/pyproject.toml -->
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "interlock-example"
version = "0.0.0"
description = "The minimal interlock plugin from the plugin-authoring guide."
requires-python = ">=3.11"
dependencies = ["interlock"]

# The plugin object: listed by `interlock plugins`, run by `interlock run example`.
[project.entry-points."interlock.plugins"]
example = "interlock_example:ExamplePlugin"

# The command group: attached as `interlock example`.
[project.entry-points."interlock.commands"]
example = "interlock_example:build_example_app"

[tool.hatch.build.targets.wheel]
packages = ["src/interlock_example"]
```
<!-- example:end -->

The package holds the plugin class and the command-group factory:

<!-- example:start docs/examples/minimal-plugin/src/interlock_example/__init__.py -->
```python
"""The minimal third-party interlock plugin from the plugin-authoring guide.

This file is copied into docs/plugin-authoring.md verbatim, and a test keeps the two
identical. It shows both halves of the contract a package can declare in its own
pyproject.toml:

- ``ExamplePlugin``, registered in the ``interlock.plugins`` group: a class with a
  ``name``, a one-line ``summary`` and a ``run`` method returning findings.
- ``build_example_app``, registered in the ``interlock.commands`` group: a
  zero-argument factory returning the ``typer.Typer`` attached as ``interlock example``.

The example does nothing offensive and touches no network, port or device. It returns
one informational finding and prints text.
"""

from __future__ import annotations

import typer

from interlock.plugin import Finding, Severity


class ExamplePlugin:
    """A plugin that returns one informational finding."""

    name = "example"
    summary = "The minimal plugin from the plugin-authoring guide."

    def run(
        self,
        target: str | None = None,
        options: dict[str, object] | None = None,
    ) -> list[Finding]:
        return [
            Finding(
                id="EXAMPLE-001",
                title="the example plugin was discovered and run",
                severity=Severity.INFO,
                evidence="interlock loaded this plugin from its entry point; it has no effect.",
                attack_technique="T1200",
                remediation="None required; this is a self-test with no effect.",
            )
        ]


def build_example_app() -> typer.Typer:
    """Return the ``interlock example`` command group."""
    app = typer.Typer(no_args_is_help=True, help="The example plugin's commands.")

    @app.command()
    def info() -> None:
        """Print what the example plugin is."""
        typer.echo(ExamplePlugin.summary)

    return app
```
<!-- example:end -->

To try it, install interlock and the example into the same virtual environment from the
repository root, then call the three commands it answers.

macOS and Linux (zsh):

```zsh
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/pip install -e docs/examples/minimal-plugin
.venv/bin/interlock plugins
.venv/bin/interlock run example -o example-report.md
.venv/bin/interlock example info
```

Windows (PowerShell 5.1):

```powershell
py -m venv .venv
.venv\Scripts\pip install -e .
.venv\Scripts\pip install -e docs\examples\minimal-plugin
.venv\Scripts\interlock plugins
.venv\Scripts\interlock run example -o example-report.md
.venv\Scripts\interlock example info
```

The Windows path has not yet been run on a Windows machine.

`interlock plugins` lists `example` next to `demo`, `interlock run example` prints the finding and
writes a report that opens with the authorized-use notice, and `interlock example info` prints the
plugin summary. To start your own plugin, copy the directory, rename the package, the class, the
entry-point names and the project name, and replace the finding with real work.

The in-tree minimal plugin is `demo`, in `src/interlock/plugins/demo.py`: the same shape without
a command group, registered in interlock's own `pyproject.toml`.

## Full worked example: OSDP

The OSDP module is a complete protocol plugin, with every part of the contract in place:

| Part | Files |
|------|-------|
| Lab | `lab/osdp/pd_driver.py`, `lab/osdp/cp_driver.py`, `lab/osdp/scenarios.py`, `Dockerfile`, `docker-compose.yml` and its `docker-compose.*.yml` overrides, `src/interlock/osdp/lab_session.py` |
| Attack and assessment | `src/interlock/osdp/attacks/` (one module per attack, each with `register(app)` and a `run_*` function), `src/interlock/osdp/attacks/__init__.py` (`build_osdp_app`), `src/interlock/osdp/assessment.py` and its command `src/interlock/osdp/attacks/assess.py` |
| ATT&CK mapping | `src/interlock/osdp/attack_map.py` |
| Report via Finding | `src/interlock/plugin.py`, `src/interlock/report.py` |
| Safety | `src/interlock/osdp/attacks/safety.py`, `tests/test_safe03.py` |
| Registration | `pyproject.toml` (`osdp` in `interlock.commands`) |

## Stability

The public surface for plugin authors is `interlock.plugin`: `Finding`, `Severity`, `Plugin`,
`finding_to_dict` and `finding_from_dict`. The entry-point group names `interlock.plugins` and
`interlock.commands` are part of it. interlock is at 0.x, and 0.x releases may still change this
surface before 1.0. Pin the interlock version your plugin was written against.
