"""SAFE-02: the physical-mode consent gate guarding the one real RS-485 path.

interlock defaults every capability at the bundled software lab (SAFE-01). The only
code path that can transmit onto real hardware is ``transport.open_serial_endpoint``,
and this module is the single guarded door in front of it. ``open_physical_endpoint``
is the one helper every subcommand's ``--physical`` branch must route through: it calls
``require_physical_consent`` first, and no byte reaches a real port until the operator
types the exact scope/consent phrase.

The comparison is exact string equality - no case-folding, no whitespace stripping,
no unicode normalization - mirroring ``scenarios.get``: a wrong-case, padded, empty, or
whitespace-only answer is a mismatch and fails closed with a ``ConsentError``. There is
deliberately no env var, flag, or kwarg that skips the prompt (D-04): the gate has no
automation escape hatch, so CI and the test suite exercise attacks against the lab
(TCP/pty, which never reaches this gate) and unit-test the gate itself through the
``input_fn`` / ``output_fn`` seams. This is the series' published dual-use safety
contract (D-03); its shape is authored once here.

Legal framing: interlock is for authorized, lab-only, or explicitly consented
assessment. Unauthorized access to another party's system is a criminal offence (e.g.
art. 267 k.k. in Poland, and equivalents elsewhere). The disclaimer restates this
before any physical transmission.

This module is not an attack subcommand: it exposes no ``register()`` and is skipped by
the ``build_osdp_app()`` auto-discovery seam.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from interlock.osdp import transport

if TYPE_CHECKING:
    import serial  # type: ignore[import-untyped]  # pyserial ships no type stubs

DISCLAIMER = (
    "interlock PHYSICAL MODE - real RS-485 transmission\n"
    "This will transmit on a real OSDP bus and may unlock doors, disrupt readers, or\n"
    "disturb a live access-control system. Use it ONLY against hardware you own or are\n"
    "explicitly authorized in writing to assess. Unauthorized access is a criminal\n"
    "offence (e.g. art. 267 k.k. in Poland; equivalents elsewhere). The bundled\n"
    "software lab is the default for every capability - nothing here is needed to\n"
    "practise against it."
)


class ConsentError(RuntimeError):
    """Physical-mode consent was not given exactly; the gate fails closed.

    Raised by ``require_physical_consent`` on any mismatch (wrong, empty,
    whitespace-only, wrong-case, or whitespace-padded phrase). No real port is opened
    when this is raised: nothing has been transmitted.
    """


def required_consent_phrase(target: str) -> str:
    """Return the exact phrase the operator must type to consent to ``target``.

    Binding the phrase to the target makes consent scope-specific: typing it
    acknowledges authorization for this exact target, not physical mode in general.
    """
    return f"I am authorized to assess {target}"


def require_physical_consent(
    target: str,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> None:
    """Print the disclaimer and require the exact typed consent phrase for ``target``.

    Reads one line via ``input_fn`` and compares it to ``required_consent_phrase`` by
    exact string equality - no strip, no casefold, no normalization (mirrors
    ``scenarios.get``). Any mismatch raises ``ConsentError`` and the caller fails closed:
    no byte reaches a real port. ``input_fn`` / ``output_fn`` exist only so the gate is
    unit-testable; there is no env var, flag, or kwarg that skips the prompt (D-04).
    """
    output_fn(DISCLAIMER)
    required = required_consent_phrase(target)
    output_fn(f'To proceed against "{target}", type this phrase exactly: {required}')
    response = input_fn("consent> ")
    if response != required:
        raise ConsentError(
            "physical-mode consent phrase did not match exactly - aborting; "
            "no byte was transmitted to a real port"
        )


def open_physical_endpoint(
    device_path: str,
    target: str,
    *,
    baudrate: int = 9600,
    timeout: float = 1.0,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> serial.Serial:
    """Open the one real serial endpoint, but only after physical consent succeeds.

    This is the single real-port helper every ``--physical`` branch must call.
    ``require_physical_consent`` runs first; if the operator's phrase does not match
    exactly it raises ``ConsentError`` and ``transport.open_serial_endpoint`` is never
    reached. On success it returns the pyserial endpoint bound to ``device_path``.
    """
    require_physical_consent(target, input_fn=input_fn, output_fn=output_fn)
    return transport.open_serial_endpoint(device_path, baudrate=baudrate, timeout=timeout)
