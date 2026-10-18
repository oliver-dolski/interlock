"""SAFE-02 physical-consent gate: fail-closed exact-match, no bypass to a real port.

Host-local (no Docker, no ``lab`` marker) proof of the one safety-critical control in
Phase 4. The gate (``require_physical_consent``) allows only on an exactly-typed consent
phrase and raises ``ConsentError`` on anything else - wrong, empty, whitespace-only,
wrong-case, or whitespace-padded. The real-port helper (``open_physical_endpoint``) is
proven to call the gate first: with ``transport.open_serial_endpoint`` mocked, a wrong
phrase never reaches the serial open, and a correct phrase reaches it exactly once.
"""

from __future__ import annotations

from unittest import mock

import pytest

from interlock.osdp.attacks import safety

TARGET = "lab-pd-101"
GOOD = safety.required_consent_phrase(TARGET)


def _answer(value: str) -> object:
    """Return an input_fn that always answers ``value`` and swallows the prompt."""
    return lambda _prompt: value


def test_correct_phrase_allows() -> None:
    # No exception means consent was granted.
    safety.require_physical_consent(TARGET, input_fn=_answer(GOOD), output_fn=lambda _msg: None)


@pytest.mark.parametrize(
    "bad",
    [
        "no",  # wrong
        "",  # empty
        "   ",  # whitespace-only
        GOOD.upper(),  # wrong-case
        f" {GOOD} ",  # whitespace-padded
        GOOD + "\n",  # trailing newline (no stripping)
    ],
)
def test_wrong_phrase_fails_closed(bad: str) -> None:
    with pytest.raises(safety.ConsentError):
        safety.require_physical_consent(TARGET, input_fn=_answer(bad), output_fn=lambda _msg: None)


def test_wrong_phrase_never_reaches_the_serial_open() -> None:
    with mock.patch.object(safety.transport, "open_serial_endpoint") as serial_open:
        with pytest.raises(safety.ConsentError):
            safety.open_physical_endpoint(
                "/dev/ttyUSB0",
                TARGET,
                input_fn=_answer("wrong"),
                output_fn=lambda _msg: None,
            )
        assert serial_open.call_count == 0, "serial open reached on wrong phrase"


def test_correct_phrase_reaches_the_serial_open_once() -> None:
    sentinel = object()
    with mock.patch.object(
        safety.transport, "open_serial_endpoint", return_value=sentinel
    ) as serial_open:
        result = safety.open_physical_endpoint(
            "/dev/ttyUSB0",
            TARGET,
            input_fn=_answer(GOOD),
            output_fn=lambda _msg: None,
        )
    assert result is sentinel
    assert serial_open.call_count == 1, "wrong call count for the serial open on correct phrase"
    serial_open.assert_called_once_with("/dev/ttyUSB0", baudrate=9600, timeout=1.0)


def test_disclaimer_is_printed_before_the_prompt() -> None:
    printed: list[str] = []
    safety.require_physical_consent(
        TARGET, input_fn=_answer(GOOD), output_fn=lambda msg: printed.append(msg)
    )
    assert any("PHYSICAL MODE" in msg for msg in printed)
    assert any("art. 267 k.k." in msg for msg in printed)
