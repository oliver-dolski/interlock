"""Unit coverage for the entry-point plugin registry (CORE-02)."""

from __future__ import annotations

import pytest

from interlock import registry
from interlock.plugin import Finding, Plugin


def test_discover_includes_demo() -> None:
    plugins = registry.discover()
    assert "demo" in plugins


def test_get_demo_returns_plugin_yielding_one_finding() -> None:
    plugin = registry.get("demo")
    assert isinstance(plugin, Plugin)

    findings = plugin.run()
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert isinstance(findings[0], Finding)


def test_get_unknown_plugin_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        registry.get("nope")
