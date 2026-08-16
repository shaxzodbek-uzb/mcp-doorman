"""The core import graph must stay dependency-light; the integration fails loudly."""

from __future__ import annotations

import importlib
import importlib.metadata
import sys

import pytest


def test_core_does_not_import_mcp_or_fastapi():
    # Drop any pre-imported SDKs, import the core fresh, and assert it pulled in neither.
    for mod in list(sys.modules):
        if mod == "mcp" or mod.startswith("mcp.") or mod == "fastapi" or mod.startswith("fastapi."):
            del sys.modules[mod]
    for mod in list(sys.modules):
        if mod == "mcp_doorman" or mod.startswith("mcp_doorman."):
            del sys.modules[mod]
    importlib.import_module("mcp_doorman")
    assert "mcp" not in sys.modules
    assert "fastapi" not in sys.modules


def test_all_exports_are_importable():
    import mcp_doorman

    # Against the packaged metadata rather than a literal, so this catches the two
    # drifting apart without needing an edit at every release.
    assert mcp_doorman.__version__ == importlib.metadata.version("mcp-doorman")
    for name in mcp_doorman.__all__:
        assert hasattr(mcp_doorman, name), f"missing export: {name}"


def test_integration_lazy_import_errors_without_mcp():
    if importlib.util.find_spec("mcp") is not None:
        pytest.skip("mcp extra is installed; lazy-error path not exercised")
    from mcp_doorman import Doorman
    from mcp_doorman.errors import DoormanError
    from mcp_doorman.integrations import fastmcp

    d = Doorman(audit="none")
    with pytest.raises(DoormanError) as ei:
        fastmcp.build_server(d)
    assert "mcp-doorman[mcp]" in str(ei.value)
