"""Live wire tests against the real ``mcp`` SDK. Skipped unless the [mcp] extra is present.

These prove the five guarantees hold on the actual MCP wire, not just in the offline core:
``tools/list`` carries the right annotations, and ``tools/call`` on a scoped tool with no
auth context fails CLOSED — the headline fix vs other bridges.
"""

from __future__ import annotations

import importlib.util

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("mcp") is None, reason="requires the [mcp] extra"
)


def _build():
    from mcp_doorman import Doorman, StaticVerifier, ToolSpec
    from mcp_doorman.integrations.fastmcp import build_server

    doorman = Doorman(
        auth=Doorman.oauth(issuer="https://i", resource="https://r", verifier=StaticVerifier({})),
        audit="none",
        rate_limit=None,
    )
    doorman.register(
        ToolSpec(
            name="get_invoice",
            handler=lambda invoice_id: {"id": invoice_id, "email": "a@b.com"},
            methods=frozenset({"GET"}),
            description="read an invoice",
            scopes=("invoices:read",),
        )
    )
    doorman.register(
        ToolSpec(
            name="delete_invoice",
            handler=lambda invoice_id: {"deleted": invoice_id},
            methods=frozenset({"DELETE"}),
            scopes=("invoices:write",),
            destructive=True,
            read_only=False,
        )
    )
    return build_server(doorman)


async def test_list_tools_emits_annotations():
    import mcp.types as t

    server = _build()
    handler = server.request_handlers[t.ListToolsRequest]
    res = await handler(t.ListToolsRequest(method="tools/list"))
    tools = {tool.name: tool for tool in res.root.tools}
    assert tools["get_invoice"].annotations.readOnlyHint is True
    assert tools["get_invoice"].annotations.destructiveHint is False
    assert tools["delete_invoice"].annotations.destructiveHint is True
    # inputSchema derived from the handler signature
    assert "invoice_id" in tools["get_invoice"].inputSchema["properties"]


async def test_call_tool_fails_closed_without_auth():
    import mcp.types as t

    server = _build()
    handler = server.request_handlers[t.CallToolRequest]
    req = t.CallToolRequest(
        method="tools/call",
        params=t.CallToolRequestParams(name="get_invoice", arguments={"invoice_id": "INV-1"}),
    )
    res = await handler(req)
    text = res.root.content[0].text
    assert "denied" in text.lower()
    assert "fail-closed" in text.lower()
