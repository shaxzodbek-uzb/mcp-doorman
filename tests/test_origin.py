"""Origin / DNS-rebinding guard. Pure-stdlib helper — no mcp extra required."""

from __future__ import annotations

from mcp_doorman.integrations.fastmcp import _origin_allowed


def _scope(origin: str | None = None):
    headers = []
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    return {"type": "http", "headers": headers}


def test_no_origin_header_is_allowed():
    # Non-browser MCP clients send no Origin; nothing to forge.
    assert _origin_allowed(_scope(None), frozenset()) is True


def test_localhost_allowed_by_default():
    assert _origin_allowed(_scope("http://localhost:5173"), frozenset()) is True
    assert _origin_allowed(_scope("http://127.0.0.1"), frozenset()) is True


def test_cross_origin_blocked_by_default():
    assert _origin_allowed(_scope("https://evil.example"), frozenset()) is False


def test_allowlist_enforced_when_configured():
    allowed = frozenset({"https://app.example.com"})
    assert _origin_allowed(_scope("https://app.example.com"), allowed) is True
    assert _origin_allowed(_scope("http://localhost:5173"), allowed) is False  # not in list
    assert _origin_allowed(_scope("https://evil.example"), allowed) is False
