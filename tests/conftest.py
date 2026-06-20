"""Shared fixtures. Every test here runs offline — no network, no mcp/fastapi required."""

from __future__ import annotations

import pytest

from mcp_doorman import (
    AccessToken,
    AuditRecord,
    Principal,
    StaticVerifier,
    ToolSpec,
    Transport,
)
from mcp_doorman.auth import oauth


class RecordingSink:
    """An :class:`AuditSink` that keeps every record for assertions."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def emit(self, record: AuditRecord) -> None:
        self.records.append(record)

    @property
    def last(self) -> AuditRecord:
        return self.records[-1]


@pytest.fixture
def sink() -> RecordingSink:
    return RecordingSink()


def _get_invoice(id: str) -> dict:
    """Return an invoice (read-only)."""
    return {"id": id, "email": "alice@example.com", "amount": 42.0}


def _refund(id: str, amount: float) -> dict:
    """Issue a refund (destructive)."""
    return {"id": id, "refunded": amount, "card_number": "4111 1111 1111 1111"}


@pytest.fixture
def read_spec() -> ToolSpec:
    return ToolSpec(
        name="get_invoice",
        handler=_get_invoice,
        methods=frozenset({"GET"}),
        description="read an invoice",
        scopes=("invoices:read",),
        read_only=True,
    )


@pytest.fixture
def write_spec() -> ToolSpec:
    return ToolSpec(
        name="refund",
        handler=_refund,
        methods=frozenset({"POST"}),
        description="issue a refund",
        scopes=("invoices:write",),
        destructive=True,
        read_only=False,
    )


@pytest.fixture
def public_spec() -> ToolSpec:
    return ToolSpec(
        name="ping",
        handler=lambda: {"ok": True},
        methods=frozenset({"GET"}),
        scopes=(),
        read_only=True,
    )


@pytest.fixture
def verified_reader() -> Principal:
    return Principal(
        subject="user-1",
        scopes=frozenset({"invoices:read"}),
        tenant="acme",
        transport=Transport.HTTP,
        verified=True,
    )


@pytest.fixture
def stdio_caller() -> Principal:
    """A STDIO call with no token: unverified by construction."""
    return Principal(subject="", transport=Transport.STDIO, verified=False)


@pytest.fixture
def auth_config():
    verifier = StaticVerifier(
        {
            "tok-reader": AccessToken(
                subject="user-1",
                scopes=frozenset({"invoices:read"}),
                audience=("https://api.example.com/mcp",),
                tenant="acme",
            ),
            "tok-wrong-aud": AccessToken(
                subject="user-2",
                scopes=frozenset({"invoices:read"}),
                audience=("https://other.example.com/mcp",),
            ),
        }
    )
    return oauth(
        issuer="https://sso.example.com",
        resource="https://api.example.com/mcp",
        verifier=verifier,
    )
