"""The headline guarantee: scope authorization fails closed, including on STDIO."""

from __future__ import annotations

import pytest

from mcp_doorman import Principal, Transport, authorize
from mcp_doorman.errors import Forbidden, Unauthorized


def test_unscoped_tool_allows_anonymous(public_spec):
    authorize(public_spec, Principal(subject="", verified=False))  # no raise


def test_scoped_tool_denies_unverified(read_spec):
    unverified = Principal(subject="x", scopes=frozenset({"invoices:read"}), verified=False)
    with pytest.raises(Unauthorized):
        authorize(read_spec, unverified)


def test_scoped_tool_denies_stdio(read_spec, stdio_caller):
    # The bypass fix: a stdio call carries no verified context -> deny, never allow.
    with pytest.raises(Unauthorized):
        authorize(read_spec, stdio_caller)


def test_scoped_tool_denies_missing_scope(read_spec):
    principal = Principal(subject="u", scopes=frozenset({"other:read"}), verified=True)
    with pytest.raises(Forbidden):
        authorize(read_spec, principal)


def test_scoped_tool_allows_sufficient(read_spec, verified_reader):
    authorize(read_spec, verified_reader)  # no raise


@pytest.mark.parametrize(
    "verified,scopes,transport",
    [
        (False, set(), Transport.HTTP),
        (False, {"invoices:read"}, Transport.HTTP),
        (False, {"invoices:read"}, Transport.STDIO),
        (True, set(), Transport.HTTP),
        (True, {"wrong"}, Transport.HTTP),
        (True, {"invoices:read"}, Transport.STDIO),  # verified stdio with the scope is OK
    ],
)
def test_no_input_bypasses_a_scoped_tool(read_spec, verified, scopes, transport):
    principal = Principal(
        subject="u", scopes=frozenset(scopes), transport=transport, verified=verified
    )
    allowed = verified and {"invoices:read"}.issubset(scopes)
    if allowed:
        authorize(read_spec, principal)
    else:
        with pytest.raises((Unauthorized, Forbidden)):
            authorize(read_spec, principal)
