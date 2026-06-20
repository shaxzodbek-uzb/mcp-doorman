"""The verified caller identity that flows through the guard pipeline.

A :class:`Principal` is *trusted* only when ``verified is True`` — that flag is set
exclusively by a :class:`~mcp_doorman.auth.TokenVerifier`. An anonymous caller, or a
STDIO call with no token, produces an **unverified** principal, which the scope check
(:func:`mcp_doorman.scopes.authorize`) treats as fail-closed.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum


class Transport(str, Enum):
    """How the call reached us. STDIO carries no auth context by construction."""

    HTTP = "http"
    STDIO = "stdio"


@dataclass(frozen=True)
class Principal:
    """A caller identity. ``verified`` gates every scope decision."""

    subject: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    tenant: str | None = None
    transport: Transport = Transport.HTTP
    verified: bool = False

    def has_scopes(self, required: Iterable[str]) -> bool:
        """True iff every required scope is present. Empty ``required`` -> True."""
        return set(required).issubset(self.scopes)


#: The default unverified caller. A STDIO call with no token resolves to a principal
#: like this one — ``verified=False`` — so scoped tools fail closed.
ANONYMOUS = Principal(subject="", verified=False)
