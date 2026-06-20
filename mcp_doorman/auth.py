"""Resource-server auth seam: audience binding + scope, no network in the core.

``mcp-doorman`` is an OAuth 2.1 *resource server*, not an authorization server. You bring
an external AS (Auth0 / Keycloak / blaze-sso); the core validates that an inbound token's
audience matches *this* server (RFC 8707 / 9068) so a token minted for another MCP server
cannot be replayed here, and exposes the RFC 9728 metadata body for discovery. A real
JWKS/introspection :class:`TokenVerifier` is provided by the integration or by the user.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .errors import Unauthorized


@dataclass(frozen=True)
class AccessToken:
    """The validated claims a :class:`TokenVerifier` returns."""

    subject: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    audience: tuple[str, ...] = ()
    tenant: str | None = None
    raw: str | None = None


@runtime_checkable
class TokenVerifier(Protocol):
    """Validates a raw bearer token, raising :class:`Unauthorized` on any failure."""

    def verify(self, token: str) -> AccessToken: ...


@dataclass(frozen=True)
class AuthConfig:
    """How this resource server validates tokens and advertises discovery."""

    issuer: str
    resource: str
    required_scopes: tuple[str, ...] = ()
    tenant_claim: str = "tenant_id"
    verifier: TokenVerifier | None = None

    def metadata(self) -> dict:
        """RFC 9728 Protected Resource Metadata body."""
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": list(self.required_scopes),
            "bearer_methods_supported": ["header"],
        }

    def check_audience(self, token: AccessToken) -> None:
        """Fail closed unless this server's ``resource`` is in the token audience.

        An empty audience is rejected when a ``resource`` is configured — a token that
        does not name its intended resource must not be honored here.
        """
        if not self.resource:
            return
        if not token.audience:
            raise Unauthorized(
                f"token carries no audience; expected {self.resource!r} (RFC 8707) — "
                "refusing a token that does not name this resource"
            )
        if self.resource not in token.audience:
            raise Unauthorized(
                f"token audience {list(token.audience)} does not include {self.resource!r}; "
                "a token minted for another resource cannot be replayed here"
            )


class StaticVerifier:
    """In-memory verifier for tests/dev: maps opaque token strings to :class:`AccessToken`."""

    def __init__(self, tokens: dict[str, AccessToken]) -> None:
        self._tokens = dict(tokens)

    def verify(self, token: str) -> AccessToken:
        try:
            return self._tokens[token]
        except KeyError:
            raise Unauthorized("unknown or expired token") from None


def oauth(
    *,
    issuer: str,
    resource: str,
    required_scopes: Sequence[str] = (),
    tenant_claim: str = "tenant_id",
    verifier: TokenVerifier | None = None,
) -> AuthConfig:
    """Build an :class:`AuthConfig`. Exposed as ``Doorman.oauth``."""
    return AuthConfig(
        issuer=issuer,
        resource=resource,
        required_scopes=tuple(required_scopes),
        tenant_claim=tenant_claim,
        verifier=verifier,
    )
