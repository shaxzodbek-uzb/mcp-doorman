"""mcp-doorman — a secure-by-default FastAPI→MCP bridge.

FastMCP gives you the tools; this gives you the seatbelts. Deny-by-default exposure,
scope→tool authorization that fails closed (even on STDIO), built-in rate limiting, PII
redaction at the source, and a structured audit log — in-process, no gateway.

Importing this package pulls in **no** ``mcp`` or FastAPI SDK; the transport wiring lives
behind the optional ``[mcp]`` extra and is lazy-imported by :meth:`Doorman.mount`.
"""

from __future__ import annotations

from .audit import AuditRecord, AuditSink, NullSink, StderrSink, make_sink, shape
from .auth import AccessToken, AuthConfig, StaticVerifier, TokenVerifier, oauth
from .config import Settings
from .doorman import Doorman
from .errors import (
    ConfigError,
    DestructiveNotAllowed,
    DoormanError,
    Forbidden,
    NotExposed,
    RateLimited,
    Unauthorized,
)
from .exposure import Registry, ToolSpec, expose
from .principal import ANONYMOUS, Principal, Transport
from .ratelimit import RateLimiter, TokenBucket, parse_rate_spec
from .redaction import REDACTED, Redactor
from .scopes import authorize

__version__ = "0.1.0"

__all__ = [
    "Doorman",
    "expose",
    "ToolSpec",
    "Registry",
    "Principal",
    "Transport",
    "ANONYMOUS",
    "authorize",
    "RateLimiter",
    "TokenBucket",
    "parse_rate_spec",
    "Redactor",
    "REDACTED",
    "AuditRecord",
    "shape",
    "AuditSink",
    "StderrSink",
    "NullSink",
    "make_sink",
    "AccessToken",
    "TokenVerifier",
    "StaticVerifier",
    "AuthConfig",
    "oauth",
    "Settings",
    "DoormanError",
    "NotExposed",
    "DestructiveNotAllowed",
    "Unauthorized",
    "Forbidden",
    "RateLimited",
    "ConfigError",
    "__version__",
]
