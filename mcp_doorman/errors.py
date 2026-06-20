"""Exception hierarchy for mcp-doorman.

Every error is a :class:`DoormanError`. The auth/rate errors carry the HTTP/MCP
status they map to in their docstrings so the integration layer can translate them
without a lookup table.
"""

from __future__ import annotations


class DoormanError(Exception):
    """Base class for every error raised by mcp-doorman."""


class NotExposed(DoormanError):
    """A tool name was requested that is not in the deny-by-default registry."""


class DestructiveNotAllowed(DoormanError):
    """``expose()`` on a destructive HTTP method without ``destructive=True``."""


class Unauthorized(DoormanError):
    """Maps to 401 — no verified principal where one is required (fail-closed)."""


class Forbidden(DoormanError):
    """Maps to 403 — the verified principal lacks the required scope(s)."""


class RateLimited(DoormanError):
    """Per-caller or per-tool token bucket exhausted.

    Carries ``retry_after`` (seconds) so the caller can back off.
    """

    def __init__(self, message: str, *, retry_after: float) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ConfigError(DoormanError):
    """Invalid configuration (e.g. a remote bind with no auth, or a bad rate spec)."""
