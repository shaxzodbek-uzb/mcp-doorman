"""Fail-closed scope authorization — the single most important security primitive.

The headline guarantee lives here: a tool that declares ``scopes`` is denied unless the
caller presents a **verified** principal whose scopes are a superset. When there is no
verified context — no token, or a STDIO call where other bridges silently return ``None``
and bypass every check — :func:`authorize` raises instead of allowing.
"""

from __future__ import annotations

from .errors import Forbidden, Unauthorized
from .exposure import ToolSpec
from .principal import Principal


def authorize(spec: ToolSpec, principal: Principal) -> None:
    """Raise unless ``principal`` may call ``spec``. Pure; no I/O.

    Rules, in order:

    1. ``spec.scopes`` empty -> allow (a public tool; still rate-limited and audited).
    2. ``principal`` must be verified, else :class:`Unauthorized`. This is the
       STDIO/no-token fail-closed guarantee: an unverified principal can never satisfy a
       scoped tool.
    3. The principal must hold every required scope, else :class:`Forbidden`.
    """
    if not spec.scopes:
        return
    if not principal.verified:
        raise Unauthorized(
            f"tool {spec.name!r} requires scopes {list(spec.scopes)} but the caller is "
            "not authenticated (no verified token / stdio transport) — denying fail-closed"
        )
    if not principal.has_scopes(spec.scopes):
        missing = sorted(set(spec.scopes) - set(principal.scopes))
        raise Forbidden(
            f"tool {spec.name!r} requires scopes {list(spec.scopes)}; "
            f"caller is missing {missing}"
        )
