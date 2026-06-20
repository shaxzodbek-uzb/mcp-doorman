"""Deny-by-default exposure: the single chokepoint that decides what becomes a tool.

A FastAPI route is **never** an MCP tool unless it carries the marker stamped by
:func:`expose`. Destructive HTTP methods refuse to be exposed without an explicit
``destructive=True`` acknowledgement, and that flag drives the MCP ``destructiveHint``
annotation so client safety UIs can gate side-effecting calls.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from .errors import ConfigError, DestructiveNotAllowed, NotExposed

#: HTTP methods that mutate state. Exposing any of these requires ``destructive=True``.
DESTRUCTIVE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Attribute name used to mark a route handler as exposed (a dict of expose() kwargs).
_MARKER = "_doorman_expose"


@dataclass(frozen=True)
class ToolSpec:
    """Everything the bridge needs to publish (and guard) one tool."""

    name: str
    handler: Callable
    methods: frozenset[str]
    description: str = ""
    scopes: tuple[str, ...] = ()
    destructive: bool = False
    read_only: bool = True
    redact: tuple[str, ...] = ()
    rate: str | None = None

    def annotations(self) -> dict:
        """MCP tool annotations a client can use to gate calls."""
        return {"readOnlyHint": self.read_only, "destructiveHint": self.destructive}


def expose(
    *,
    name: str | None = None,
    scopes: Sequence[str] = (),
    destructive: bool = False,
    description: str | None = None,
    redact: Sequence[str] = (),
    rate: str | None = None,
) -> Callable:
    """Mark a FastAPI route handler as an MCP tool (deny-by-default opt-in).

    The decorator stamps the kwargs onto the function via the ``_doorman_expose``
    attribute and returns the function **unchanged**, so it still works as an ordinary
    FastAPI route regardless of decorator order. Destructive-method enforcement happens
    later, in :meth:`Registry.add_route`, where the route's HTTP methods are known.
    """

    def decorator(func: Callable) -> Callable:
        setattr(
            func,
            _MARKER,
            {
                "name": name or func.__name__,
                "scopes": tuple(scopes),
                "destructive": bool(destructive),
                "description": description,
                "redact": tuple(redact),
                "rate": rate,
            },
        )
        return func

    return decorator


def _marker(handler: Callable) -> dict | None:
    """Return the expose() marker for ``handler``, unwrapping ``functools.wraps``."""
    seen = set()
    cur = handler
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        marker = getattr(cur, _MARKER, None)
        if marker is not None:
            return marker
        cur = getattr(cur, "__wrapped__", None)
    return None


class Registry:
    """Deny-by-default tool registry. Only ``@expose``'d routes become tools."""

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}

    def add_route(self, *, handler: Callable, methods: Iterable[str]) -> ToolSpec | None:
        """Build and store a :class:`ToolSpec` if ``handler`` is exposed.

        Returns ``None`` for an unexposed handler (the deny-by-default path). Raises
        :class:`DestructiveNotAllowed` when a destructive method is exposed without
        ``destructive=True``, and :class:`ConfigError` on a duplicate tool name.
        """
        marker = _marker(handler)
        if marker is None:
            return None

        method_set = frozenset(m.upper() for m in methods)
        # Fail-closed: an exposed route with no determinable methods is treated as
        # side-effecting (read_only=False), so it cannot register as a "safe" tool
        # without an explicit destructive=True acknowledgement.
        read_only = bool(method_set) and method_set.isdisjoint(DESTRUCTIVE_METHODS)
        if not read_only and not marker["destructive"]:
            offending = sorted(method_set & DESTRUCTIVE_METHODS) or "an undetermined method"
            raise DestructiveNotAllowed(
                f"tool {marker['name']!r} exposes a destructive/unknown method "
                f"({offending}) but expose(destructive=True) was not set; refusing to "
                "publish a side-effecting tool implicitly"
            )

        spec = ToolSpec(
            name=marker["name"],
            handler=handler,
            methods=method_set,
            description=marker["description"] or (handler.__doc__ or "").strip(),
            scopes=marker["scopes"],
            destructive=marker["destructive"],
            read_only=read_only,
            redact=marker["redact"],
            rate=marker["rate"],
        )
        if spec.name in self._specs:
            raise ConfigError(f"duplicate tool name {spec.name!r}")
        self._specs[spec.name] = spec
        return spec

    def add(self, spec: ToolSpec) -> None:
        """Register a pre-built :class:`ToolSpec` directly (the offline/testing path)."""
        if spec.name in self._specs:
            raise ConfigError(f"duplicate tool name {spec.name!r}")
        self._specs[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        """Return the spec for ``name`` or raise :class:`NotExposed`."""
        try:
            return self._specs[name]
        except KeyError:
            raise NotExposed(f"no exposed tool named {name!r}") from None

    def __contains__(self, name: str) -> bool:
        return name in self._specs

    def names(self) -> list[str]:
        return list(self._specs)

    def specs(self) -> list[ToolSpec]:
        return list(self._specs.values())
