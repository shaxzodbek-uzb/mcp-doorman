"""Structured audit — one OTel-friendly record per invocation, values never logged.

The defining property is :func:`shape`: it records the *structure* of arguments (container
types, lengths, counts) and **neither values nor caller-controlled keys**. Dict keys are
treated as untrusted data (a tool taking a free-form mapping could be called with a secret
or email as a key), so they are summarized by count, not emitted verbatim. That is what
makes the audit safe to ship to a log sink or trace collector without leaking PII.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

_MAX_DEPTH = 4


def shape(obj: Any, *, _depth: int = 0) -> Any:
    """Return a structural fingerprint of ``obj`` containing **no values or keys**.

    ``dict`` -> ``{'type':'dict','len':N,'values': shape(a representative value)}`` (keys
    are NOT emitted — they may be caller-controlled data); ``list``/``tuple``/``set`` ->
    ``{'type','len','items'}``; ``str`` -> ``{'type':'str','len':N}``; scalars ->
    ``{'type': typename}``. Depth-capped. The output never contains an input value nor any
    input dict key — only container types, lengths, and counts.
    """
    if _depth >= _MAX_DEPTH:
        return {"type": "…"}
    if isinstance(obj, bool):
        return {"type": "bool"}
    if isinstance(obj, dict):
        return {
            "type": "dict",
            "len": len(obj),
            "values": shape(next(iter(obj.values())), _depth=_depth + 1) if obj else None,
        }
    if isinstance(obj, (list, tuple, set, frozenset)):
        first = next(iter(obj), None) if obj else None
        return {
            "type": type(obj).__name__,
            "len": len(obj),
            "items": shape(first, _depth=_depth + 1) if obj else None,
        }
    if isinstance(obj, str):
        return {"type": "str", "len": len(obj)}
    if isinstance(obj, bytes):
        return {"type": "bytes", "len": len(obj)}
    if obj is None:
        return {"type": "none"}
    return {"type": type(obj).__name__}


@dataclass(frozen=True)
class AuditRecord:
    """One invocation's audit line. ``arg_shape`` holds shapes only — never values or keys."""

    tool: str
    caller: str
    tenant: str | None
    transport: str
    status: str  # "ok" | "denied" | "error" | "rate_limited"
    reason: str
    arg_shape: dict
    duration_ms: float
    scopes_required: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "caller": self.caller,
            "tenant": self.tenant,
            "transport": self.transport,
            "status": self.status,
            "reason": self.reason,
            "arg_shape": self.arg_shape,
            "duration_ms": round(self.duration_ms, 3),
            "scopes_required": list(self.scopes_required),
        }


@runtime_checkable
class AuditSink(Protocol):
    """Anything that consumes audit records (stderr, OTel, a list, ...)."""

    def emit(self, record: AuditRecord) -> None: ...


class StderrSink:
    """Writes one JSON line per record to stderr (OTel-collector friendly)."""

    def emit(self, record: AuditRecord) -> None:
        sys.stderr.write(json.dumps({"audit": record.as_dict()}, ensure_ascii=False) + "\n")


class NullSink:
    """Drops every record (opt-out / testing)."""

    def emit(self, record: AuditRecord) -> None:  # noqa: D401 - intentional no-op
        return None


def make_sink(spec: str | AuditSink | None) -> AuditSink:
    """Resolve a sink spec.

    ``'stderr'``/``'otel'`` -> :class:`StderrSink`; ``None``/``'none'``/``'null'`` ->
    :class:`NullSink`; an existing :class:`AuditSink` is returned unchanged.
    """
    if spec is None:
        return NullSink()
    if isinstance(spec, str):
        key = spec.lower()
        if key in ("stderr", "otel"):
            return StderrSink()
        if key in ("none", "null"):
            return NullSink()
        raise ValueError(f"unknown audit sink {spec!r}")
    if isinstance(spec, AuditSink):
        return spec
    raise TypeError(f"cannot build an audit sink from {type(spec).__name__}")
