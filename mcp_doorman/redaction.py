"""PII redaction at the source.

Configured sensitive keys (globs like ``*_token``) and value patterns (email / phone /
SSN / card) are stripped from tool **results** before they reach the model. Redaction
returns a deep copy and never mutates its input, even for cyclic structures.

It walks the common result shapes a FastAPI handler returns: ``dict`` / mappings, lists,
tuples, sets, ``str``, ``bytes`` (decoded as UTF-8; undecodable binary is passed through
unscanned), ints (scanned as strings for card/SSN shapes), and **structured objects** —
dataclasses and pydantic models are normalized to dicts and redacted, rather than slipping
through unredacted. The value patterns are deliberately conservative heuristics (e.g. the
phone matcher needs ~9+ digits and will miss bare 7-digit locals); add your own via
``value_patterns=`` for stricter coverage.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, is_dataclass
from typing import Any

#: The token substituted for any redacted value.
REDACTED = "«redacted»"

#: Value-level patterns searched inside string values.
DEFAULT_VALUE_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # email
    re.compile(r"(?<!\d)\+?\d[\d\s().-]{7,}\d(?!\d)"),  # phone (e164-ish / formatted)
    re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),  # US SSN
    re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),  # credit-card-ish
)

#: Dict keys whose entire value is masked (case-insensitive fnmatch globs).
DEFAULT_KEYS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "*_token",
    "api_key",
    "apikey",
    "authorization",
    "ssn",
    "credit_card",
    "card_number",
    "cvv",
)


class Redactor:
    """Redacts sensitive keys and value patterns from arbitrary nested structures."""

    def __init__(
        self,
        keys: Sequence[str] = DEFAULT_KEYS,
        *,
        value_patterns: Sequence[re.Pattern] = DEFAULT_VALUE_PATTERNS,
        mask: str = REDACTED,
    ) -> None:
        self._keys = tuple(k.lower() for k in keys)
        self._value_patterns = tuple(value_patterns)
        self._mask = mask

    def with_extra_keys(self, extra: Iterable[str]) -> Redactor:
        """Return a new redactor whose key set is the union with ``extra`` (per-tool merge)."""
        merged = tuple(dict.fromkeys((*self._keys, *(k.lower() for k in extra))))
        return Redactor(merged, value_patterns=self._value_patterns, mask=self._mask)

    def _key_is_sensitive(self, key: str) -> bool:
        low = key.lower()
        return any(fnmatch.fnmatchcase(low, pat) for pat in self._keys)

    def _redact_str(self, value: str) -> str:
        out = value
        for pattern in self._value_patterns:
            out = pattern.sub(self._mask, out)
        return out

    def redact(self, obj: Any) -> Any:
        """Return a redacted deep copy of ``obj``. Never mutates the input."""
        return self._walk(obj, set())

    @staticmethod
    def _normalize(obj: Any) -> Any:
        """Turn a structured object (pydantic / dataclass / plain) into a mapping.

        Common JSON scalars and containers are returned unchanged. Anything else is
        normalized to a dict so its fields get walked and redacted — closing the gap where
        a returned model would otherwise slip through untouched.
        """
        if obj is None or isinstance(
            obj, (str, bytes, bool, int, float, Mapping, list, tuple, set, frozenset)
        ):
            return obj
        model_dump = getattr(obj, "model_dump", None)  # pydantic v2
        if callable(model_dump):
            try:
                return model_dump()
            except Exception:  # noqa: BLE001 - fall through to other strategies
                pass
        if is_dataclass(obj) and not isinstance(obj, type):
            try:
                return asdict(obj)
            except Exception:  # noqa: BLE001
                pass
        attrs = getattr(obj, "__dict__", None)
        if isinstance(attrs, dict) and attrs:
            return dict(attrs)
        return obj

    def _walk(self, obj: Any, seen: set[int]) -> Any:
        obj = self._normalize(obj)
        if isinstance(obj, Mapping):
            if id(obj) in seen:
                return self._mask
            seen = seen | {id(obj)}
            out: dict = {}
            for key, value in obj.items():
                # Coerce non-str keys so a sensitive key that isn't a plain str (bytes /
                # Enum / int) still masks its value instead of leaking it.
                if isinstance(key, str):
                    key_str = key
                elif isinstance(key, bytes):
                    key_str = key.decode("utf-8", "ignore")
                else:
                    key_str = str(key)
                if self._key_is_sensitive(key_str):
                    out[key] = self._mask
                else:
                    out[key] = self._walk(value, seen)
            return out
        if isinstance(obj, (list, tuple)):
            if id(obj) in seen:
                return self._mask
            seen = seen | {id(obj)}
            walked = [self._walk(item, seen) for item in obj]
            return tuple(walked) if isinstance(obj, tuple) else walked
        if isinstance(obj, (set, frozenset)):
            if id(obj) in seen:
                return self._mask
            seen = seen | {id(obj)}
            return type(obj)(self._walk(item, seen) for item in obj)
        if isinstance(obj, str):
            return self._redact_str(obj)
        if isinstance(obj, bytes):
            try:
                decoded = obj.decode("utf-8")
            except UnicodeDecodeError:
                return obj  # opaque binary — not scanned
            return self._redact_str(decoded).encode("utf-8")
        if isinstance(obj, bool):
            return obj
        if isinstance(obj, int):
            # An int card/SSN under a non-sensitive key would otherwise never be scanned.
            masked = self._redact_str(str(obj))
            return masked if masked != str(obj) else obj
        return obj
