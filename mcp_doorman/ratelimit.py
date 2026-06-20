"""In-process token-bucket rate limiting — no Redis, no gateway.

Answers the documented uncontrolled-tool-loop / runaway-cost failure mode with per-caller
and per-tool buckets. The only time source is an injectable monotonic clock, so the math
is fully deterministic under test.
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from .errors import ConfigError, RateLimited

#: Cap on distinct live buckets to bound memory against high-cardinality callers.
DEFAULT_MAX_BUCKETS = 100_000

_UNIT_SECONDS = {
    "s": 1.0,
    "sec": 1.0,
    "second": 1.0,
    "seconds": 1.0,
    "m": 60.0,
    "min": 60.0,
    "minute": 60.0,
    "minutes": 60.0,
    "h": 3600.0,
    "hour": 3600.0,
    "hours": 3600.0,
}

_VALID_SCOPES = ("per_caller", "per_tool")
_RULE_RE = re.compile(
    r"^\s*(?P<count>\d+(?:\.\d+)?)\s*/\s*(?P<unit>[a-zA-Z]+)\s*(?P<scope>per_caller|per_tool)?\s*$"
)


@dataclass
class TokenBucket:
    """A classic leaky/token bucket. ``take`` is pure given ``now`` (monotonic seconds)."""

    capacity: float
    refill_per_sec: float
    tokens: float
    updated: float

    def _refill(self, now: float) -> None:
        if now > self.updated:
            gained = (now - self.updated) * self.refill_per_sec
            self.tokens = min(self.capacity, self.tokens + gained)
            self.updated = now

    def take(self, now: float, n: float = 1.0) -> bool:
        """Refill for elapsed time (capacity-capped) then take ``n`` if available."""
        self._refill(now)
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

    def retry_after(self, now: float, n: float = 1.0) -> float:
        """Seconds until ``n`` tokens are available (0.0 if available now)."""
        self._refill(now)
        if self.tokens >= n:
            return 0.0
        if self.refill_per_sec <= 0:
            return float("inf")
        return (n - self.tokens) / self.refill_per_sec


def parse_rate_spec(spec: str) -> list[tuple[str, float, float]]:
    """Parse ``'COUNT/UNIT [per_caller|per_tool][; ...]'`` into rules.

    Each rule becomes ``(scope, capacity, refill_per_sec)``. ``scope`` defaults to
    ``per_caller``. Raises :class:`ConfigError` on malformed input.
    """
    rules: list[tuple[str, float, float]] = []
    for chunk in spec.split(";"):
        if not chunk.strip():
            continue
        m = _RULE_RE.match(chunk)
        if not m:
            raise ConfigError(
                f"invalid rate rule {chunk.strip()!r}; expected e.g. '60/min per_caller'"
            )
        count = float(m.group("count"))
        if count <= 0:
            raise ConfigError(f"rate count must be > 0 in {chunk.strip()!r}")
        unit = m.group("unit").lower()
        if unit not in _UNIT_SECONDS:
            raise ConfigError(f"unknown rate unit {unit!r} in {chunk.strip()!r}")
        scope = m.group("scope") or "per_caller"
        window = _UNIT_SECONDS[unit]
        rules.append((scope, count, count / window))
    if not rules:
        raise ConfigError(f"no rate rules parsed from {spec!r}")
    return rules


class RateLimiter:
    """Enforces every configured rule. ``spec=None`` disables limiting entirely."""

    def __init__(
        self,
        spec: str | None,
        *,
        clock: Callable[[], float] | None = None,
        max_buckets: int = DEFAULT_MAX_BUCKETS,
    ) -> None:
        self._clock = clock or time.monotonic
        self._rules = parse_rate_spec(spec) if spec else []
        self._buckets: OrderedDict[tuple[str, str], TokenBucket] = OrderedDict()
        self._max_buckets = max_buckets

    @property
    def enabled(self) -> bool:
        return bool(self._rules)

    def _bucket(
        self, key: tuple[str, str], capacity: float, refill: float, now: float
    ) -> TokenBucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self._max_buckets:
                self._evict(now)  # make room BEFORE inserting the key we are about to use
            bucket = TokenBucket(
                capacity=capacity, refill_per_sec=refill, tokens=capacity, updated=now
            )
            self._buckets[key] = bucket
        else:
            self._buckets.move_to_end(key)  # mark recently used (LRU)
        return bucket

    def _evict(self, now: float) -> None:
        """Bound memory: drop fully-recovered buckets, then LRU-evict toward the cap.

        A bucket at full capacity carries no state worth keeping — it is reconstructable on
        next use — so dropping it is lossless. Beyond that, evict least-recently-used. Runs
        only when at the cap, so for the default 100k cap it never fires in normal use.
        """
        for key in list(self._buckets):
            if len(self._buckets) < self._max_buckets:
                return
            bucket = self._buckets[key]
            bucket._refill(now)
            if bucket.tokens >= bucket.capacity:
                del self._buckets[key]
        while len(self._buckets) >= self._max_buckets:
            self._buckets.popitem(last=False)  # evict the oldest

    def check(self, *, tool: str, caller: str, cost: float = 1.0) -> None:
        """Enforce all rules. Raises :class:`RateLimited` on the first exhausted bucket.

        A rule that would fail does not consume tokens from rules checked after it: we
        probe every relevant bucket first and only commit the takes once all pass.
        """
        if not self._rules:
            return
        now = self._clock()
        targets: list[TokenBucket] = []
        for scope, capacity, refill in self._rules:
            key = (scope, caller if scope == "per_caller" else tool)
            bucket = self._bucket(key, capacity, refill, now)
            if bucket.retry_after(now, cost) > 0:
                raise RateLimited(
                    f"rate limit exceeded for {scope} on {key[1]!r}",
                    retry_after=bucket.retry_after(now, cost),
                )
            targets.append(bucket)
        for bucket in targets:
            bucket.take(now, cost)
