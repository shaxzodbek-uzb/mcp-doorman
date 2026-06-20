"""Token-bucket rate limiting with an injected monotonic clock."""

from __future__ import annotations

import pytest

from mcp_doorman import RateLimiter, TokenBucket, parse_rate_spec
from mcp_doorman.errors import ConfigError, RateLimited


def test_token_bucket_take_and_refill():
    b = TokenBucket(capacity=2, refill_per_sec=1.0, tokens=2, updated=0.0)
    assert b.take(0.0) is True
    assert b.take(0.0) is True
    assert b.take(0.0) is False  # empty
    assert b.take(1.0) is True  # one refilled after 1s
    # capacity cap: long wait does not exceed capacity
    assert b.take(100.0) is True
    assert b.take(100.0) is True
    assert b.take(100.0) is False


def test_token_bucket_retry_after():
    b = TokenBucket(capacity=1, refill_per_sec=0.5, tokens=0, updated=0.0)
    assert b.retry_after(0.0) == pytest.approx(2.0)  # 1 token / 0.5 per sec


def test_parse_rate_spec_variants():
    assert parse_rate_spec("60/min") == [("per_caller", 60.0, 1.0)]
    rules = parse_rate_spec("60/min per_caller; 10/min per_tool")
    assert rules[0] == ("per_caller", 60.0, 1.0)
    assert rules[1][0] == "per_tool"
    assert rules[1][1] == 10.0
    assert rules[1][2] == pytest.approx(10.0 / 60.0)
    assert parse_rate_spec("5/s") == [("per_caller", 5.0, 5.0)]


def test_parse_rate_spec_rejects_garbage():
    for bad in ["", "abc", "10/decade", "10 per minute", "/min"]:
        with pytest.raises(ConfigError):
            parse_rate_spec(bad)


def test_parse_rate_spec_rejects_zero():
    # 0/min would brick a tool forever (capacity 0, no refill) — reject it at config time.
    for bad in ["0/min", "0/s per_tool", "0.0/hour"]:
        with pytest.raises(ConfigError):
            parse_rate_spec(bad)


def test_bucket_map_is_bounded():
    t = {"v": 0.0}
    rl = RateLimiter("100/min per_caller", clock=lambda: t["v"], max_buckets=2)
    for i in range(50):
        rl.check(tool="x", caller=f"caller-{i}")
    # memory is bounded regardless of caller cardinality
    assert len(rl._buckets) <= 2


def test_limiter_per_caller_isolation():
    t = {"v": 0.0}
    rl = RateLimiter("2/min per_caller", clock=lambda: t["v"])
    rl.check(tool="x", caller="a")
    rl.check(tool="x", caller="a")
    with pytest.raises(RateLimited) as ei:
        rl.check(tool="x", caller="a")
    assert ei.value.retry_after > 0
    # different caller is unaffected
    rl.check(tool="x", caller="b")


def test_limiter_per_tool_keying():
    t = {"v": 0.0}
    rl = RateLimiter("1/min per_tool", clock=lambda: t["v"])
    rl.check(tool="x", caller="a")
    with pytest.raises(RateLimited):
        rl.check(tool="x", caller="b")  # per-tool bucket shared across callers


def test_limiter_disabled_when_no_spec():
    rl = RateLimiter(None)
    assert rl.enabled is False
    for _ in range(1000):
        rl.check(tool="x", caller="a")  # never raises


def test_failed_rule_does_not_consume_other_buckets():
    t = {"v": 0.0}
    # Sharp design: per_caller has exactly 2 tokens; per_tool has 1. If a per_tool
    # rejection wrongly consumed a per_caller token, the later tool "y" call would fail.
    rl = RateLimiter("2/min per_caller; 1/min per_tool", clock=lambda: t["v"])
    rl.check(tool="x", caller="a")  # per_caller a -> 1 left; per_tool x -> 0 left
    with pytest.raises(RateLimited):
        rl.check(tool="x", caller="a")  # per_tool x empty -> reject; must NOT take per_caller
    # per_caller a must still hold 1 token -> a fresh tool succeeds exactly once.
    rl.check(tool="y", caller="a")
    with pytest.raises(RateLimited):
        rl.check(tool="z", caller="a")  # now per_caller a is genuinely exhausted
