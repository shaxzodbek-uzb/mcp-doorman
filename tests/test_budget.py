"""Per-tool rate overrides and the cost budget guard.

Both close the same documented failure mode — an uncontrolled tool-call loop running up
a bill — from opposite ends: the override caps how often one expensive tool may be
called, the budget caps how much may be spent overall.

A manual clock makes every assertion deterministic; nothing here sleeps.
"""

from __future__ import annotations

import pytest

from mcp_doorman import BudgetExceeded, Doorman, Principal, RateLimited, ToolSpec, Transport
from mcp_doorman.errors import ConfigError
from mcp_doorman.exposure import expose


class Clock:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


def _spec(name: str, *, rate: str | None = None, cost: float = 1.0) -> ToolSpec:
    return ToolSpec(
        name=name,
        handler=lambda **kw: {"ok": True},
        methods=frozenset({"GET"}),
        scopes=(),
        read_only=True,
        rate=rate,
        cost=cost,
    )


@pytest.fixture
def caller() -> Principal:
    return Principal(subject="user-1", transport=Transport.HTTP, verified=True)


def _call(doorman: Doorman, name: str, principal: Principal):
    return doorman.guard_call(name, {}, principal, lambda a: {"ok": True})


# -- the bug: expose(rate=...) was accepted and never enforced ----------------


def test_per_tool_rate_override_is_enforced(clock, sink, caller):
    """`expose(rate=...)` used to be stored on the spec and silently ignored."""
    doorman = Doorman(rate_limit="1000/min per_caller", audit=sink, clock=clock)
    doorman.register(_spec("expensive", rate="2/min per_caller"))

    _call(doorman, "expensive", caller)
    _call(doorman, "expensive", caller)
    with pytest.raises(RateLimited):
        _call(doorman, "expensive", caller)


def test_the_override_tightens_one_tool_without_touching_the_others(clock, sink, caller):
    doorman = Doorman(rate_limit="1000/min per_caller", audit=sink, clock=clock)
    doorman.register(_spec("expensive", rate="1/min per_caller"))
    doorman.register(_spec("cheap"))

    _call(doorman, "expensive", caller)
    with pytest.raises(RateLimited):
        _call(doorman, "expensive", caller)
    for _ in range(10):
        _call(doorman, "cheap", caller)  # unaffected


def test_two_tools_sharing_a_spec_string_get_separate_allowances(clock, sink, caller):
    """'5/min' on two tools means five each, not five between them."""
    doorman = Doorman(rate_limit=None, audit=sink, clock=clock)
    doorman.register(_spec("a", rate="1/min per_caller"))
    doorman.register(_spec("b", rate="1/min per_caller"))

    _call(doorman, "a", caller)
    _call(doorman, "b", caller)  # b has its own bucket
    with pytest.raises(RateLimited):
        _call(doorman, "a", caller)


def test_the_override_refills_over_time(clock, sink, caller):
    doorman = Doorman(rate_limit=None, audit=sink, clock=clock)
    doorman.register(_spec("expensive", rate="60/min per_caller"))

    for _ in range(60):
        _call(doorman, "expensive", caller)
    with pytest.raises(RateLimited):
        _call(doorman, "expensive", caller)
    clock.advance(1.0)  # 60/min == 1 per second
    _call(doorman, "expensive", caller)


def test_a_rejected_override_does_not_spend_the_global_allowance(clock, sink, caller):
    """Rules are probed before any are committed, so a refusal costs nothing."""
    doorman = Doorman(rate_limit="10/min per_caller", audit=sink, clock=clock)
    doorman.register(_spec("expensive", rate="1/min per_caller"))
    doorman.register(_spec("cheap"))

    _call(doorman, "expensive", caller)  # global: 1 spent
    for _ in range(5):
        with pytest.raises(RateLimited):
            _call(doorman, "expensive", caller)  # refused; must not spend global tokens

    for _ in range(9):
        _call(doorman, "cheap", caller)  # 9 more global calls still available
    with pytest.raises(RateLimited):
        _call(doorman, "cheap", caller)


def test_a_malformed_override_fails_at_decoration_not_on_the_first_call():
    with pytest.raises(ConfigError, match="invalid rate rule"):

        @expose(rate="every now and then")
        def handler():
            """A tool."""


def test_a_valid_override_decorates_cleanly():
    @expose(rate="5/min per_caller", cost=2.0)
    def handler():
        """A tool."""

    assert handler.__name__ == "handler"


# -- the budget --------------------------------------------------------------


def test_no_budget_is_configured_by_default(clock, sink, caller):
    """A cost unit means nothing until a deployment defines one."""
    doorman = Doorman(rate_limit=None, audit=sink, clock=clock)
    doorman.register(_spec("t", cost=1_000_000))
    for _ in range(20):
        _call(doorman, "t", caller)
    assert doorman.remaining_budget(tool="t", caller="user-1") == float("inf")


def test_budget_counts_declared_cost_not_calls(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="10/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("pricey", cost=4.0))

    _call(doorman, "pricey", caller)  # 4
    _call(doorman, "pricey", caller)  # 8
    with pytest.raises(BudgetExceeded, match="budget exceeded"):
        _call(doorman, "pricey", caller)  # would be 12


def test_a_free_tool_never_exhausts_the_budget(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="1/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("free", cost=0.0))
    for _ in range(50):
        _call(doorman, "free", caller)


def test_budget_is_per_caller(clock, sink):
    doorman = Doorman(rate_limit=None, budget="2/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=2.0))
    alice = Principal(subject="alice", transport=Transport.HTTP, verified=True)
    bob = Principal(subject="bob", transport=Transport.HTTP, verified=True)

    _call(doorman, "t", alice)
    _call(doorman, "t", bob)  # bob's allowance is his own
    with pytest.raises(BudgetExceeded):
        _call(doorman, "t", alice)


def test_budget_spans_tools_for_one_caller(clock, sink, caller):
    """Unlike a per-tool rate, a per-caller budget is shared across every tool."""
    doorman = Doorman(rate_limit=None, budget="3/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("a", cost=2.0))
    doorman.register(_spec("b", cost=2.0))

    _call(doorman, "a", caller)
    with pytest.raises(BudgetExceeded):
        _call(doorman, "b", caller)


def test_budget_recovers_over_the_window(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="3600/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=3600.0))

    _call(doorman, "t", caller)
    with pytest.raises(BudgetExceeded):
        _call(doorman, "t", caller)
    clock.advance(3600.0)
    _call(doorman, "t", caller)


def test_remaining_budget_reports_and_does_not_consume(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="10/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=3.0))

    assert doorman.remaining_budget(tool="t", caller="user-1") == pytest.approx(10.0)
    _call(doorman, "t", caller)
    assert doorman.remaining_budget(tool="t", caller="user-1") == pytest.approx(7.0)
    # Reading it repeatedly must not spend anything.
    for _ in range(5):
        doorman.remaining_budget(tool="t", caller="user-1")
    assert doorman.remaining_budget(tool="t", caller="user-1") == pytest.approx(7.0)


def test_budget_exceeded_is_catchable_as_rate_limited(clock, sink, caller):
    """Existing `except RateLimited` handlers keep working."""
    doorman = Doorman(rate_limit=None, budget="1/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=5.0))
    with pytest.raises(RateLimited):
        _call(doorman, "t", caller)


def test_budget_refusal_carries_retry_after(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="3600/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=3600.0))
    _call(doorman, "t", caller)
    with pytest.raises(BudgetExceeded) as excinfo:
        _call(doorman, "t", caller)
    assert excinfo.value.retry_after == pytest.approx(3600.0)


# -- ordering and auditing ---------------------------------------------------


def test_a_rate_limited_call_does_not_spend_budget(clock, sink, caller):
    """Budget is checked last, so a too-frequent call keeps its allowance."""
    doorman = Doorman(
        rate_limit="1/min per_caller", budget="100/hour per_caller", audit=sink, clock=clock
    )
    doorman.register(_spec("t", cost=10.0))

    _call(doorman, "t", caller)
    for _ in range(5):
        with pytest.raises(RateLimited):
            _call(doorman, "t", caller)
    assert doorman.remaining_budget(tool="t", caller="user-1") == pytest.approx(90.0)


def test_a_budget_refusal_is_audited_distinctly(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="1/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=5.0))
    with pytest.raises(BudgetExceeded):
        _call(doorman, "t", caller)

    record = sink.last
    assert record.status == "budget_exceeded"
    assert record.reason == "budget_exceeded"
    assert record.cost == 5.0


def test_the_audit_record_carries_the_declared_cost(clock, sink, caller):
    doorman = Doorman(rate_limit=None, audit=sink, clock=clock)
    doorman.register(_spec("t", cost=2.5))
    _call(doorman, "t", caller)
    assert sink.last.status == "ok"
    assert sink.last.cost == 2.5
    assert sink.last.as_dict()["cost"] == 2.5


def test_a_refused_call_is_audited_exactly_once(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="1/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=5.0))
    with pytest.raises(BudgetExceeded):
        _call(doorman, "t", caller)
    assert len(sink.records) == 1


def test_a_refused_call_never_reaches_the_handler(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="1/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=5.0))

    calls: list[dict] = []
    with pytest.raises(BudgetExceeded):
        doorman.guard_call("t", {}, caller, lambda a: calls.append(a))
    assert calls == []


# -- configuration -----------------------------------------------------------


def test_expose_rejects_a_negative_cost():
    with pytest.raises(ConfigError, match="cost must be >= 0"):

        @expose(cost=-1.0)
        def handler():
            """A tool."""


def test_day_is_a_valid_budget_window(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="100/day per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t", cost=60.0))
    _call(doorman, "t", caller)
    with pytest.raises(BudgetExceeded):
        _call(doorman, "t", caller)


def test_a_spec_without_a_cost_defaults_to_one(clock, sink, caller):
    doorman = Doorman(rate_limit=None, budget="2/hour per_caller", audit=sink, clock=clock)
    doorman.register(_spec("t"))
    _call(doorman, "t", caller)
    _call(doorman, "t", caller)
    with pytest.raises(BudgetExceeded):
        _call(doorman, "t", caller)
