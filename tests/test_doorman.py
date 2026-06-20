"""The guard_call pipeline: ordering, fail-closed exits, redaction, and audit hygiene."""

from __future__ import annotations

import json

import pytest

from mcp_doorman import (
    ANONYMOUS,
    Doorman,
    Principal,
    Settings,
    ToolSpec,
    Transport,
)
from mcp_doorman.errors import ConfigError, Forbidden, NotExposed, RateLimited, Unauthorized


def _doorman(sink, read_spec, **kw):
    d = Doorman(audit=sink, rate_limit=kw.pop("rate_limit", None), **kw)
    d.register(read_spec)
    return d


def test_happy_path_redacts_and_audits_ok(sink, read_spec, verified_reader):
    d = _doorman(sink, read_spec)
    result = d.guard_call(
        "get_invoice",
        {"id": "INV-1"},
        verified_reader,
        lambda a: {"id": a["id"], "email": "alice@example.com"},
    )
    assert result["email"] == "«redacted»"  # value-pattern redaction applied to result
    assert sink.last.status == "ok"
    assert sink.last.tool == "get_invoice"
    assert sink.last.caller == "user-1"
    # keyless structural fingerprint of {"id": "INV-1"}
    assert sink.last.arg_shape == {"type": "dict", "len": 1, "values": {"type": "str", "len": 5}}


def test_not_exposed_audits_error_and_raises(sink, read_spec, verified_reader):
    d = _doorman(sink, read_spec)
    with pytest.raises(NotExposed):
        d.guard_call("ghost", {}, verified_reader, lambda a: {})
    assert sink.last.status == "error"
    assert sink.last.reason == "not_exposed"


def test_unverified_audits_denied(sink, read_spec):
    d = _doorman(sink, read_spec)
    with pytest.raises(Unauthorized):
        d.guard_call("get_invoice", {"id": "x"}, ANONYMOUS, lambda a: {})
    assert sink.last.status == "denied"
    assert sink.last.reason == "unauthorized"


def test_wrong_scope_audits_forbidden(sink, read_spec):
    d = _doorman(sink, read_spec)
    principal = Principal(subject="u", scopes=frozenset({"other"}), verified=True)
    with pytest.raises(Forbidden):
        d.guard_call("get_invoice", {"id": "x"}, principal, lambda a: {})
    assert sink.last.status == "denied"
    assert sink.last.reason == "forbidden:scope"


def test_rate_limited_audits(sink, read_spec, verified_reader):
    d = Doorman(audit=sink, rate_limit="1/min per_caller", clock=lambda: 0.0)
    d.register(read_spec)
    d.guard_call("get_invoice", {"id": "x"}, verified_reader, lambda a: {"ok": 1})
    with pytest.raises(RateLimited):
        d.guard_call("get_invoice", {"id": "x"}, verified_reader, lambda a: {"ok": 1})
    assert sink.last.status == "rate_limited"


def test_handler_error_audits_error_and_reraises(sink, read_spec, verified_reader):
    d = _doorman(sink, read_spec)

    def boom(_a):
        raise ValueError("kaboom")

    with pytest.raises(ValueError):
        d.guard_call("get_invoice", {"id": "x"}, verified_reader, boom)
    assert sink.last.status == "error"
    assert sink.last.reason == "handler_error"


def test_no_raw_values_or_secrets_in_any_record(sink, read_spec, verified_reader):
    d = _doorman(sink, read_spec)
    d.guard_call(
        "get_invoice",
        {"id": "ARG-SENTINEL", "api_key": "SECRET-SENTINEL"},
        verified_reader,
        lambda a: {"token": "RESULT-SECRET", "ok": True},
    )
    blob = json.dumps([r.as_dict() for r in sink.records])
    for sentinel in ("ARG-SENTINEL", "SECRET-SENTINEL", "RESULT-SECRET"):
        assert sentinel not in blob


def test_per_tool_redact_merge(sink, verified_reader):
    from mcp_doorman import ToolSpec

    spec = ToolSpec(
        name="bal",
        handler=lambda: {},
        methods=frozenset({"GET"}),
        scopes=("invoices:read",),
        redact=("balance",),
    )
    d = Doorman(audit=sink, rate_limit=None)
    d.register(spec)
    out = d.guard_call("bal", {}, verified_reader, lambda a: {"balance": 999, "name": "ok"})
    assert out["balance"] == "«redacted»"
    assert out["name"] == "ok"


async def test_aguard_call_awaits_coroutine(sink, read_spec, verified_reader):
    d = _doorman(sink, read_spec)

    async def handler(_a):
        return {"async": True}

    out = await d.aguard_call("get_invoice", {"id": "x"}, verified_reader, handler)
    assert out == {"async": True}
    assert sink.last.status == "ok"


# -- identity / audience -------------------------------------------------------------


def test_principal_from_token_verifies_and_binds_audience(auth_config):
    d = Doorman(auth=auth_config, audit="none", rate_limit=None)
    p = d.principal_from_token("tok-reader", transport=Transport.HTTP)
    assert p.verified is True
    assert p.subject == "user-1"
    assert p.tenant == "acme"
    assert "invoices:read" in p.scopes


def test_principal_from_token_rejects_wrong_audience(auth_config):
    d = Doorman(auth=auth_config, audit="none", rate_limit=None)
    with pytest.raises(Unauthorized):
        d.principal_from_token("tok-wrong-aud", transport=Transport.HTTP)


def test_principal_from_missing_token_is_unverified(auth_config):
    d = Doorman(auth=auth_config, audit="none", rate_limit=None)
    p = d.principal_from_token(None, transport=Transport.STDIO)
    assert p.verified is False
    assert p.transport == Transport.STDIO


def test_token_without_verifier_raises():
    d = Doorman(auth=None, audit="none", rate_limit=None)
    with pytest.raises(Unauthorized):
        d.principal_from_token("anything", transport=Transport.HTTP)


# -- mount guards --------------------------------------------------------------------


def test_mount_without_auth_fails_closed():
    d = Doorman(auth=None, audit="none", settings=Settings(require_auth_for_remote=True))
    with pytest.raises(ConfigError):
        d.mount("/mcp")


def test_dev_preset_disables_auth_and_warns(capsys):
    d = Doorman.dev()
    assert d.auth is None
    assert d.settings.require_auth_for_remote is False
    err = capsys.readouterr().err
    assert "dev() preset" in err


def test_scan_app_discovers_only_exposed():
    from mcp_doorman import expose

    @expose(name="shown", scopes=["s"])
    def shown():
        return {}

    def hidden():
        return {}

    class _Route:
        def __init__(self, endpoint, methods):
            self.endpoint = endpoint
            self.methods = methods

    class _App:
        routes = [_Route(shown, ["GET"]), _Route(hidden, ["GET"])]

    d = Doorman(audit="none", rate_limit=None)
    found = d.scan_app(_App())
    assert [s.name for s in found] == ["shown"]
    assert "hidden" not in d.registry.names()


def test_scan_app_fails_closed_on_unknown_methods():
    from mcp_doorman import expose
    from mcp_doorman.errors import DestructiveNotAllowed

    @expose(name="mystery")  # not acknowledged destructive
    def mystery():
        return {}

    class _Route:
        endpoint = mystery
        methods = None  # custom route with no determinable verb

    class _App:
        routes = [_Route()]

    d = Doorman(audit="none", rate_limit=None)
    with pytest.raises(DestructiveNotAllowed):
        d.scan_app(_App())


def test_anonymous_callers_are_isolated_by_caller_hint(sink, read_spec):
    # Two anonymous callers must NOT share one bucket: caller_hint keys them apart.
    from mcp_doorman import Principal, Transport

    d = Doorman(audit=sink, rate_limit="1/min per_caller", clock=lambda: 0.0)
    d.register(
        ToolSpec(name="ping", handler=lambda: {}, methods=frozenset({"GET"}))  # unscoped
    )
    anon = Principal(subject="", transport=Transport.STDIO, verified=False)
    d.guard_call("ping", {}, anon, lambda a: {"ok": 1}, caller_hint="10.0.0.1")
    # a different peer is unaffected by the first peer exhausting its bucket
    d.guard_call("ping", {}, anon, lambda a: {"ok": 1}, caller_hint="10.0.0.2")
    # the same peer is now limited
    with pytest.raises(RateLimited):
        d.guard_call("ping", {}, anon, lambda a: {"ok": 1}, caller_hint="10.0.0.1")
