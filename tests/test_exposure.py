"""Deny-by-default exposure + destructive gating."""

from __future__ import annotations

import pytest

from mcp_doorman import Registry, expose
from mcp_doorman.errors import ConfigError, DestructiveNotAllowed, NotExposed


def test_undecorated_route_is_not_exposed():
    def handler():
        return {}

    reg = Registry()
    assert reg.add_route(handler=handler, methods=["GET"]) is None
    assert reg.names() == []


def test_exposed_get_is_read_only():
    @expose(name="get_thing", scopes=["things:read"])
    def handler(id: str):
        return {"id": id}

    reg = Registry()
    spec = reg.add_route(handler=handler, methods=["GET"])
    assert spec is not None
    assert spec.name == "get_thing"
    assert spec.read_only is True
    assert spec.scopes == ("things:read",)
    assert spec.annotations() == {"readOnlyHint": True, "destructiveHint": False}


def test_destructive_method_requires_acknowledgement():
    @expose(name="delete_thing")
    def handler(id: str):
        return {"deleted": id}

    reg = Registry()
    with pytest.raises(DestructiveNotAllowed):
        reg.add_route(handler=handler, methods=["DELETE"])


def test_destructive_acknowledged_emits_hint():
    @expose(name="delete_thing", destructive=True, scopes=["things:write"])
    def handler(id: str):
        return {"deleted": id}

    reg = Registry()
    spec = reg.add_route(handler=handler, methods=["DELETE"])
    assert spec.destructive is True
    assert spec.read_only is False
    assert spec.annotations() == {"readOnlyHint": False, "destructiveHint": True}


def test_default_name_is_function_name():
    @expose()
    def my_tool():
        return {}

    reg = Registry()
    spec = reg.add_route(handler=my_tool, methods=["GET"])
    assert spec.name == "my_tool"


def test_duplicate_name_raises():
    @expose(name="dup")
    def a():
        return {}

    @expose(name="dup")
    def b():
        return {}

    reg = Registry()
    reg.add_route(handler=a, methods=["GET"])
    with pytest.raises(ConfigError):
        reg.add_route(handler=b, methods=["GET"])


def test_get_unknown_raises_not_exposed():
    reg = Registry()
    with pytest.raises(NotExposed):
        reg.get("nope")
