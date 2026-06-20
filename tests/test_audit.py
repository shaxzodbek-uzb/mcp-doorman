"""Audit records carry argument SHAPE only — never values."""

from __future__ import annotations

import json

from mcp_doorman import AuditRecord, shape


def test_shape_has_no_values_or_keys():
    payload = {
        "param_name": "INV-SENTINEL-123",
        "amount": 4242.42,
        "items": ["SENTINEL-A", "SENTINEL-B"],
        "filters": {"alice@corp.com": True, "sk-live-SENTINEL": 1},
    }
    fingerprint = shape(payload)
    dumped = json.dumps(fingerprint)
    # No input VALUES leak.
    for sentinel in ("INV-SENTINEL-123", "4242", "SENTINEL-A", "sk-live-SENTINEL"):
        assert sentinel not in dumped
    # No caller-controlled KEYS leak — not top-level param names, not nested data keys.
    for key in ("param_name", "amount", "items", "filters", "alice@corp.com"):
        assert key not in dumped
    assert fingerprint["type"] == "dict"
    assert fingerprint["len"] == 4


def test_shape_lists_record_count_and_item_shape():
    fp = shape(["SENTINEL-A", "SENTINEL-B", "SENTINEL-C"])
    assert fp == {"type": "list", "len": 3, "items": {"type": "str", "len": len("SENTINEL-A")}}


def test_shape_depth_cap():
    deep = {"a": {"b": {"c": {"d": {"e": "x"}}}}}
    fingerprint = shape(deep)
    assert fingerprint["values"]["values"]["values"]["values"] == {"type": "…"}


def test_record_round_trips():
    rec = AuditRecord(
        tool="get_invoice",
        caller="user-1",
        tenant="acme",
        transport="http",
        status="ok",
        reason="ok",
        arg_shape={"id": {"type": "str", "len": 3}},
        duration_ms=1.23456,
        scopes_required=("invoices:read",),
    )
    d = rec.as_dict()
    assert d["tool"] == "get_invoice"
    assert d["scopes_required"] == ["invoices:read"]
    assert d["duration_ms"] == 1.235  # rounded
    assert json.loads(json.dumps(d))  # serializable
