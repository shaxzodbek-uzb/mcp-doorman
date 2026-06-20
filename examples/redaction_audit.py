"""Show PII redaction at the source and the values-free audit record.

    python examples/redaction_audit.py
"""

from __future__ import annotations

import json

from mcp_doorman import AuditRecord, Doorman, Principal, Redactor, ToolSpec, shape


def redaction_demo() -> None:
    r = Redactor(["password", "*_token"]).with_extra_keys(["balance"])
    payload = {
        "name": "Alice",
        "password": "hunter2",
        "access_token": "sk-live-deadbeef",
        "balance": 10_000,
        "note": "email alice@example.com, ssn 123-45-6789",
        "nested": [{"refresh_token": "rt-123"}],
    }
    print("redacted result ->")
    print(json.dumps(r.redact(payload), indent=2, ensure_ascii=False))


def audit_demo() -> None:
    records: list[AuditRecord] = []

    class ListSink:
        def emit(self, record: AuditRecord) -> None:
            records.append(record)

    doorman = Doorman(audit=ListSink(), rate_limit=None)
    doorman.register(
        ToolSpec(name="echo", handler=lambda **k: k, methods=frozenset({"GET"}))
    )
    principal = Principal(subject="alice", verified=True)
    doorman.guard_call(
        "echo",
        {"query": "SECRET QUERY TEXT", "limit": 50, "tags": ["a", "b"]},
        principal,
        lambda a: {"ok": True},
    )
    print("\naudit record (note: shapes only, no values) ->")
    print(json.dumps(records[0].as_dict(), indent=2))
    # Prove the raw value never made it into the record.
    assert "SECRET QUERY TEXT" not in json.dumps(records[0].as_dict())
    print("\nshape('SECRET QUERY TEXT') =", shape("SECRET QUERY TEXT"))


if __name__ == "__main__":
    redaction_demo()
    audit_demo()
