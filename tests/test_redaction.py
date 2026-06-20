"""PII redaction at the source — including a hard leakage assertion."""

from __future__ import annotations

from mcp_doorman import REDACTED, Redactor


def test_sensitive_key_masks_whole_value():
    r = Redactor()
    out = r.redact({"api_key": "sk-live-deadbeef", "name": "ok"})
    assert out["api_key"] == REDACTED
    assert out["name"] == "ok"


def test_glob_key_match():
    r = Redactor()
    out = r.redact({"access_token": "abc", "refresh_token": "def"})
    assert out["access_token"] == REDACTED
    assert out["refresh_token"] == REDACTED


def test_nested_recursion():
    r = Redactor()
    payload = {
        "user": {"password": "hunter2", "profile": {"email": "a@b.com"}},
        "items": [{"secret": "x"}],
    }
    out = r.redact(payload)
    assert out["user"]["password"] == REDACTED
    assert out["user"]["profile"]["email"] == REDACTED  # value-pattern match
    assert out["items"][0]["secret"] == REDACTED


def test_value_patterns():
    r = Redactor()
    out = r.redact(
        {
            "note": "reach me at alice@example.com or call 415-555-0100",
            "ssn": "123-45-6789",
            "free": "ssn is 987-65-4321 here",
        }
    )
    assert "alice@example.com" not in out["note"]
    assert "415-555-0100" not in out["note"]
    assert out["ssn"] == REDACTED  # key match
    assert "987-65-4321" not in out["free"]  # value match in a non-sensitive key


def test_with_extra_keys_union():
    r = Redactor().with_extra_keys(["amount"])
    out = r.redact({"amount": 1000, "password": "p"})
    assert out["amount"] == REDACTED
    assert out["password"] == REDACTED


def test_input_not_mutated():
    r = Redactor()
    payload = {"password": "secret", "nested": {"token": "t"}}
    r.redact(payload)
    assert payload["password"] == "secret"
    assert payload["nested"]["token"] == "t"


def test_cyclic_structure_does_not_raise():
    r = Redactor()
    a: dict = {"k": "v"}
    a["self"] = a
    out = r.redact(a)
    assert out["k"] == "v"


def test_bytes_values_are_scanned():
    r = Redactor()
    out = r.redact({"body": b"contact me at john@example.com"})
    assert b"john@example.com" not in out["body"]
    assert isinstance(out["body"], bytes)


def test_undecodable_bytes_pass_through():
    r = Redactor()
    blob = b"\xff\xfe\x00binary"
    out = r.redact({"blob": blob})
    assert out["blob"] == blob  # opaque, not corrupted


def test_set_and_frozenset_elements_redacted():
    r = Redactor()
    out = r.redact({"emails": {"john@example.com"}, "frozen": frozenset({"a@b.co"})})
    assert "john@example.com" not in next(iter(out["emails"]))
    assert all("@b.co" not in e for e in out["frozen"])


def test_non_str_sensitive_key_masks_value():
    r = Redactor()
    out = r.redact({b"token": "opaque-secret-xyz", 1: "plain"})
    assert out[b"token"] == REDACTED  # bytes key 'token' still masks
    assert out[1] == "plain"


def test_int_card_number_is_scanned():
    r = Redactor()
    out = r.redact({"acct": 4111111111111111, "count": 42})
    assert out["acct"] == REDACTED  # 16-digit card matched as a value pattern
    assert out["count"] == 42  # short int untouched, stays int
    assert out["acct"] != 42


def test_dataclass_and_object_results_are_redacted():
    from dataclasses import dataclass

    @dataclass
    class Customer:
        name: str
        email: str
        api_key: str

    r = Redactor()
    out = r.redact(Customer(name="Alice", email="alice@example.com", api_key="sk-live-x"))
    assert out["name"] == "Alice"
    assert out["email"] == REDACTED  # value pattern
    assert out["api_key"] == REDACTED  # sensitive key

    class Plain:
        def __init__(self):
            self.password = "hunter2"
            self.note = "ok"

    out2 = r.redact(Plain())
    assert out2["password"] == REDACTED
    assert out2["note"] == "ok"


def test_leakage_secret_under_sensitive_keys_absent_at_any_depth():
    # Honest guarantee: a secret placed under a SENSITIVE KEY is removed wherever it lives
    # (top level, nested dict, inside a list). A key+pattern redactor cannot catch an
    # unknown secret hidden in arbitrary free text — that is documented, not tested-as-true.
    r = Redactor()
    secret = "TOP-SECRET-VALUE-9999"
    payload = {
        "api_key": secret,
        "nested": {"refresh_token": secret},
        "deep": [{"password": secret}, {"cvv": secret}],
    }
    import json

    dumped = json.dumps(r.redact(payload))
    assert secret not in dumped


def test_pii_value_patterns_removed_from_free_text():
    # The complementary guarantee: known PII shapes are stripped even from benign keys.
    r = Redactor()
    out = r.redact({"log": "contact alice@example.com, ssn 123-45-6789"})
    assert "alice@example.com" not in out["log"]
    assert "123-45-6789" not in out["log"]
