"""P1 unit tests: strict JSON parsing."""

from __future__ import annotations

import pytest

from attest_sdk import canonical
from attest_sdk.errors import AttestError, LimitExceededError
from attest_sdk.jsonparse import parse_json

MAX_SAFE = 2**53 - 1


def test_valid_documents() -> None:
    assert parse_json('{"b": [3, 2], "a": {"y": -5, "x": 0}}') == {
        "b": [3, 2],
        "a": {"y": -5, "x": 0},
    }
    assert parse_json(' \t\r\n{\r\n"a":\t1}  ') == {"a": 1}
    assert parse_json("{}") == {}
    assert parse_json("[]") == []
    assert parse_json("[true, false, null, 0, -0]") == [True, False, None, 0, 0]
    assert parse_json(f"{MAX_SAFE}") == MAX_SAFE
    assert parse_json(f"{-MAX_SAFE}") == -MAX_SAFE


def test_string_escapes() -> None:
    assert parse_json(r'"\"\\\/\b\f\n\r\t"') == '"\\/\b\f\n\r\t'
    assert parse_json(r'"caf\u00e9"') == "caf\u00e9"
    assert parse_json(r'"\ud834\udd1e"') == "\U0001d11e"
    assert parse_json(r'"\u0000"') == "\x00"


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("01", "leading-zero"),
        ("-01", "leading-zero"),
        ("+1", "bad-number"),
        ("-", "bad-number"),
        ("1.5", "non-integer-number"),
        ("1.0", "non-integer-number"),
        ("1e3", "non-integer-number"),
        ("1E-3", "non-integer-number"),
        ("NaN", "non-json-constant"),
        ("Infinity", "non-json-constant"),
        ("-Infinity", "non-json-constant"),
        ("+Infinity", "non-json-constant"),
        ("undefined", "non-json-constant"),
        ("True", "non-json-constant"),
        ("nulx", "bad-literal"),
        ("trux", "bad-literal"),
        ("tru", "unexpected-end"),
        ("nul", "unexpected-end"),
        (r'"\x"', "bad-escape"),
        (r'"\a"', "bad-escape"),
        (r'"\u123"', "bad-escape"),
        (r'"\uzzzz"', "bad-escape"),
        (r'"\ud800"', "lone-surrogate"),
        (r'"\udc00"', "lone-surrogate"),
        (r'"\ud800A"', "lone-surrogate"),
        (r'"\ud800\ud800"', "lone-surrogate"),
        ('"a\x01b"', "unescaped-control"),
        ('"abc', "unterminated-string"),
        ("", "empty-document"),
        ("   ", "empty-document"),
        ("[1", "unexpected-end"),
        ('{"a": 1', "unexpected-end"),
        ("[1,]", "unexpected-value"),
        ('{"a"}', "expected-colon"),
        ("{1: 2}", "expected-quote"),
        ('{"a": 1, "a": 2}', "duplicate-key"),
        ('{"a": {"b": 1, "b": 2}}', "duplicate-key"),
        ("{} trailing", "trailing-data"),
        ("1 2", "trailing-data"),
    ],
)
def test_invalid_documents_refuse(text: str, reason: str) -> None:
    with pytest.raises(AttestError) as err:
        parse_json(text)
    assert err.value.reason_class == reason, text


def test_depth_boundary() -> None:
    parse_json("[" * 32 + "0" + "]" * 32)
    with pytest.raises(LimitExceededError) as err:
        parse_json("[" * 33 + "0" + "]" * 33)
    assert err.value.reason_class == "limit-depth"


def test_source_limits_apply_end_to_end() -> None:
    with pytest.raises(LimitExceededError) as err_limit:
        canonical.parse_bytes(b"x" * 1048577)
    assert err_limit.value.reason_class == "limit-source"
    with pytest.raises(AttestError) as err:
        canonical.parse_bytes(b"\xff")
    assert err.value.reason_class == "invalid-utf8"
