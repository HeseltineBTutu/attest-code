"""F3 parse entry point: strict bytes parsing and kind dispatch."""

from __future__ import annotations

from typing import Any

import pytest
from f3_fixtures import assert_fails, to_bytes, valid_attempt, valid_total

from attest_core.f3_parse import parse_record_bytes
from attest_core.f3_records import AttemptRecord, TotalRecord


def test_parse_valid_attempt() -> None:
    record = parse_record_bytes(to_bytes(valid_attempt()))
    assert isinstance(record, AttemptRecord)
    assert (record.attempt, record.outcome, record.censored, record.pid) == (
        2,
        "PASS",
        False,
        41822,
    )


def test_parse_valid_total() -> None:
    record = parse_record_bytes(to_bytes(valid_total()))
    assert isinstance(record, TotalRecord)
    assert (record.verdict, record.attempts_total) == ("PASSED", 3)
    assert record.attempt_outcomes == {"PASS": 3}


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        ("not json", "bad-literal"),
        ("&", "unexpected-value"),
        ('{"a": 1} {"b": 2}', "trailing-data"),
        ('{"k": "v", "k": "w"}', "duplicate-key"),
        ('{"n": 1.5}', "non-integer-number"),
        ('{"n": 1e3}', "non-integer-number"),
        ('{"n": NaN}', "non-json-constant"),
        ('{"n": 01}', "leading-zero"),
        ('{"n": +1}', "bad-number"),
        ("", "empty-document"),
        ('{"a": "unterminated}', "unterminated-string"),
    ],
)
def test_parse_rejects_malformed_bytes(data: str, reason: str) -> None:
    assert_fails(
        parse_record_bytes, data.encode(), rule="PARSE", section="8.2", location="$", reason=reason
    )


def test_parse_rejects_encoding_and_limits() -> None:
    assert_fails(
        parse_record_bytes,
        b"\xef\xbb\xbf{}",
        rule="PARSE",
        section="8.2",
        location="$",
        reason="bom",
    )
    assert_fails(
        parse_record_bytes,
        b"\xff\xfe{}",
        rule="PARSE",
        section="8.2",
        location="$",
        reason="invalid-utf8",
    )
    assert_fails(
        parse_record_bytes,
        b" " * (1048576 + 1),
        rule="PARSE",
        section="8.2",
        location="$",
        reason="limit-source",
    )
    deep = "[" * 40 + "]" * 40
    assert_fails(
        parse_record_bytes, deep.encode(), rule="PARSE", section="8.2", location="$", reason="limit"
    )
    not_bytes: Any = "42"
    assert_fails(
        parse_record_bytes,
        not_bytes,
        rule="PARSE",
        section="8.2",
        location="$",
        reason="input must be bytes",
    )


def test_parse_rejects_non_object_and_kind() -> None:
    assert_fails(
        parse_record_bytes,
        b"[1, 2]",
        rule="V-B6",
        section="7",
        location="$",
        reason="must be an object",
    )
    assert_fails(
        parse_record_bytes,
        b"{}",
        rule="V-B6",
        section="7",
        location="$.record_kind",
        reason="unknown",
    )
    assert_fails(
        parse_record_bytes,
        b'{"record_kind": "attempts"}',
        rule="V-B6",
        section="7",
        location="$.record_kind",
        reason="unknown",
    )
    assert_fails(
        parse_record_bytes,
        b'{"record_kind": 7}',
        rule="V-B6",
        section="7",
        location="$.record_kind",
        reason="unknown",
    )
