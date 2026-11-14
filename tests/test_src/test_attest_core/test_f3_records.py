"""F3 attempt and invocation_total record validation."""

from __future__ import annotations

from typing import Any

import pytest
from f3_fixtures import assert_fails, valid_attempt, valid_total

from attest_core.f3_records import validate_attempt, validate_total


def test_attempt_valid() -> None:
    record = validate_attempt(valid_attempt())
    assert record.record_kind == "attempt"
    assert record.invocation_id == "33333333-3333-4333-a333-333333333333"


def test_attempt_missing_and_unknown() -> None:
    payload = valid_attempt()
    del payload["outcome"]
    assert_fails(
        validate_attempt,
        payload,
        rule="V-B6",
        section="7.1",
        location="$.outcome",
        reason="missing",
    )
    assert_fails(
        validate_attempt,
        {**valid_attempt(), "zzz": 1},
        rule="V-B6",
        section="7.1",
        location="$",
        reason="'zzz'",
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("record_kind", "total"),
        ("record_version", 2),
        ("invocation_id", None),
        ("emitted_by", "worker"),
        ("target", "Has Space"),
        ("workload_class", "medium"),
        ("workload_id", ""),
        ("input_digest", "zz"),
        ("attempt", 0),
        ("attempt", True),
        ("sample_class", "cold"),
        ("elapsed_s", "1.5"),
        ("outcome", 7),
        ("censored", 1),
        ("profile", "turbo"),
        ("timeout_s", None),
        ("pid", 0),
        ("pid", 4.5),
    ],
)
def test_attempt_rejects_bad_fields(key: str, value: Any) -> None:
    assert_fails(
        validate_attempt,
        valid_attempt(**{key: value}),
        rule="V-B6",
        section="7.1",
        location=f"$.{key}",
    )


def test_attempt_accepts_huge_pid_shape() -> None:
    """Shape validation is unbounded; canonicalizer limits apply downstream."""
    assert validate_attempt(valid_attempt(pid=2**60)).pid == 2**60


def test_total_valid() -> None:
    record = validate_total(valid_total())
    assert record.attempt_outcomes == {"PASS": 3}


def test_total_missing_and_unknown() -> None:
    payload = valid_total()
    del payload["verdict"]
    assert_fails(
        validate_total, payload, rule="V-B6", section="7.2", location="$.verdict", reason="missing"
    )
    assert_fails(
        validate_total,
        {**valid_total(), "zzz": 1},
        rule="V-B6",
        section="7.2",
        location="$",
        reason="'zzz'",
    )


@pytest.mark.parametrize(
    ("key", "value", "location"),
    [
        ("verdict", "passed", "$.verdict"),
        ("verdict", "BANANA", "$.verdict"),
        ("verdict", None, "$.verdict"),
        ("verdict", 5, "$.verdict"),
        ("attempts_completed", -1, "$.attempts_completed"),
        ("attempts_total", True, "$.attempts_total"),
        ("sample_class", "lukewarm", "$.sample_class"),
        ("attempt_outcomes", {"NOPE": 1}, "$.attempt_outcomes"),
        ("attempt_outcomes", {"PASS": -1}, "$.attempt_outcomes.PASS"),
        ("attempt_outcomes", {"PASS": "3"}, "$.attempt_outcomes.PASS"),
        ("attempt_outcomes", [1], "$.attempt_outcomes"),
        ("invocation_id", None, "$.invocation_id"),
    ],
)
def test_total_rejects_bad_fields(key: str, value: Any, location: str) -> None:
    assert_fails(
        validate_total,
        valid_total(**{key: value}),
        rule="V-B6",
        section="7.2",
        location=location,
    )
