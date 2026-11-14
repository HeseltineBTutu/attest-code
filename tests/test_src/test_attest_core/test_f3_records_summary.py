"""F3 summary records: strict structural validation (§7.5)."""

from __future__ import annotations

from typing import Any

import pytest
from f3_fixtures import UUID_A, assert_fails, valid_summary

from attest_core.f3_records_summary import validate_summary


def test_summary_valid() -> None:
    record = validate_summary(valid_summary())
    assert record.record_kind == "summary"
    assert record.invocation_id is None
    assert record.statistic == "attempt"
    assert record.observation_ids == [UUID_A, "550e8400-e29b-41d4-a716-446655440000"]


def test_summary_missing_and_unknown() -> None:
    payload = valid_summary()
    del payload["series"]
    assert_fails(
        validate_summary, payload, rule="V-B6", section="7.5", location="$.series", reason="missing"
    )
    assert_fails(
        validate_summary,
        {**valid_summary(), "zzz": 1},
        rule="V-B6",
        section="7.5",
        location="$",
        reason="'zzz'",
    )


@pytest.mark.parametrize(
    ("key", "value", "location"),
    [
        ("invocation_id", UUID_A, "$.invocation_id"),
        ("target", "Bad Target", "$.target"),
        ("workload_class", "medium", "$.workload_class"),
        ("workload_id", "", "$.workload_id"),
        ("input_digest", "zz", "$.input_digest"),
        ("series", "repaired/latency", "$.series"),
        ("series", "repaired/b0/latency", "$.series"),
        ("series", "repaired/b1/", "$.series"),
        ("series", 7, "$.series"),
        ("statistic", "invocation", "$.statistic"),
        ("statistic", "mean", "$.statistic"),
        ("observation_ids", [UUID_A, "nope"], "$.observation_ids[1]"),
        ("observation_ids", "notalist", "$.observation_ids"),
        ("excluded_warmups", [None], "$.excluded_warmups[0]"),
        ("n_total", -1, "$.n_total"),
        ("n_total", True, "$.n_total"),
        ("n_successful", "15", "$.n_successful"),
        ("outcome_counts", {"NOPE": 1}, "$.outcome_counts"),
        ("outcome_counts", {"PASS": -2}, "$.outcome_counts.PASS"),
        ("outcome_counts", [], "$.outcome_counts"),
        ("min_s", None, "$.min_s"),
        ("median_s", "5.0", "$.median_s"),
        ("max_s", "1e3", "$.max_s"),
        ("range_s", 7, "$.range_s"),
        ("context", {"ok": 1}, "$.context.ok"),
        ("context", {"": "x"}, "$.context"),
        ("context", [], "$.context"),
    ],
)
def test_summary_rejects_bad_fields(key: str, value: Any, location: str) -> None:
    assert_fails(
        validate_summary,
        valid_summary(**{key: value}),
        rule="V-B6",
        section="7.5",
        location=location,
    )


def test_summary_allows_empty_lists_and_zero_counts() -> None:
    """Shape accepts empties; partition/meaning rules belong later."""
    record = validate_summary(
        valid_summary(observation_ids=[], excluded_warmups=[], n_total=0, n_successful=0)
    )
    assert record.observation_ids == []
    assert record.n_total == 0
