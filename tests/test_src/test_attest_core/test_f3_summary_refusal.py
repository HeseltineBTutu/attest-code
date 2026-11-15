"""F3 summary refusals: dimension, membership, homogeneity (§10.4, §11.3)."""

from __future__ import annotations

from typing import Any

from f3_fixtures import assert_fails
from f3_identity_pkg import CAMPAIGN_ID, INVOCATION_1, INVOCATION_2, TRIPLE, attempt, total

from attest_core.f3_summary import compose_summary

KEY = ("repaired", *TRIPLE, 1)
RID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _compose(records: list[Any], **kwargs: Any) -> Any:
    params: dict[str, Any] = {
        "series_key": KEY,
        "member_invocations": frozenset({INVOCATION_1}),
        "campaign_id": CAMPAIGN_ID,
        "record_id": RID,
    }
    params.update(kwargs)
    return compose_summary(records, **params)


def _fails(records: list[Any], **kwargs: Any) -> Any:
    """Run composition for assert_fails with the given overrides."""
    return _compose(records, **kwargs)


def test_reserved_and_unknown_statistics_refused() -> None:
    """v1 defines statistic attempt only; invocation is reserved (§11.3)."""
    made = [attempt(INVOCATION_1, 1)]
    assert_fails(
        lambda v: _fails(v, statistic="invocation"),
        made,
        rule="COMPOSE",
        section="10.4",
        location="$.statistic",
        reason="reserved",
    )
    assert_fails(
        lambda v: _fails(v, statistic="p95"),
        made,
        rule="COMPOSE",
        section="10.4",
        location="$.statistic",
        reason="'attempt' only",
    )


def test_non_attempt_observation_refused() -> None:
    """Totals are a disjoint aggregation namespace (§11.2), never observations."""
    mixed: list[Any] = [attempt(INVOCATION_1, 1), total(INVOCATION_1)]
    assert_fails(
        _fails,
        mixed,
        rule="COMPOSE",
        section="10.4",
        location="$",
        reason="mixed-dimension",
    )


def test_foreign_invocation_record_refused() -> None:
    """Records outside the series set name their record ids (no pooling)."""
    foreign = attempt(INVOCATION_2, 1)
    assert_fails(
        _fails,
        [attempt(INVOCATION_1, 1), foreign],
        rule="COMPOSE",
        section="10.4",
        location="$",
        reason=foreign.record_id,
    )


def test_mixed_target_refused() -> None:
    """Mixed-target input sets are a hard composer error (§10.4)."""
    other = attempt(INVOCATION_1, 2, target="baseline")
    assert_fails(
        _fails,
        [attempt(INVOCATION_1, 1), other],
        rule="COMPOSE",
        section="10.4",
        location="$",
        reason=other.record_id,
    )


def test_mixed_workload_refused() -> None:
    """Mixed-workload input sets are a hard composer error (§10.4)."""
    other = attempt(INVOCATION_1, 2, workload_id="other-workload")
    assert_fails(
        _fails,
        [attempt(INVOCATION_1, 1), other],
        rule="COMPOSE",
        section="10.4",
        location="$",
        reason=other.record_id,
    )


def test_malformed_record_id_fails_summary_schema() -> None:
    """Caller-supplied ids must satisfy the §7.5 summary contract."""
    assert_fails(
        lambda v: _fails(v, record_id="not-a-uuid"),
        [attempt(INVOCATION_1, 1)],
        rule="V-B6",
        section="7.5",
        location="$.record_id",
        reason="UUID",
    )


def test_non_string_context_fails_summary_schema() -> None:
    """Context values must be strings (§7.5); nothing is coerced."""
    bad: dict[str, Any] = {"note": 7}
    assert_fails(
        lambda v: _fails(v, context=bad),
        [attempt(INVOCATION_1, 1)],
        rule="V-B6",
        section="7.5",
        location="$.context.note",
        reason="strings",
    )
