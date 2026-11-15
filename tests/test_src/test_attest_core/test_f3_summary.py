"""F3 per-series summary computation (§7.5, §10.4)."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from f3_identity_pkg import CAMPAIGN_ID, INVOCATION_1, INVOCATION_2, TRIPLE, attempt

from attest_core import f3_fields as ff
from attest_core.bench_stats import Observation, summarize
from attest_core.f3_summary import compose_summary, mint_record_id

KEY = ("repaired", *TRIPLE, 1)
RID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _compose(records: list[Any], **kwargs: Any) -> Any:
    params: dict[str, Any] = {
        "series_key": KEY,
        "member_invocations": frozenset({INVOCATION_1, INVOCATION_2}),
        "campaign_id": CAMPAIGN_ID,
        "record_id": RID,
    }
    params.update(kwargs)
    return compose_summary(records, **params)


def test_measured_partition_and_statistics() -> None:
    """Warmups excluded from every statistic, retained by id (I2, §6.3)."""
    made = [
        attempt(INVOCATION_1, 1, elapsed_s="1.000000000"),
        attempt(INVOCATION_1, 2, elapsed_s="3.000000000"),
        attempt(INVOCATION_1, 3, elapsed_s="2.000000000"),
    ]
    warm = [
        attempt(INVOCATION_2, 1, elapsed_s="9.000000000", sample_class="warmup"),
        attempt(INVOCATION_2, 2, elapsed_s="9.000000000", sample_class="warmup"),
    ]
    outcome = _compose([*made, *warm])
    assert outcome.absent_reason is None
    summary = outcome.summary
    assert (summary.n_total, summary.n_successful) == (3, 3)
    assert summary.outcome_counts == {"PASS": 3}
    assert (summary.min_s, summary.median_s, summary.max_s, summary.range_s) == ("1", "2", "3", "2")
    assert summary.observation_ids == sorted(r.record_id for r in made)
    assert summary.excluded_warmups == sorted(r.record_id for r in warm)
    assert summary.series == "repaired/b1/latency"
    assert (summary.target, summary.workload_class, summary.workload_id) == (
        "repaired",
        TRIPLE[0],
        TRIPLE[1],
    )
    assert summary.input_digest == TRIPLE[2]
    assert summary.statistic == "attempt"
    assert summary.emitted_by == "composer"
    assert summary.record_id == RID
    assert summary.invocation_id is None
    assert summary.context == {}


def test_mixed_outcomes_feed_counts_not_extremes() -> None:
    """VIOLATION counts as successful; censored/timeout do not (§10.3)."""
    made = [
        attempt(INVOCATION_1, 1, elapsed_s="1.000000000"),
        attempt(INVOCATION_1, 2, elapsed_s="2.000000000", outcome="VIOLATION"),
        attempt(INVOCATION_1, 3, elapsed_s="3.000000000", outcome="TIMEOUT"),
        attempt(INVOCATION_2, 1, elapsed_s="4.000000000", censored=True),
    ]
    summary = _compose(made).summary
    assert (summary.n_total, summary.n_successful) == (4, 2)
    assert summary.outcome_counts == {"PASS": 2, "TIMEOUT": 1, "VIOLATION": 1}
    assert (summary.min_s, summary.median_s, summary.max_s, summary.range_s) == (
        "1",
        "1.5",
        "2",
        "1",
    )


def test_even_median_exact_to_ten_places() -> None:
    """Even-count medians are exact decimals, never floats."""
    made = [
        attempt(INVOCATION_1, 1, elapsed_s="1.000000001"),
        attempt(INVOCATION_1, 2, elapsed_s="1.000000002"),
    ]
    summary = _compose(made).summary
    assert summary.median_s == "1.0000000015"
    assert summary.range_s == "0.000000001"


def test_input_order_irrelevant() -> None:
    """Identical sets compose identically regardless of collection order."""
    made = [
        attempt(INVOCATION_1, 1, elapsed_s="2.000000000"),
        attempt(INVOCATION_2, 1, elapsed_s="1.000000000"),
        attempt(INVOCATION_1, 2, elapsed_s="3.000000000", sample_class="warmup"),
    ]
    assert _compose(made) == _compose(list(reversed(made)))


def test_statistics_match_bench_stats_kernel() -> None:
    """The F3 stats core stays byte-identical to the shared kernel."""
    made = [
        attempt(INVOCATION_1, 1, elapsed_s="3.770075605"),
        attempt(INVOCATION_1, 2, elapsed_s="1.000000001"),
        attempt(INVOCATION_2, 1, elapsed_s="1.000000002"),
        attempt(INVOCATION_2, 2, elapsed_s="9.999999999", outcome="VIOLATION"),
        attempt(INVOCATION_2, 3, elapsed_s="0.500000000", censored=True),
    ]
    summary = _compose(made).summary
    obs = [
        Observation(
            repetition=index, elapsed_s=Decimal(r.elapsed_s), outcome=r.outcome, censored=r.censored
        )
        for index, r in enumerate(made, start=1)
    ]
    expected = summarize(obs, required_successful=1)
    assert (summary.n_total, summary.n_successful) == (
        expected["n_total"],
        expected["n_successful"],
    )
    assert summary.outcome_counts == expected["outcome_counts"]
    assert (summary.min_s, summary.median_s, summary.max_s, summary.range_s) == (
        expected["min_s"],
        expected["median_s"],
        expected["max_s"],
        expected["range_s"],
    )


def test_no_measured_observations_is_absent_not_invented() -> None:
    """A warmup-only set yields an explicit absence, never zeros."""
    warm = [attempt(INVOCATION_1, 1, sample_class="warmup")]
    outcome = _compose(warm)
    assert outcome.summary is None
    assert "no measured observations" in outcome.absent_reason


def test_no_successful_observations_is_absent() -> None:
    """Zero successful samples define no descriptive statistics."""
    made = [
        attempt(INVOCATION_1, 1, censored=True),
        attempt(INVOCATION_1, 2, outcome="TIMEOUT"),
    ]
    outcome = _compose(made)
    assert outcome.summary is None
    assert "0 successful" in outcome.absent_reason


def test_context_echoed_verbatim() -> None:
    """Caller provenance echoes into the summary untouched."""
    made = [attempt(INVOCATION_1, 1)]
    context = {"campaign": "s3-m5-1-campaign-03", "revision": "975d511"}
    assert _compose(made, context=context).summary.context == context


def test_minted_record_ids_are_uuid4() -> None:
    """Composer minting (§5.1) yields distinct valid UUIDv4 values."""
    first, second = mint_record_id(), mint_record_id()
    assert ff.uuid4(first, "7.5", "$") == first
    assert ff.uuid4(second, "7.5", "$") == second
    assert first != second
