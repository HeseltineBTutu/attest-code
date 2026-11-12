"""Benchmark-run aggregation: parsing, statistics, determinism."""

import json
from decimal import Decimal, getcontext, setcontext
from typing import Any

import pytest

from attest_core.bench_stats import (
    BenchStatsError,
    Observation,
    parse_timing_jsonl,
    summarize,
)


def _line(**fields: Any) -> str:
    record: dict[str, Any] = {
        "record_type": "attempt",
        "attempt": 1,
        "elapsed_s": "0.500000000",
        "outcome": "PASS",
        "censored": False,
    }
    return json.dumps(record | fields)


def _obs(n: int, s: str, o: str = "PASS", c: bool = False) -> Observation:
    return Observation(repetition=n, elapsed_s=Decimal(s), outcome=o, censored=c)


def test_odd_median_min_max_range() -> None:
    summary = summarize([_obs(1, "1.5"), _obs(2, "0.5"), _obs(3, "2.0")], required_successful=3)
    assert (summary["min_s"], summary["median_s"], summary["max_s"]) == ("0.5", "1.5", "2")
    assert summary["range_s"] == "1.5"


def test_even_median_is_exact() -> None:
    summary = summarize([_obs(1, "0.1"), _obs(2, "0.2")], required_successful=2)
    assert summary["median_s"] == "0.15"
    rounding = summarize(
        [_obs(1, "0.000000000001"), _obs(2, "0.000000000002")], required_successful=2
    )
    assert rounding["median_s"] == "0.000000000002"


def test_mixed_outcomes() -> None:
    observations = [
        _obs(1, "0.5", "PASS"),
        _obs(2, "1.5", "VIOLATION"),
        _obs(3, "9.0", "INFRA_FAILURE"),
        _obs(4, "9.0", "TIMEOUT", True),
        _obs(5, "9.0", "PASS", True),
    ]
    summary = summarize(observations, required_successful=2)
    assert summary["n_total"] == 5
    assert summary["n_successful"] == 2
    assert summary["median_s"] == "1"
    assert summary["outcome_counts"] == {
        "INFRA_FAILURE": 1,
        "PASS": 2,
        "TIMEOUT": 1,
        "VIOLATION": 1,
    }
    assert list(summary["outcome_counts"]) == ["INFRA_FAILURE", "PASS", "TIMEOUT", "VIOLATION"]


def test_quorum_and_empty() -> None:
    empty = summarize([_obs(1, "9.0", "INFRA_FAILURE")], required_successful=1)
    assert empty["n_successful"] == 0
    assert (empty["min_s"], empty["median_s"], empty["max_s"], empty["range_s"]) == (None,) * 4
    assert empty["complete"] is False
    pair = [_obs(1, "0.5"), _obs(2, "1.5")]
    assert summarize(pair, required_successful=5)["complete"] is False
    assert summarize(pair, required_successful=2)["complete"] is True


def test_parse_robustness() -> None:
    text = "\n".join(
        [
            _line(),
            _line(elapsed_s="-1.5"),
            _line(elapsed_s="NaN"),
            _line(elapsed_s="abc"),
            _line(elapsed_s=0.5),
            _line(elapsed_s="-0.000000000"),
            _line(attempt="1"),
            _line(censored=0),
            _line(outcome="MAYBE"),
            _line(outcome=["PASS"]),
            _line(outcome={"k": "v"}),
            '{"record_type": "attempt", "elapsed_s": "0.5", "outcome": "PASS", "censored": false}',
            "not json",
            "[1, 2]",
            "",
            '{"record_type": "total", "elapsed_s": "1.0", "profile": "standard"}',
            '{"record_type": "bogus"}',
            '{"attempt": 3}',
        ]
    )
    observations, unparsed = parse_timing_jsonl(text)
    assert [(o.repetition, str(o.elapsed_s)) for o in observations] == [(1, "0.500000000")]
    assert [problem["reason"] for problem in unparsed] == [
        "invalid:elapsed_s must not be negative",
        "invalid:elapsed_s must be finite",
        "invalid-decimal:elapsed_s",
        "invalid-type:elapsed_s",
        "invalid:elapsed_s must not be negative zero",
        "invalid:repetition must be an int",
        "invalid:censored must be a bool",
        "invalid:unknown outcome: 'MAYBE'",
        "invalid:unknown outcome: ['PASS']",
        "invalid:unknown outcome: {'k': 'v'}",
        "missing-field:attempt",
        "invalid-json:Expecting value",
        "not-an-object",
        "blank-line",
        "skipped:record-type-total",
        "unknown-record-type:bogus",
        "missing-field:record_type",
    ]
    assert [problem["line"] for problem in unparsed] == list(range(2, 19))
    assert len(observations) + len(unparsed) == 18


def test_duplicates_rejected() -> None:
    with pytest.raises(BenchStatsError, match="duplicate repetition"):
        summarize([_obs(1, "0.5"), _obs(1, "1.5")], required_successful=1)
    with pytest.raises(BenchStatsError, match="duplicate repetition"):
        parse_timing_jsonl(_line(attempt=1) + "\n" + _line(attempt=1))


def test_order_and_determinism() -> None:
    first = [_obs(1, "2.0"), _obs(2, "0.5"), _obs(3, "0.5"), _obs(4, "1.5")]
    second = first[::-1]
    one = summarize(first, required_successful=4)
    two = summarize(second, required_successful=4)
    assert one == two
    assert one["median_s"] == "1"
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


def test_inputs_immutable() -> None:
    observations = [_obs(1, "0.5"), _obs(2, "1.5")]
    snapshot = list(observations)
    context = {"profile": "standard"}
    summarize(observations, required_successful=1, context=context)
    assert observations == snapshot
    assert context == {"profile": "standard"}


def test_context_echoed() -> None:
    context = {"profile": "hardened", "nested": [1, 2]}
    summary = summarize([_obs(1, "0.5")], required_successful=1, context=context)
    assert summary["context"] == context
    assert summary["context"] is not context
    assert summarize([_obs(1, "0.5")], required_successful=1)["context"] == {}


def test_large_sample_median() -> None:
    observations = [
        Observation(repetition=n, elapsed_s=Decimal(n) / 1000, outcome="PASS", censored=False)
        for n in range(1, 151)
    ]
    summary = summarize(observations, required_successful=100)
    assert summary["n_successful"] == 150
    assert summary["median_s"] == "0.0755"
    assert "p95" not in summary


def test_invalid_arguments() -> None:
    bad: Any = "nope"
    with pytest.raises(BenchStatsError):
        Observation(repetition=1, elapsed_s=Decimal("0.5"), outcome="PASS", censored=bad)
    with pytest.raises(BenchStatsError):
        Observation(repetition=2, elapsed_s=bad, outcome="PASS", censored=False)
    with pytest.raises(BenchStatsError):
        summarize([_obs(1, "0.5")], required_successful=0)
    with pytest.raises(BenchStatsError):
        summarize([_obs(1, "0.5")], required_successful=2, context=bad)
    with pytest.raises(BenchStatsError):
        summarize([bad], required_successful=1)
    unhashable: Any = [["PASS"], {"k": "v"}]
    for outcome in unhashable:
        with pytest.raises(BenchStatsError):
            Observation(repetition=9, elapsed_s=Decimal("0.5"), outcome=outcome, censored=False)


def test_canonicalization_ignores_ambient_context() -> None:
    observations = [_obs(1, "123.456"), _obs(2, "123.458")]
    expected = summarize(observations, required_successful=2)
    assert expected["median_s"] == "123.457"
    ambient = getcontext()
    saved = ambient.copy()
    ambient.prec = 2
    try:
        assert summarize(observations, required_successful=2) == expected
    finally:
        setcontext(saved)
