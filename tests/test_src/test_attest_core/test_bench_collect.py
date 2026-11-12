"""Repetition composition: provenance, retention, and summary wiring."""

import json
from decimal import Decimal
from typing import Any

import pytest

from attest_core.bench_collect import build_summary, load_repetitions
from attest_core.bench_stats import BenchStatsError

_TOTAL = '{"record_type": "total", "elapsed_s": "9.0", "profile": "standard"}'


def _line(n: int, s: str, o: str = "PASS", c: bool = False) -> str:
    record = {"record_type": "attempt", "attempt": n, "elapsed_s": s, "outcome": o}
    record["censored"] = c
    return json.dumps(record)


def test_empty_input() -> None:
    observations, unparsed, provenance = load_repetitions([])
    assert (observations, unparsed, provenance) == ([], [], [])
    summary = build_summary([], required_successful=1)
    assert summary["n_total"] == 0 and summary["complete"] is False
    assert summary["unparsed"] == [] and summary["provenance"] == []


def test_single_source() -> None:
    text = "\n".join([_line(1, "0.5"), _line(2, "1.5"), _line(3, "2.5"), _TOTAL])
    observations, unparsed, provenance = load_repetitions([text])
    assert [o.repetition for o in observations] == [1, 2, 3]
    assert [(p["repetition"], p["source_position"], p["attempt"]) for p in provenance] == [
        (1, 1, 1),
        (2, 1, 2),
        (3, 1, 3),
    ]
    assert set(provenance[0]) == {"repetition", "source_position", "attempt"}
    assert [(p["source_position"], p["reason"]) for p in unparsed] == [
        (1, "skipped:record-type-total")
    ]


def test_multiple_sources() -> None:
    first = "\n".join([_line(1, "0.5"), _line(2, "1.5"), _line(3, "2.5")])
    second = "\n".join([_line(1, "3.5"), _line(2, "4.5"), _line(3, "5.5")])
    observations, unparsed, provenance = load_repetitions([first, second])
    assert [o.repetition for o in observations] == [1, 2, 3, 4, 5, 6]
    assert [(p["repetition"], p["source_position"], p["attempt"]) for p in provenance] == [
        (1, 1, 1),
        (2, 1, 2),
        (3, 1, 3),
        (4, 2, 1),
        (5, 2, 2),
        (6, 2, 3),
    ]
    assert len(observations) == len(provenance) == 6
    assert len({(p["source_position"], p["attempt"]) for p in provenance}) == 6
    assert unparsed == []


def test_source_order_changes_provenance() -> None:
    first = _line(1, "0.5")
    second = _line(1, "9.5")
    _, _, forward = load_repetitions([first, second])
    _, _, backward = load_repetitions([second, first])
    assert [(p["repetition"], p["source_position"]) for p in forward] == [(1, 1), (2, 2)]
    assert [(p["repetition"], p["source_position"]) for p in backward] == [(1, 1), (2, 2)]
    assert forward[0]["attempt"] == backward[0]["attempt"] == 1


def test_within_source_duplicate_rejected() -> None:
    text = _line(1, "0.5") + "\n" + _line(1, "1.5")
    with pytest.raises(BenchStatsError, match="duplicate repetition"):
        load_repetitions([text])
    with pytest.raises(BenchStatsError, match="duplicate repetition"):
        build_summary([text], required_successful=1)


def test_problems_tagged_and_accounted() -> None:
    first = "\n".join([_line(1, "0.5"), _TOTAL])
    second = "\n".join(["not json", "", _line(1, "1.5")])
    third = "\n".join(['{"record_type": "bogus"}', '{"record_type": "attempt"}'])
    observations, unparsed, _ = load_repetitions([first, second, third])
    assert [o.repetition for o in observations] == [1, 2]
    assert [(p["source_position"], p["reason"]) for p in unparsed] == [
        (1, "skipped:record-type-total"),
        (2, "invalid-json:Expecting value"),
        (2, "blank-line"),
        (3, "unknown-record-type:bogus"),
        (3, "missing-field:attempt"),
    ]
    assert [p["line"] for p in unparsed] == [2, 1, 2, 1, 2]
    assert len(observations) + len(unparsed) == 2 + 3 + 2


def test_mixed_statistics() -> None:
    first = "\n".join([_line(1, "0.5"), _line(2, "0.5", "VIOLATION"), _line(3, "1.5")])
    second = "\n".join(
        [
            _line(1, "9.0", "INFRA_FAILURE"),
            _line(2, "9.0", "TIMEOUT", True),
            _line(3, "9.0", c=True),
        ]
    )
    summary = build_summary([first, second], required_successful=3)
    assert summary["n_total"] == 6
    assert summary["n_successful"] == 3
    assert summary["median_s"] == "0.5"
    assert summary["outcome_counts"] == {
        "INFRA_FAILURE": 1,
        "PASS": 3,
        "TIMEOUT": 1,
        "VIOLATION": 1,
    }
    assert summary["complete"] is True


def test_warmup_exclusion_by_selection() -> None:
    warmup = "\n".join([_line(1, "99.0"), _line(2, "99.0"), _line(3, "99.0")])
    measured = "\n".join([_line(1, "0.5"), _line(2, "1.5")])
    observations, _, provenance = load_repetitions([measured])
    assert [o.elapsed_s for o in observations] == [Decimal("0.5"), Decimal("1.5")]
    assert all(p["source_position"] == 1 for p in provenance)
    both, _, _ = load_repetitions([warmup, measured])
    assert len(both) == 5


def test_context_echoed() -> None:
    context = {"warmup_invocations_excluded": 2, "sampling_unit": "supervised_attempt"}
    summary = build_summary([_line(1, "0.5")], required_successful=1, context=context)
    assert summary["context"] == context
    assert summary["context"] is not context


def test_quorum_overshoot() -> None:
    texts = ["\n".join([_line(1, "0.5"), _line(2, "1.5"), _line(3, "2.5")]) for _ in range(2)]
    assert build_summary(texts, required_successful=5)["complete"] is True
    assert build_summary(texts, required_successful=10)["complete"] is False


def test_empty_statistics_null() -> None:
    text = "\n".join([_line(1, "9.0", "INFRA_FAILURE"), _line(2, "9.0", "TIMEOUT", True)])
    summary = build_summary([text], required_successful=1)
    assert summary["n_successful"] == 0
    assert (summary["min_s"], summary["median_s"], summary["max_s"], summary["range_s"]) == (
        None,
    ) * 4
    assert summary["complete"] is False


def test_deterministic_serialization() -> None:
    texts = ["\n".join([_line(2, "1.5"), _line(1, "0.5")]), "not json"]
    one = build_summary(texts, required_successful=2)
    two = build_summary(list(texts), required_successful=2)
    assert one == two
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


def test_inputs_not_mutated() -> None:
    texts = ["\n".join([_line(1, "0.5"), "oops"]), _line(1, "1.5")]
    snapshot = list(texts)
    context = {"k": "v"}
    build_summary(texts, required_successful=1, context=context)
    load_repetitions(texts)
    assert texts == snapshot
    assert context == {"k": "v"}


@pytest.mark.parametrize("bad", ["nope", [42], [None], [{"record_type": "attempt"}]])
def test_invalid_input_types_rejected(bad: Any) -> None:
    with pytest.raises(BenchStatsError):
        load_repetitions(bad)


def test_build_summary_attaches_problems_and_provenance() -> None:
    first = "\n".join([_line(1, "0.5"), "oops", _TOTAL])
    second = "\n".join([_line(1, "1.5", "VIOLATION"), "bad", _line(2, "2.5")])
    summary = build_summary([first, second], required_successful=3)
    problems = [
        (p["source_position"], p["line"], p["raw"], p["reason"]) for p in summary["unparsed"]
    ]
    assert problems == [
        (1, 2, "oops", "invalid-json:Expecting value"),
        (1, 3, _TOTAL, "skipped:record-type-total"),
        (2, 2, "bad", "invalid-json:Expecting value"),
    ]
    assert [
        (p["repetition"], p["source_position"], p["attempt"]) for p in summary["provenance"]
    ] == [
        (1, 1, 1),
        (2, 2, 1),
        (3, 2, 2),
    ]
    assert summary["n_successful"] == 3
    assert summary["median_s"] == "1.5"
