"""F3 count legs, N-chain, and total consistency (V-B7, V-B12, T1, T2)."""

from __future__ import annotations

from typing import Any

from f3_identity_pkg import (
    INVOCATION_1,
    attempt,
    campaign,
    env,
    issues,
    total,
    view,
)

from attest_core.f3_identity import check_identity

WHERE = "$.campaign.invocations[0]"


def _full(*numbers: int, **total_kw: Any) -> tuple[list[Any], Any, Any]:
    made = [attempt(INVOCATION_1, n) for n in numbers]
    return made, total(INVOCATION_1, **total_kw), env(INVOCATION_1)


def _check(made: list[Any], tot: Any, environment: Any, camp: Any = None) -> Any:
    camp = campaign() if camp is None else camp
    return check_identity(view(camp, attempts=made, totals=[tot], envs=[environment]))


def test_count_injection() -> None:
    made, tot, environment = _full(1, 2, 3, 4)
    report = _check(made, tot, environment)
    assert report.severity == "INVALID"
    assert ("INVALID", "V-B7", "total[0]") in issues(report)
    assert "injection" in str([item.reason for item in report.findings])


def test_count_short_is_incomplete() -> None:
    made, tot, environment = _full(1, 2)
    report = _check(made, tot, environment)
    assert report.severity == "INCOMPLETE"
    assert ("INCOMPLETE", "V-B7", "total[0]") in issues(report)
    assert ("INCOMPLETE", "V-B11", WHERE) in issues(report)


def test_chain_total_protocol_break() -> None:
    made = [attempt(INVOCATION_1, n) for n in (1, 2, 3, 4, 5)]
    tot = total(
        INVOCATION_1,
        attempts_completed=5,
        attempts_total=5,
        attempt_outcomes={"PASS": 5},
        elapsed_s="30.000000000",
    )
    report = _check(made, tot, env(INVOCATION_1))
    assert issues(report) == [("INVALID", "V-B12", "total[0]")]
    assert "total.attempts_total 5 != protocol.attempts_per_invocation 3" in (
        report.findings[0].reason
    )


def test_chain_protocol_engine_break() -> None:
    camp = campaign(protocol_n=5)
    made = [attempt(INVOCATION_1, n) for n in (1, 2, 3, 4, 5)]
    tot = total(
        INVOCATION_1,
        attempts_completed=5,
        attempts_total=5,
        attempt_outcomes={"PASS": 5},
        elapsed_s="30.000000000",
    )
    report = _check(made, tot, env(INVOCATION_1), camp)
    assert issues(report) == [("INVALID", "V-B8", "$.campaign.protocol.attempts_per_invocation")]


def test_completed_exceeds_total() -> None:
    made, tot, environment = _full(1, 2, 3, attempts_completed=4)
    report = _check(made, tot, environment)
    assert ("INVALID", "V-B12", "total[0].attempts_completed") in issues(report)


def test_partial_run_is_incomplete() -> None:
    made = [attempt(INVOCATION_1, n) for n in (1, 2)]
    tot = total(INVOCATION_1, attempts_completed=2, attempt_outcomes={"PASS": 2})
    report = _check(made, tot, env(INVOCATION_1))
    assert report.severity == "INCOMPLETE"
    assert ("INCOMPLETE", "V-B12", "total[0]") in issues(report)
    assert not [item for item in report.findings if item.rule in ("T1", "T2")]


def test_t1_violation() -> None:
    made, tot, environment = _full(1, 2, 3, elapsed_s="1.000000000")
    report = _check(made, tot, environment)
    assert ("INVALID", "T1", "total[0]") in issues(report)


def test_t2_violation() -> None:
    made, tot, environment = _full(1, 2, 3, attempt_outcomes={"PASS": 2, "VIOLATION": 1})
    report = _check(made, tot, environment)
    assert ("INVALID", "T2", "total[0]") in issues(report)


def test_t2_strict_map_equality() -> None:
    """A zero-count extra key is not equal to the recount (strict T2)."""
    made, tot, environment = _full(1, 2, 3, attempt_outcomes={"PASS": 3, "VIOLATION": 0})
    report = _check(made, tot, environment)
    assert ("INVALID", "T2", "total[0]") in issues(report)


def test_t_gates_skip_incomplete_sets() -> None:
    made, tot, environment = _full(1, 2)
    report = _check(made, tot, environment)
    assert report.severity == "INCOMPLETE"
    assert not [item for item in report.findings if item.rule in ("T1", "T2")]
