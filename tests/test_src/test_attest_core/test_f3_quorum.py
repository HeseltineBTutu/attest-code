"""F3 performance quorum per series (Q1), AQ-1/AQ-2 carried."""

from __future__ import annotations

from typing import Any

import f3_identity_pkg as pkg
import pytest
from f3_identity_pkg import INVOCATION_1, INVOCATION_2
from f3_series_pkg import INVOCATION_3, camp, invocation, package

import attest_core.f3_quorum as quorum_mod
from attest_core.f3_measure import measure_invocation
from attest_core.f3_quorum import evaluate_quorum
from attest_core.f3_series import compute_series


def _setup(specs: list, outcomes: dict[str, str]) -> Any:
    warmups = [i + 1 for i, (_, sample) in enumerate(specs) if sample == "warmup"]
    campaign = camp(specs, warmups=warmups)
    groups = []
    for inv, sample in specs:
        made, tot, environment = invocation(inv, sample=sample)
        if sample == "measured" and inv in outcomes:
            made = [pkg.attempt(inv, n, outcome=outcomes[inv]) for n in (1, 2, 3)]
        groups.append((made, tot, environment))
    return campaign, package(campaign, *groups)


def _evaluate(campaign: Any, view: Any, evidence: set[str], required: int) -> Any:
    return _evaluate_series(compute_series(campaign)[0], view, evidence, required)


def _evaluate_series(series: Any, view: Any, evidence: set[str], required: int) -> Any:
    by_inv: dict[str, Any] = {}
    attempts: dict[str, list] = {}
    totals: dict[str, list] = {}
    envs: dict[str, int] = {}
    for record in view.attempts:
        attempts.setdefault(record.invocation_id, []).append(record)
    for record in view.totals:
        totals.setdefault(record.invocation_id, []).append(record)
    for record in view.envs:
        envs[record.invocation_id] = envs.get(record.invocation_id, 0) + 1
    for inv in attempts:
        by_inv[inv] = measure_invocation(inv, attempts[inv], totals.get(inv, []), envs.get(inv, 0))
    return evaluate_quorum(
        series=series, measurements=by_inv, evidence_ok=evidence, required_successful=required
    )


def test_met_exactly_at_threshold() -> None:
    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")]
    campaign, view = _setup(specs, {})
    result = _evaluate(campaign, view, {INVOCATION_1, INVOCATION_2}, 2)
    assert (result.eligible_count, result.required_successful, result.met) == (2, 2, True)
    assert result.eligible == (INVOCATION_1, INVOCATION_2)
    assert result.excluded == ()


def test_shortfall_is_met_false() -> None:
    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")]
    campaign, view = _setup(specs, {})
    result = _evaluate(campaign, view, {INVOCATION_1, INVOCATION_2}, 5)
    assert (result.eligible_count, result.met) == (2, False)


def test_excluded_reasons() -> None:
    specs = [(INVOCATION_1, "warmup"), (INVOCATION_2, "measured"), (INVOCATION_3, "measured")]
    campaign, view = _setup(specs, {INVOCATION_3: "VIOLATION"})
    result = _evaluate(campaign, view, {INVOCATION_2}, 1)
    assert result.excluded == (
        (INVOCATION_1, "warmup"),
        (INVOCATION_3, "evidence-missing"),
    )
    assert result.eligible == (INVOCATION_2,)


def test_inconclusive_and_incomplete_excluded() -> None:
    campaign = camp([(INVOCATION_1, "measured"), (INVOCATION_2, "measured")], warmups=[])
    pairs = [(1, "PASS"), (2, "VIOLATION"), (3, "PASS")]
    mixed = [pkg.attempt(INVOCATION_1, n, outcome=o) for n, o in pairs]
    short = [pkg.attempt(INVOCATION_2, 1)]
    view = package(
        campaign,
        (mixed, pkg.total(INVOCATION_1), pkg.env(INVOCATION_1)),
        (short, pkg.total(INVOCATION_2), pkg.env(INVOCATION_2)),
    )
    result = _evaluate(campaign, view, {INVOCATION_1, INVOCATION_2}, 1)
    assert result.excluded == (
        (INVOCATION_1, "measurement-inconclusive"),
        (INVOCATION_2, "incomplete"),
    )
    assert result.met is False


def test_violations_count_per_design_aq1_open() -> None:
    """AQ-1: the design counts reproducible violations; owner approval pending."""
    assert quorum_mod.VIOLATION_COUNTS_AS_SUCCESSFUL is True
    specs = [(INVOCATION_1, "measured")]
    campaign, view = _setup(specs, {INVOCATION_1: "VIOLATION"})
    result = _evaluate(campaign, view, {INVOCATION_1}, 1)
    assert result.eligible == (INVOCATION_1,)
    assert result.met is True


def test_aq1_narrowing_is_one_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the owner rejects AQ-1, the flag narrows the predicate (restored after)."""
    monkeypatch.setattr(quorum_mod, "VIOLATION_COUNTS_AS_SUCCESSFUL", False)
    specs = [(INVOCATION_1, "measured")]
    campaign, view = _setup(specs, {INVOCATION_1: "VIOLATION"})
    result = _evaluate(campaign, view, {INVOCATION_1}, 1)
    assert result.excluded == ((INVOCATION_1, "measurement-inconclusive"),)


def test_quorum_per_series_aq2_open() -> None:
    """AQ-2: quorum evaluates per W3 series (proposed reading, P5 decomposition)."""
    campaign = camp(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        entry_targets={INVOCATION_2: "baseline"},
        targets=["repaired", "baseline"],
    )
    first = invocation(INVOCATION_1, sample="measured")
    second = invocation(INVOCATION_2, sample="measured", target="baseline")
    view = package(campaign, first, second)
    series = compute_series(campaign)
    assert len(series) == 2
    assert series[0].key != series[1].key
    first_result = _evaluate_series(series[0], view, {INVOCATION_1}, 1)
    second_result = _evaluate_series(series[1], view, set(), 1)
    assert (first_result.met, second_result.met) == (True, False)
    assert second_result.excluded == ((INVOCATION_2, "evidence-missing"),)
