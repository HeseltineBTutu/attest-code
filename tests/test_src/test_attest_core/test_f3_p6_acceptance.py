"""P6 owner-decision acceptance: AQ-1 quorum counting, AQ-2 per-series scope."""

from __future__ import annotations

from typing import Any

from f3_identity_pkg import INVOCATION_1, INVOCATION_2, attempt
from f3_series_pkg import INVOCATION_3, camp, invocation, package

from attest_core.f3_identity import PackageRecords
from attest_core.f3_measure import measure_invocation
from attest_core.f3_quorum import evaluate_quorum
from attest_core.f3_series import compute_series


def _setup(specs: list[tuple[str, str]], **kwargs: Any) -> Any:
    warmups = [i + 1 for i, (_, sample) in enumerate(specs) if sample == "warmup"]
    campaign = camp(specs, warmups=warmups, **kwargs)
    groups = [invocation(inv, sample=sample) for inv, sample in specs]
    return campaign, package(campaign, *groups)


def _run(campaign: Any, view: Any, evidence: set[str], required: int, ordinal: int = 1) -> Any:
    series = [s for s in compute_series(campaign) if s.ordinal == ordinal][0]
    attempts: dict[str, list] = {}
    totals: dict[str, list] = {}
    envs: dict[str, int] = {}
    for record in view.attempts:
        attempts.setdefault(record.invocation_id, []).append(record)
    for record in view.totals:
        totals.setdefault(record.invocation_id, []).append(record)
    for record in view.envs:
        envs[record.invocation_id] = envs.get(record.invocation_id, 0) + 1
    by_inv = {
        inv: measure_invocation(inv, attempts[inv], totals.get(inv, []), envs.get(inv, 0))
        for inv in attempts
    }
    return evaluate_quorum(
        series=series, measurements=by_inv, evidence_ok=evidence, required_successful=required
    )


def _violation_view(specs: list[tuple[str, str]]) -> Any:
    warmups = [i + 1 for i, (_, sample) in enumerate(specs) if sample == "warmup"]
    campaign = camp(specs, warmups=warmups)
    groups = []
    for inv, sample in specs:
        if sample == "measured":
            made = [attempt(inv, n, outcome="VIOLATION") for n in (1, 2, 3)]
            _, tot, environment = invocation(inv, sample=sample)
            groups.append((made, tot, environment))
        else:
            groups.append(invocation(inv, sample=sample))
    return campaign, package(campaign, *groups)


def test_aq1_violation_shortfall_fails() -> None:
    """Two eligible violations against required three: met False, both eligible."""
    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")]
    campaign, view = _violation_view(specs)
    result = _run(campaign, view, {INVOCATION_1, INVOCATION_2}, 3)
    assert result.eligible == (INVOCATION_1, INVOCATION_2)
    assert (result.eligible_count, result.met) == (2, False)


def test_aq1_censored_violation_excluded() -> None:
    """A censored all-VIOLATION run is inconclusive, never a success."""
    campaign = camp([(INVOCATION_1, "measured")], warmups=[])
    made = [
        attempt(INVOCATION_1, 1, outcome="VIOLATION", censored=True),
        attempt(INVOCATION_1, 2, outcome="VIOLATION"),
        attempt(INVOCATION_1, 3, outcome="VIOLATION"),
    ]
    _, tot, environment = invocation(INVOCATION_1, sample="measured")
    view = package(campaign, (made, tot, environment))
    result = _run(campaign, view, {INVOCATION_1}, 1)
    assert result.excluded == ((INVOCATION_1, "measurement-inconclusive"),)
    assert result.met is False


def test_aq2_per_series_warmup_prefixes() -> None:
    """Each series keeps its own prefix; warm-ups never leak across series."""
    specs = [
        (INVOCATION_1, "warmup"),
        (INVOCATION_2, "measured"),
        (INVOCATION_3, "warmup"),
    ]
    campaign, view = _setup(specs, triples={INVOCATION_3: ("Medium", "other-workload", "ff" * 32)})
    first = _run(campaign, view, {INVOCATION_1, INVOCATION_2, INVOCATION_3}, 1, ordinal=1)
    second = _run(campaign, view, {INVOCATION_1, INVOCATION_2, INVOCATION_3}, 1, ordinal=2)
    assert first.excluded == ((INVOCATION_1, "warmup"),)
    assert first.eligible == (INVOCATION_2,)
    assert first.met is True
    assert second.excluded == ((INVOCATION_3, "warmup"),)
    assert second.met is False


def test_aq2_quorum_deterministic() -> None:
    """Member (run) order drives output; record input order is irrelevant."""
    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")]
    campaign, view = _setup(specs)
    evidence = {INVOCATION_2, INVOCATION_1}
    first = _run(campaign, view, evidence, 2)
    shuffled = PackageRecords(
        campaigns=view.campaigns,
        attempts=tuple(reversed(view.attempts)),
        totals=tuple(reversed(view.totals)),
        envs=tuple(reversed(view.envs)),
    )
    second = _run(campaign, shuffled, set(evidence), 2)
    assert (first.eligible, first.excluded, first.met) == (
        (INVOCATION_1, INVOCATION_2),
        (),
        True,
    )
    assert (second.eligible, second.excluded, second.met) == (
        first.eligible,
        first.excluded,
        first.met,
    )
