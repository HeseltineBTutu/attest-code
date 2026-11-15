"""F3 P7 acceptance: isolation, absence, upstream handling, determinism."""

from __future__ import annotations

import pytest
from f3_compose_pkg import RID_ONE, RID_TWO, orchestrate, pieces, setup
from f3_fixtures import assert_fails
from f3_identity_pkg import INVOCATION_1, INVOCATION_2, attempt
from f3_series_pkg import camp, invocation, package

from attest_core.f3_compare_attrs import derive_attributes
from attest_core.f3_compose import compose_package
from attest_core.f3_identity import IdentityReport, PackageRecords, check_identity
from attest_core.f3_measure import InvocationMeasurement
from attest_core.f3_quorum import evaluate_quorum
from attest_core.f3_series import compute_series
from attest_core.f3_series_check import check_package_series


def test_per_series_isolation() -> None:
    """Each series composes its own observations; nothing pools (§10.4)."""
    campaign = camp(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        warmups=[],
        entry_targets={INVOCATION_2: "baseline"},
        targets=["repaired", "baseline"],
    )
    first = invocation(INVOCATION_1, sample="measured")
    second = invocation(INVOCATION_2, sample="measured", target="baseline")
    view = package(campaign, first, second)
    keys = [s.key for s in compute_series(campaign)]
    ids = dict(zip(keys, (RID_ONE, RID_TWO), strict=True))
    result = orchestrate(view, {INVOCATION_1, INVOCATION_2}, ids, 1)
    assert [one.summary.n_total for one in result.series] == [3, 3]
    assert [one.summary.target for one in result.series] == ["repaired", "baseline"]
    assert [one.summary.series for one in result.series] == [
        "repaired/b1/latency",
        "baseline/b2/latency",
    ]
    obs = [set(one.summary.observation_ids) for one in result.series]
    assert obs[0].isdisjoint(obs[1])
    assert result.severity == "VALID"


def test_absent_summary_all_censored() -> None:
    """Zero successful samples: explicit absence, carried quorum, VALID."""
    campaign = camp([(INVOCATION_1, "measured")], warmups=[])
    _, tot, environment = invocation(INVOCATION_1, sample="measured")
    made = [attempt(INVOCATION_1, n, censored=True) for n in (1, 2, 3)]
    view = package(campaign, (made, tot, environment))
    key = compute_series(campaign)[0].key
    result = orchestrate(view, {INVOCATION_1}, {key: RID_ONE}, 1)
    (one,) = result.series
    assert one.summary is None
    assert "0 successful" in one.absent_reason
    assert one.quorum.excluded == ((INVOCATION_1, "measurement-inconclusive"),)
    assert (result.severity, result.ok) == ("VALID", True)


@pytest.mark.parametrize(
    ("field", "section", "reason"),
    [
        ("quorums", "10.6", "missing upstream quorum"),
        ("measurements", "10.6", "missing upstream measurement"),
        ("attributes", "10.7", "missing upstream attributes"),
        ("record_ids", "7.5", "missing upstream record_id"),
    ],
)
def test_missing_upstream_refuses(field: str, section: str, reason: str) -> None:
    """Each series needs its quorum, measurement, attributes, and id."""
    campaign, view = setup([(INVOCATION_1, "measured")])
    key = compute_series(campaign)[0].key
    inputs = pieces(view, {INVOCATION_1}, {key: RID_ONE}, 1)
    inputs[field] = {}
    assert_fails(
        lambda _: compose_package(**inputs),
        None,
        rule="COMPOSE",
        section=section,
        location="$",
        reason=reason,
    )


def test_surplus_upstream_refuses() -> None:
    """Upstream content outside the package is incompatible, never ignored."""
    campaign, view = setup([(INVOCATION_1, "measured")])
    key = compute_series(campaign)[0].key
    inputs = pieces(view, {INVOCATION_1}, {key: RID_ONE}, 1)
    foreign = ("other", "Medium", "w", "ab" * 32, 9)
    inputs["quorums"][foreign] = inputs["quorums"][key]
    assert_fails(
        lambda _: compose_package(**inputs),
        None,
        rule="COMPOSE",
        section="10.6",
        location="$",
        reason="incompatible quorum",
    )
    inputs["quorums"] = {key: inputs["quorums"][key]}
    inputs["measurements"]["surplus-invocation"] = inputs["measurements"][INVOCATION_1]
    assert_fails(
        lambda _: compose_package(**inputs),
        None,
        rule="COMPOSE",
        section="10.6",
        location="$",
        reason="incompatible measurement",
    )


def test_foreign_series_refused() -> None:
    """Reports from another package never compose with local records (I2)."""
    _, view = setup([(INVOCATION_1, "measured")])
    other = camp([(INVOCATION_2, "measured")], warmups=[])
    group = invocation(INVOCATION_2, sample="measured")
    report = check_package_series(package(other, group))
    series = report.series[0]
    quorum = evaluate_quorum(
        series=series, measurements={}, evidence_ok=set(), required_successful=1
    )
    inputs = {
        "package": view,
        "identity": check_identity(view),
        "workload_findings": (),
        "series_report": report,
        "measurements": {INVOCATION_2: InvocationMeasurement(INVOCATION_2, False, None)},
        "quorums": {series.key: quorum},
        "attributes": {INVOCATION_2: derive_attributes(INVOCATION_2, [], None)},
        "record_ids": {series.key: RID_ONE},
    }
    assert_fails(
        lambda _: compose_package(**inputs),
        None,
        rule="COMPOSE",
        section="10.4",
        location="$",
        reason="I2",
    )


def test_multi_campaign_refused() -> None:
    """Defensive: real P3 always gates first, yet the composer still refuses."""
    first, _ = setup([(INVOCATION_1, "measured")])
    second, _ = setup([(INVOCATION_2, "measured")])
    view = PackageRecords(campaigns=(first, second), attempts=(), totals=(), envs=())
    inputs = {
        "package": view,
        "identity": IdentityReport(findings=()),
        "workload_findings": (),
        "series_report": check_package_series(view),
        "measurements": {},
        "quorums": {},
        "attributes": {},
        "record_ids": {},
    }
    assert_fails(
        lambda _: compose_package(**inputs),
        None,
        rule="COMPOSE",
        section="10.4",
        location="$",
        reason="no single campaign",
    )


def test_composition_deterministic() -> None:
    """Record collection order never affects the composed package."""
    campaign, view = setup([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")])
    key = compute_series(campaign)[0].key
    evidence = {INVOCATION_1, INVOCATION_2}
    first = orchestrate(view, evidence, {key: RID_ONE}, 1)
    shuffled = PackageRecords(
        campaigns=view.campaigns,
        attempts=tuple(reversed(view.attempts)),
        totals=tuple(reversed(view.totals)),
        envs=tuple(reversed(view.envs)),
    )
    second = orchestrate(shuffled, set(evidence), {key: RID_ONE}, 1)
    assert first == second
