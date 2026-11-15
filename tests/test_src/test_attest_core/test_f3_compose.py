"""F3 package summary composition over P3–P6 reports (§10.4, §10.6, §13)."""

from __future__ import annotations

from f3_compose_pkg import RID_ONE, orchestrate, pieces, setup
from f3_fixtures import assert_fails
from f3_identity_pkg import INVOCATION_1, INVOCATION_2, attempt, total
from f3_series_pkg import camp, invocation, package

from attest_core.f3_compose import compose_package
from attest_core.f3_identity import PackageRecords, check_identity
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_series import compute_series
from attest_core.f3_series_check import check_package_series


def test_clean_package_composes() -> None:
    campaign, view = setup([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")])
    key = compute_series(campaign)[0].key
    result = orchestrate(view, {INVOCATION_1, INVOCATION_2}, {key: RID_ONE}, 1)
    assert (result.severity, result.ok) == ("VALID", True)
    assert (result.findings, result.diagnostics) == ((), ())
    assert result.campaign_id == campaign.campaign_id
    (one,) = result.series
    assert one.summary.n_total == 3
    assert one.summary.excluded_warmups != []
    assert one.quorum.met is True
    assert one.quorum.eligible == (INVOCATION_2,)
    assert [m.invocation_id for m in one.measurements] == [INVOCATION_1, INVOCATION_2]
    assert one.stored_verdicts == ((INVOCATION_1, "PASSED"), (INVOCATION_2, "PASSED"))


def test_invalid_identity_refuses() -> None:
    """Nothing downstream consumes an INVALID package (§13)."""
    campaign = camp([(INVOCATION_1, "measured")], warmups=[])
    made, tot, environment = invocation(INVOCATION_1, sample="measured", target="baseline")
    view = package(campaign, (made, tot, environment))
    key = compute_series(campaign)[0].key
    assert_fails(
        lambda _: orchestrate(view, {INVOCATION_1}, {key: RID_ONE}, 1),
        None,
        rule="COMPOSE",
        section="13",
        location="$",
        reason="R-ID9",
    )


def test_invalid_series_prefix_refuses() -> None:
    campaign, view = setup([(INVOCATION_1, "measured"), (INVOCATION_2, "warmup")])
    key = compute_series(campaign)[0].key
    assert_fails(
        lambda _: orchestrate(view, {INVOCATION_1, INVOCATION_2}, {key: RID_ONE}, 1),
        None,
        rule="COMPOSE",
        section="13",
        location="$",
        reason="W3",
    )


def test_invalid_workload_refuses() -> None:
    """P4 findings gate composition opaquely (P7 reads severity only)."""
    campaign, view = setup([(INVOCATION_1, "measured")])
    key = compute_series(campaign)[0].key
    blocked = Finding(
        severity="INVALID",
        rule="V-B13",
        location="$.campaign.invocations[0].workload",
        reason="input_digest mismatch",
    )
    inputs = pieces(view, {INVOCATION_1}, {key: RID_ONE}, 1, findings=(blocked,))
    assert_fails(
        lambda _: compose_package(**inputs),
        None,
        rule="COMPOSE",
        section="13",
        location="$",
        reason="V-B13",
    )


def test_incomplete_gaps_carried_and_observed() -> None:
    """Short sets stay describable; gaps ride along verbatim (§10.4, §13)."""
    campaign = camp([(INVOCATION_1, "measured"), (INVOCATION_2, "measured")], warmups=[])
    full = invocation(INVOCATION_1, sample="measured")
    short = invocation(INVOCATION_2, sample="measured", attempt_numbers=(1, 2))
    view = package(campaign, full, short)
    key = compute_series(campaign)[0].key
    result = orchestrate(view, {INVOCATION_1, INVOCATION_2}, {key: RID_ONE}, 1)
    assert (result.severity, result.ok) == ("INCOMPLETE", False)
    assert result.findings == check_identity(view).findings
    assert result.series[0].summary.n_total == 5


def test_diagnostics_carried_without_severity() -> None:
    """P5 notes never fail the package and are never buried (§13)."""
    campaign = camp([(INVOCATION_1, "measured"), (INVOCATION_2, "measured")], warmups=[])
    first = invocation(INVOCATION_1, sample="measured")
    second = invocation(
        INVOCATION_2,
        sample="measured",
        env_overrides={"cpu_model": {"unavailable": "probe-failed"}},
    )
    view = package(campaign, first, second)
    key = compute_series(campaign)[0].key
    result = orchestrate(view, {INVOCATION_1, INVOCATION_2}, {key: RID_ONE}, 1)
    assert (result.severity, result.ok) == ("VALID", True)
    assert result.diagnostics == check_package_series(view).diagnostics
    assert [(d.rule, d.location) for d in result.diagnostics] == [("W4", "env[1]")]


def test_quorum_shortfall_stays_valid() -> None:
    """met false is a complete package, never incompleteness (Q1, §13)."""
    campaign, view = setup([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")])
    key = compute_series(campaign)[0].key
    result = orchestrate(view, {INVOCATION_1, INVOCATION_2}, {key: RID_ONE}, 5)
    one = result.series[0]
    assert one.quorum.met is False
    assert one.quorum.excluded == ((INVOCATION_1, "warmup"),)
    assert (result.severity, result.ok, result.findings) == ("VALID", True, ())


def test_stored_verdict_preserved_without_interpretation() -> None:
    """Opposite stored verdicts change carried values only, never content (M2)."""
    campaign = camp([(INVOCATION_1, "measured")], warmups=[])
    key = compute_series(campaign)[0].key
    made, _, environment = invocation(INVOCATION_1, sample="measured")
    passing = package(campaign, (made, total(INVOCATION_1, verdict="PASSED"), environment))
    failing = package(campaign, (made, total(INVOCATION_1, verdict="FAILED"), environment))
    first = orchestrate(passing, {INVOCATION_1}, {key: RID_ONE}, 1)
    second = orchestrate(failing, {INVOCATION_1}, {key: RID_ONE}, 1)
    assert first.series[0].summary == second.series[0].summary
    assert first.series[0].stored_verdicts == ((INVOCATION_1, "PASSED"),)
    assert second.series[0].stored_verdicts == ((INVOCATION_1, "FAILED"),)
    assert (first.severity, second.severity) == ("VALID", "VALID")


def test_empty_package_composes_empty_with_gaps() -> None:
    """No campaign and no records: nothing composed, gaps carried."""
    view = PackageRecords(campaigns=(), attempts=(), totals=(), envs=())
    result = compose_package(**pieces(view, set(), {}, 1))
    assert (result.campaign_id, result.series) == (None, ())
    assert result.severity == "INCOMPLETE"
    assert result.findings == check_identity(view).findings


def test_records_without_campaign_refused() -> None:
    """Records with no series would be silently dropped, violating I2."""
    view = PackageRecords(campaigns=(), attempts=(attempt(INVOCATION_1, 1),), totals=(), envs=())
    inputs = pieces(view, set(), {}, 1)
    assert_fails(
        lambda _: compose_package(**inputs),
        None,
        rule="COMPOSE",
        section="10.4",
        location="$",
        reason="I2",
    )
