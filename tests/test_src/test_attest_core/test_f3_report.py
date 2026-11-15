"""F3 validation report assembly: schema, inventory, severity (unit)."""

from __future__ import annotations

from typing import Any

import pytest
from f3_compose_pkg import RID_ONE, pieces, setup
from f3_identity_pkg import CAMPAIGN_ID, INVOCATION_1, INVOCATION_2, attempt, campaign, entry
from f3_series_pkg import camp, invocation, package

from attest_core.f3_compose import compose_package
from attest_core.f3_identity import PackageRecords
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_report import STATUS_INFRA, STATUS_REFUSED, STATUS_VALIDATED, build_report
from attest_core.f3_series import Diagnostic, compute_series


def _content(view: Any, evidence: set[str], record_ids: dict[Any, str], required: int) -> Any:
    """Real P3/P5/P6/P7 content over a view, as build_report inputs."""
    parts = pieces(view, evidence, record_ids, required)
    ordered = compute_series(view.campaigns[0])
    composed = compose_package(**parts)
    return {
        "identity": parts["identity"],
        "series": parts["series_report"],
        "measurements": tuple(parts["measurements"][inv] for inv in sorted(parts["measurements"])),
        "attributes": tuple(parts["attributes"][inv] for inv in sorted(parts["attributes"])),
        "quorums": tuple(parts["quorums"][s.key] for s in ordered),
        "composition": composed.series,
    }


def _report(view: Any, evidence: set[str], content: Any) -> Any:
    identity, series = content["identity"], content["series"]
    return build_report(
        status=STATUS_VALIDATED,
        package=view,
        evidence_ok=evidence,
        findings=(*identity.findings, *series.findings),
        diagnostics=series.diagnostics,
        measurements=content["measurements"],
        attributes=content["attributes"],
        quorums=content["quorums"],
        composition=content["composition"],
    )


def test_valid_report_core() -> None:
    campaign, view = setup([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")])
    key = compute_series(campaign)[0].key
    evidence = {INVOCATION_1, INVOCATION_2}
    report = _report(view, evidence, _content(view, evidence, {key: RID_ONE}, 1))
    assert report.severity == "VALID"
    assert report.campaign_id == campaign.campaign_id
    assert [(i.invocation_id, i.evidence_verified) for i in report.inventory] == [
        (INVOCATION_1, True),
        (INVOCATION_2, True),
    ]
    assert [len(i.attempts) for i in report.inventory] == [3, 3]
    assert report.quorums[0].met is True
    assert report.composition[0].summary.n_total == 3
    partial = _report(view, {INVOCATION_1}, _content(view, evidence, {key: RID_ONE}, 1))
    assert [i.evidence_verified for i in partial.inventory] == [True, False]


def test_severity_worst_wins() -> None:
    """INVALID beats INCOMPLETE beats VALID (§13 aggregation)."""
    bad = Finding(severity="INVALID", rule="V-B1", location="$", reason="x")
    gap = Finding(severity="INCOMPLETE", rule="V-B7", location="$", reason="y")
    view = PackageRecords()

    def severity_of(findings: Any) -> Any:
        return build_report(
            status=STATUS_VALIDATED, package=view, evidence_ok=set(), findings=findings
        ).severity

    assert severity_of((bad, gap)) == "INVALID"
    assert severity_of((gap,)) == "INCOMPLETE"
    assert severity_of(()) == "VALID"


def test_infra_severity_none_only_when_empty() -> None:
    """No validation content is None, never a success; partials aggregate."""
    view = PackageRecords()
    bare = build_report(status=STATUS_INFRA, package=view, evidence_ok=set(), findings=())
    assert bare.severity is None
    gap = Finding(severity="INCOMPLETE", rule="V-B1", location="$", reason="y")
    partial = build_report(status=STATUS_INFRA, package=view, evidence_ok=set(), findings=(gap,))
    assert partial.severity == "INCOMPLETE"


def test_refused_severity_from_findings() -> None:
    """Refusal carries the pin findings; severity still aggregates them."""
    pin = Finding(severity="INVALID", rule="V-B6", location="$.canonicalization", reason="z")
    report = build_report(
        status=STATUS_REFUSED, package=PackageRecords(), evidence_ok=set(), findings=(pin,)
    )
    assert report.severity == "INVALID"


def test_unknown_status_rejected() -> None:
    with pytest.raises(ValueError, match="unknown validation status"):
        build_report(status="bogus", package=PackageRecords(), evidence_ok=set(), findings=())


def test_campaign_id_single_multi_zero() -> None:
    """One campaign identifies the report; otherwise None (never invented)."""
    one = campaign([entry(INVOCATION_1, 1)])
    two = campaign([entry(INVOCATION_2, 1)])
    single = build_report(
        status=STATUS_VALIDATED,
        package=PackageRecords(campaigns=(one,)),
        evidence_ok=set(),
        findings=(),
    )
    assert single.campaign_id == CAMPAIGN_ID
    multi = build_report(
        status=STATUS_VALIDATED,
        package=PackageRecords(campaigns=(one, two)),
        evidence_ok=set(),
        findings=(),
    )
    assert multi.campaign_id is None
    empty = build_report(
        status=STATUS_VALIDATED, package=PackageRecords(), evidence_ok=set(), findings=()
    )
    assert empty.campaign_id is None


def test_inventory_declared_unobserved_and_strays() -> None:
    """Inventory unions declared and observed ids, sorted, with flags."""
    camp_record = campaign([entry(INVOCATION_1, 1), entry(INVOCATION_2, 2)])
    view = PackageRecords(campaigns=(camp_record,), attempts=(attempt(INVOCATION_2, 1),))
    report = build_report(
        status=STATUS_VALIDATED, package=view, evidence_ok={INVOCATION_1}, findings=()
    )
    assert [(i.invocation_id, len(i.attempts), i.evidence_verified) for i in report.inventory] == [
        (INVOCATION_1, 0, True),
        (INVOCATION_2, 1, False),
    ]


def test_diagnostics_never_affect_severity() -> None:
    """Notes ride along verbatim without changing the determination."""
    note = Diagnostic(rule="W4", location="env[0]", reason="unknown class")
    report = build_report(
        status=STATUS_VALIDATED,
        package=PackageRecords(),
        evidence_ok=set(),
        findings=(),
        diagnostics=(note,),
    )
    assert (report.severity, report.diagnostics) == ("VALID", (note,))


def test_composition_content_preserved() -> None:
    """P7 series content, including absent summaries, survives assembly."""
    campaign = camp([(INVOCATION_1, "measured")], warmups=[])
    _, tot, environment = invocation(INVOCATION_1, sample="measured")
    made = [attempt(INVOCATION_1, n, censored=True) for n in (1, 2, 3)]
    view = package(campaign, (made, tot, environment))
    key = compute_series(campaign)[0].key
    report = _report(view, {INVOCATION_1}, _content(view, {INVOCATION_1}, {key: RID_ONE}, 1))
    (one,) = report.composition
    assert one.summary is None
    assert "0 successful" in (one.absent_reason or "")
    assert report.quorums[0].excluded == ((INVOCATION_1, "measurement-inconclusive"),)
    assert report.severity == "VALID"
