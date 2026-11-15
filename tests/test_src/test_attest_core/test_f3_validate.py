"""F3 validator orchestration over filesystem packages (integration)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from f3_identity_pkg import INVOCATION_1, INVOCATION_2
from f3_input_pkg import file_entry, manifest, workload
from f3_validate_pkg import (
    attempt_dict,
    campaign_dict,
    env_dict,
    group_dicts,
    tamper_file,
    total_dict,
    write_campaign,
)

from attest_core.f3_measure import MEASUREMENT_CLEAN
from attest_core.f3_validate import validate_package

EVIDENCE = b"s3-report-bytes-0"


def _validate(
    root: Path,
    records: list[dict[str, Any]],
    evidence: dict[str, bytes],
    extra: dict[str, bytes] | None = None,
    **kw: Any,
) -> Any:
    write_campaign(root, records, evidence, extra)
    return validate_package(root, **kw)


def test_clean_package_validates(tmp_path: Path) -> None:
    """A coherent staged package validates end to end with full content."""
    shared = workload(manifest([file_entry()]))
    specs = [(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")]
    workloads = {INVOCATION_1: shared, INVOCATION_2: shared}
    records = [campaign_dict(specs, warmups=[1], required=1, workloads=workloads)]
    digest = shared["input_digest"]
    records.extend(group_dicts(INVOCATION_1, "warmup", input_digest=digest))
    records.extend(group_dicts(INVOCATION_2, "measured", input_digest=digest))
    evidence = {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE}
    report = _validate(tmp_path, records, evidence, extra={"inputs/data.bin": b"input-bytes"})
    assert (report.status, report.severity) == ("validated", "VALID")
    assert (report.findings, report.diagnostics) == ((), ())
    assert report.campaign_id is not None
    assert [m.m1 for m in report.measurements] == [MEASUREMENT_CLEAN] * 2
    assert len(report.attributes) == 2
    (quorum,) = report.quorums
    assert (quorum.met, quorum.eligible) == (True, (INVOCATION_2,))
    (series,) = report.composition
    assert series.summary.n_total == 3
    assert len(series.summary.excluded_warmups) == 3
    assert series.stored_verdicts == ((INVOCATION_1, "PASSED"), (INVOCATION_2, "PASSED"))
    reasons = [reason for q in report.quorums for _, reason in q.excluded]
    assert "consum" not in " ".join(reasons).lower()


def test_stage_findings_ordered_without_duplicates(tmp_path: Path) -> None:
    """Findings concatenate in execution order; each appears exactly once."""

    def stage(rule: str) -> int:
        if rule == "V-B1" or rule.startswith("V-P"):
            return 0
        if rule.startswith(("R-ID", "V-B7", "V-B10", "V-B11", "V-B12", "T")):
            return 1
        if rule == "V-B13":
            return 2
        if rule.startswith("W"):
            return 3
        raise AssertionError(f"unstaged rule: {rule}")

    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "warmup")]
    bad = workload(manifest(), digest="00" * 32)
    workloads = {INVOCATION_1: bad, INVOCATION_2: bad}
    records = [campaign_dict(specs, warmups=[2], required=1, workloads=workloads)]
    records.extend(group_dicts(INVOCATION_1, "measured", numbers=(1, 2), input_digest="00" * 32))
    records.extend(group_dicts(INVOCATION_2, "warmup", input_digest="00" * 32))
    evidence = {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE}
    write_campaign(tmp_path, records, evidence)
    tamper_file(tmp_path, f"evidence/{INVOCATION_2}.json")
    report = validate_package(tmp_path)
    rules = [f.rule for f in report.findings]
    assert rules[0] == "V-B1"
    assert [stage(rule) for rule in rules] == sorted(stage(rule) for rule in rules)
    assert len(set(report.findings)) == len(report.findings)
    assert {"V-B1", "V-B13", "W3"} <= set(rules)
    assert report.severity == "INVALID"


def test_p3_invalid_gates_quorum_and_composition(tmp_path: Path) -> None:
    """R-ID9 disagreement: no quorum, no composition, measurements kept."""
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured", target="baseline"))
    report = _validate(tmp_path, records, {INVOCATION_1: EVIDENCE})
    assert (report.status, report.severity) == ("validated", "INVALID")
    assert "R-ID9" in [f.rule for f in report.findings]
    assert (report.quorums, report.composition) == ((), ())
    assert [m.m1 for m in report.measurements] == [MEASUREMENT_CLEAN]
    assert len(report.attributes) == 1


def test_p4_invalid_keeps_quorum(tmp_path: Path) -> None:
    """V-B13 failure is not a quorum precondition (only P3 gates Q1)."""
    bad = workload(manifest(), digest="00" * 32)
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1, workloads={INVOCATION_1: bad})]
    records.extend(group_dicts(INVOCATION_1, "measured", input_digest="00" * 32))
    report = _validate(tmp_path, records, {INVOCATION_1: EVIDENCE})
    assert (report.status, report.severity) == ("validated", "INVALID")
    assert "V-B13" in [f.rule for f in report.findings]
    assert [q.met for q in report.quorums] == [True]
    assert report.composition == ()


def test_p5_invalid_keeps_quorum(tmp_path: Path) -> None:
    """W3 failure is not a quorum precondition either."""
    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "warmup")]
    records = [campaign_dict(specs, warmups=[2], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    records.extend(group_dicts(INVOCATION_2, "warmup"))
    report = _validate(tmp_path, records, {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE})
    assert report.severity == "INVALID"
    assert "W3" in [f.rule for f in report.findings]
    assert [q.met for q in report.quorums] == [True]
    assert report.composition == ()


def test_missing_input_file_incomplete(tmp_path: Path) -> None:
    """Unstaged inputs are gaps: summaries still compose with them carried."""
    staged = workload(manifest([file_entry("inputs/missing.bin", b"staged-never-0")]))
    specs = [(INVOCATION_1, "measured")]
    workloads = {INVOCATION_1: staged}
    records = [campaign_dict(specs, warmups=[], required=1, workloads=workloads)]
    records.extend(group_dicts(INVOCATION_1, "measured", input_digest=staged["input_digest"]))
    report = _validate(tmp_path, records, {INVOCATION_1: EVIDENCE})
    assert report.severity == "INCOMPLETE"
    gaps = [f for f in report.findings if f.rule == "V-B13"]
    assert [(g.severity, g.location) for g in gaps] == [
        ("INCOMPLETE", "$.campaign.invocations[0].workload.input_manifest.entries[0]")
    ]
    assert "missing.bin" in gaps[0].reason
    assert report.composition[0].summary.n_total == 3


def test_quiet_evidence_missing(tmp_path: Path) -> None:
    """No evidence entry: quorum-ineligible with no finding (V-B5)."""
    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    records.extend(group_dicts(INVOCATION_2, "measured"))
    report = _validate(tmp_path, records, {INVOCATION_1: EVIDENCE})
    assert (report.severity, report.findings) == ("VALID", ())
    (quorum,) = report.quorums
    assert (quorum.met, quorum.excluded) == (True, ((INVOCATION_2, "evidence-missing"),))
    assert [i.evidence_verified for i in report.inventory] == [True, False]


def test_tampered_record_dropped_with_findings(tmp_path: Path) -> None:
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    tamper_file(tmp_path, "records/01.json")
    report = validate_package(tmp_path)
    assert report.severity == "INVALID"
    assert any("mismatch" in f.reason for f in report.findings if f.rule == "V-B1")
    (inv,) = report.inventory
    assert len(inv.attempts) == 2


def test_diagnostics_carried(tmp_path: Path) -> None:
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    made = [attempt_dict(INVOCATION_1, n) for n in (1, 2, 3)]
    environment = env_dict(INVOCATION_1, cpu_model={"unavailable": "probe-failed"})
    records.extend([*made, total_dict(INVOCATION_1), environment])
    report = _validate(tmp_path, records, {INVOCATION_1: EVIDENCE})
    assert (report.severity, [d.rule for d in report.diagnostics]) == ("VALID", ["W4"])
    assert report.composition[0].summary.n_total == 3
