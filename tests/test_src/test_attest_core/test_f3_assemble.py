"""F3 stage-input derivation from verified P2 outputs (unit)."""

from __future__ import annotations

from typing import Any

from f3_fixtures import (
    UUID_A,
    UUID_B,
    UUID_C,
    UUID_D,
    UUID_E,
    assert_fails,
    valid_attempt,
    valid_campaign,
    valid_env,
    valid_summary,
    valid_total,
)
from f3_identity_pkg import INVOCATION_1, INVOCATION_2
from f3_package import CANON, PROJ

from attest_core.f3_assemble import (
    assemble_package,
    declared_ids,
    grouped,
    p2_findings,
    pins_accepted,
    single,
    verified_evidence,
)
from attest_core.f3_identity import PackageRecords
from attest_core.f3_manifest import ManifestReport
from attest_core.f3_manifest_entries import EntryResult, Finding
from attest_core.f3_records import AttemptRecord


def _entry(record: Any, index: int = 0) -> EntryResult:
    return EntryResult(
        source="records", index=index, identity=f"records[{index}]", findings=(), record=record
    )


def test_assemble_dispatches_kinds() -> None:
    """Payloads land in typed slots; summaries are bound but unconsumed."""
    payloads = [
        valid_attempt(record_id=UUID_A),
        valid_total(record_id=UUID_B),
        valid_env(record_id=UUID_C),
        valid_campaign(record_id=UUID_D),
        valid_summary(record_id=UUID_E),
    ]
    view = assemble_package(tuple(_entry(item, i) for i, item in enumerate(payloads)))
    kinds = (len(view.attempts), len(view.totals), len(view.envs), len(view.campaigns))
    assert kinds == (1, 1, 1, 1)
    assert isinstance(view.attempts[0], AttemptRecord)
    assert view.attempts[0].record_id == UUID_A


def test_assemble_skips_failed_and_evidence_entries() -> None:
    """Payload-less entries contribute nothing and never crash assembly."""
    broken = EntryResult(
        source="records",
        index=0,
        identity="records[0]",
        findings=(Finding(severity="INVALID", rule="V-B1", location="$", reason="x"),),
        record=None,
    )
    evidence = EntryResult(
        source="evidence", index=0, identity="(inv, s3-report)", findings=(), record=None
    )
    assert assemble_package((broken, evidence)) == PackageRecords()


def test_assemble_unknown_kind_raises() -> None:
    """Fail-closed defense mirroring the P0 kind dispatch."""
    assert_fails(
        lambda v: assemble_package((_entry(v),)),
        {"record_kind": "bogus"},
        rule="V-B6",
        section="7",
        location="$.record_kind",
        reason="unknown record_kind",
    )


def test_verified_evidence() -> None:
    """Only finding-free evidence entries qualify, by manifest index."""
    good = EntryResult(source="evidence", index=0, identity="e0", findings=(), record=None)
    bad = EntryResult(
        source="evidence",
        index=1,
        identity="e1",
        findings=(Finding(severity="INVALID", rule="V-B1", location="$", reason="x"),),
        record=None,
    )
    manifest = {"evidence": [{"invocation_id": INVOCATION_1}, {"invocation_id": INVOCATION_2}]}
    report = ManifestReport(manifest_findings=(), entries=(good, bad), manifest=manifest)
    assert verified_evidence(report) == {INVOCATION_1}
    assert verified_evidence(ManifestReport((), (), None)) == set()
    assert verified_evidence(ManifestReport((), (), {"evidence": "nope"})) == set()


def test_pins_accepted() -> None:
    """Exact v1 pins pass; anything else refuses (§8.2)."""
    good = {"canonicalization": dict(CANON), "digest_projection": dict(PROJ)}
    assert pins_accepted(good) is True
    assert pins_accepted({**good, "digest_projection": {"name": "x", "version": 1}}) is False
    assert pins_accepted({}) is False


def test_p2_findings_flatten_in_order() -> None:
    """Manifest findings first, then per-entry findings in entry order."""
    first = Finding(severity="INVALID", rule="V-B6", location="$", reason="a")
    second = Finding(severity="INVALID", rule="V-B1", location="r", reason="b")
    entries = (
        EntryResult(source="records", index=0, identity="r0", findings=(second,), record=None),
        EntryResult(source="evidence", index=0, identity="e0", findings=(), record=None),
    )
    report = ManifestReport(manifest_findings=(first,), entries=entries, manifest={})
    assert p2_findings(report) == (first, second)


def test_grouped_and_single() -> None:
    """Invocation grouping preserves order; single() never infers counts."""
    first = valid_attempt(record_id=UUID_A, invocation_id=INVOCATION_1)
    second = valid_attempt(record_id=UUID_B, invocation_id=INVOCATION_1)
    view = assemble_package((_entry(first), _entry(second, 1)))
    assert [r.record_id for r in grouped(view.attempts)[INVOCATION_1]] == [UUID_A, UUID_B]
    assert single(grouped(view.attempts)[INVOCATION_1]) is None
    assert single(grouped(view.attempts).get("absent", [])) is None


def test_declared_ids() -> None:
    """Declared ids span every campaign record."""
    view = assemble_package((_entry(valid_campaign()),))
    assert declared_ids(view) == {UUID_C}
    assert declared_ids(PackageRecords()) == set()
