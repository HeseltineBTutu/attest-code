"""P3 unit tests: attempt execution, observation gating, verdicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from p3_fixtures import (
    APPROVAL,
    DIGEST,
    FakeVerifier,
    load_auth_invariant,
    make_matrix,
    make_obs,
    make_registry,
    make_request,
)

from attest_sdk import verify
from attest_sdk.engine import Report
from attest_sdk.verifiers import AttemptObservation
from attest_spec import AttemptOutcome, Verdict


def _valid() -> FakeVerifier:
    return FakeVerifier([make_obs(AttemptOutcome.PASS)])


def test_deprecated_warns_but_verifies(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-deprecated")
    report = verify(make_request(), load_auth_invariant(), _valid(), reg)
    assert report.verdict is Verdict.PASSED
    assert report.warnings == ("deprecated",)
    assert report.lifecycle_state == "deprecated"


def test_verdict_goldens_and_counts(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    report = verify(make_request(), load_auth_invariant(), _valid(), reg)
    assert report.verdict is Verdict.PASSED
    assert len(report.attempts) == 3
    assert all(a.evidence_hash for a in report.attempts)
    assert len(report.evidence) == 3 * (len(make_matrix(True)) + 1)
    bad = FakeVerifier([make_obs(AttemptOutcome.VIOLATION, passed=False)])
    failed = verify(make_request(), load_auth_invariant(), bad, reg)
    assert failed.verdict is Verdict.FAILED
    assert bad.calls == 3
    script = [
        make_obs(AttemptOutcome.PASS),
        make_obs(AttemptOutcome.PASS),
        make_obs(AttemptOutcome.VIOLATION, passed=False),
    ]
    mixed = verify(make_request(), load_auth_invariant(), FakeVerifier(script), reg)
    assert mixed.verdict is Verdict.INCONCLUSIVE


def test_crash_and_reported_infra_stay_infra(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    crashing = FakeVerifier([RuntimeError("boom")])
    report = verify(make_request(), load_auth_invariant(), crashing, reg)
    assert report.verdict is Verdict.INCONCLUSIVE
    assert [a.outcome for a in report.attempts] == [AttemptOutcome.INFRA_FAILURE] * 3
    timeouts = FakeVerifier([AttemptObservation(AttemptOutcome.INFRA_FAILURE, (), "timed out")])
    report2 = verify(make_request(), load_auth_invariant(), timeouts, reg)
    assert report2.verdict is Verdict.INCONCLUSIVE


def test_unfaithful_observations_demote_to_infra(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    no_coverage = AttemptObservation(AttemptOutcome.PASS, (), "d")
    missing_probe = AttemptObservation(AttemptOutcome.PASS, tuple(make_matrix(True)[:-1]), "d")
    incoherent = AttemptObservation(AttemptOutcome.PASS, tuple(make_matrix(False)), "d")
    no_evidence = AttemptObservation(AttemptOutcome.VIOLATION, tuple(make_matrix(True)), "d")
    for obs in (no_coverage, missing_probe, incoherent, no_evidence):
        report = verify(make_request(), load_auth_invariant(), FakeVerifier([obs]), reg)
        assert report.verdict is Verdict.INCONCLUSIVE
        assert report.attempts[0].outcome is AttemptOutcome.INFRA_FAILURE


def test_hostile_shapes_cannot_select_verdict(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    hostile: Any = FakeVerifier(["PASSED"])
    report = verify(make_request(), load_auth_invariant(), hostile, reg)
    assert report.verdict is Verdict.INCONCLUSIVE
    assert report.attempts[0].outcome is AttemptOutcome.INFRA_FAILURE
    assert report.evidence[0].detail.startswith("attempt 1: malformed")


def test_determinism(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    first = verify(make_request(), load_auth_invariant(), _valid(), reg)
    second = verify(make_request(), load_auth_invariant(), _valid(), reg)
    assert (first.verdict, first.config_digest) == (second.verdict, second.config_digest)


def test_report_bindings(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    report: Report = verify(make_request(), load_auth_invariant(), _valid(), reg)
    assert report.invariant_id == "AUTH-ADMIN-001"
    assert report.content_digest == DIGEST
    assert report.approval_event_id == APPROVAL
    assert report.revision == "0" * 40
    assert report.execution_profile == "standard"
    assert report.verifier_ref.implementation == "fake"
    assert len(report.config_digest) == 64
