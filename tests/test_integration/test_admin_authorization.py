"""End-to-end AUTH-ADMIN-001 verification against demo fixtures."""

from __future__ import annotations

import dataclasses
from typing import cast

from fastapi import FastAPI

from apps.demo_api import (
    create_app_with_extra_admin_route,
    create_incomplete_repair_app,
    create_repaired_app,
    create_vulnerable_app,
)
from attest_core.invariants import invariant_content_digest, is_approval_valid
from attest_core.verification import (
    AttemptReport,
    VerificationError,
    VerificationReport,
    run_verification,
)
from attest_spec import ApprovalRecord, AttemptOutcome, Invariant, Verdict
from examples.admin_authorization import (
    CHECK_ADMIN,
    CHECK_NON_ADMIN,
    CHECK_UNAUTHENTICATED,
    run_admin_checks,
)

REVISION = "demo-app-v1"
SETTINGS = {
    "checks": "scope-coverage,unauthenticated-rejected,non-admin-denied,admin-allowed",
    "client": "fastapi-testclient",
    "scope": "/admin/settings,/admin/users",
}


def _verify(
    app: FastAPI,
    invariant: Invariant,
    approval: ApprovalRecord,
    revision: str = REVISION,
) -> VerificationReport:
    def run_checks() -> AttemptReport:
        return run_admin_checks(app, invariant.scope)

    return run_verification(
        invariant=invariant,
        approval=approval,
        revision=revision,
        settings=SETTINGS,
        run_checks=run_checks,
    )


def test_vulnerable_app_is_reproducible_violation(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    report = _verify(create_vulnerable_app(), auth_admin_invariant, auth_admin_approval)
    assert report.verdict == Verdict.FAILED
    assert "reproducible violation" in report.reason
    assert [attempt.outcome for attempt in report.attempts] == [AttemptOutcome.VIOLATION] * 3


def test_incomplete_repair_still_fails(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    report = _verify(create_incomplete_repair_app(), auth_admin_invariant, auth_admin_approval)
    assert report.verdict != Verdict.PASSED
    assert report.verdict == Verdict.FAILED


def test_repaired_app_passes(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    report = _verify(create_repaired_app(), auth_admin_invariant, auth_admin_approval)
    assert report.verdict == Verdict.PASSED
    assert [attempt.outcome for attempt in report.attempts] == [AttemptOutcome.PASS] * 3


def test_every_declared_endpoint_is_tested(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    report = _verify(create_repaired_app(), auth_admin_invariant, auth_admin_approval)
    for attempt_no in (1, 2, 3):
        for path in auth_admin_invariant.scope:
            for check_id in (CHECK_UNAUTHENTICATED, CHECK_NON_ADMIN, CHECK_ADMIN):
                matches = [
                    record
                    for record in report.evidence
                    if record.attempt == attempt_no
                    and record.target == path
                    and record.check_id == check_id
                ]
                assert len(matches) == 1, (attempt_no, path, check_id)


def test_extra_endpoint_fails_closed_not_silent(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    report = _verify(create_app_with_extra_admin_route(), auth_admin_invariant, auth_admin_approval)
    assert report.verdict != Verdict.PASSED
    assert report.verdict == Verdict.INCONCLUSIVE
    assert any("scope mismatch" in record.detail for record in report.evidence)


def test_declared_but_missing_endpoint_is_inconclusive(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    def run_checks() -> AttemptReport:
        return run_admin_checks(create_repaired_app(), ("/admin/users", "/admin/gone"))

    report = run_verification(
        invariant=auth_admin_invariant,
        approval=auth_admin_approval,
        revision=REVISION,
        settings=SETTINGS,
        run_checks=run_checks,
    )
    assert report.verdict == Verdict.INCONCLUSIVE


def test_missing_inventory_is_inconclusive(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    broken = cast(FastAPI, object())

    def run_checks() -> AttemptReport:
        return run_admin_checks(broken, auth_admin_invariant.scope)

    report = run_verification(
        invariant=auth_admin_invariant,
        approval=auth_admin_approval,
        revision=REVISION,
        settings=SETTINGS,
        run_checks=run_checks,
    )
    assert report.verdict == Verdict.INCONCLUSIVE
    assert all(attempt.outcome == AttemptOutcome.INFRA_FAILURE for attempt in report.attempts)


def test_invariant_unchanged_across_diagnosis_and_repair(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    before = invariant_content_digest(auth_admin_invariant)
    for app in (
        create_vulnerable_app(),
        create_incomplete_repair_app(),
        create_repaired_app(),
    ):
        _verify(app, auth_admin_invariant, auth_admin_approval)
    assert invariant_content_digest(auth_admin_invariant) == before
    assert is_approval_valid(auth_admin_invariant, auth_admin_approval)


def test_tampered_invariant_cannot_verify(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    tampered = dataclasses.replace(auth_admin_invariant, requirement="weakened")
    try:
        _verify(create_repaired_app(), tampered, auth_admin_approval)
    except VerificationError:
        pass
    else:
        raise AssertionError("expected VerificationError")
