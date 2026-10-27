"""Approved independent checks for AUTH-ADMIN-001.

For every endpoint in the declared scope: unauthenticated requests must be
rejected (401), authenticated non-admin requests denied (403), and admin
requests served (200). Declared scope is compared against the app's
registered routes; any mismatch fails closed to an infrastructure outcome
(INCONCLUSIVE), never a silent pass.
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.demo_api import (
    ADMIN_TOKEN,
    USER_TOKEN,
    admin_route_paths,
    create_crashing_app,
    create_hanging_app,
    create_incomplete_repair_app,
    create_repaired_app,
    create_vulnerable_app,
)
from attest_core.evidence import EvidenceRecord
from attest_core.verification import AttemptReport, CheckEvidence
from attest_spec import AttemptOutcome

CHECK_SCOPE = "scope-coverage"
CHECK_UNAUTHENTICATED = "unauthenticated-rejected"
CHECK_NON_ADMIN = "non-admin-denied"
CHECK_ADMIN = "admin-allowed"

TARGETS = (
    "vulnerable",
    "incomplete",
    "repaired",
    "hanging",
    "crashing",
)
"""Demo fixture names accepted by :func:`run_target_attempt`."""


def _expect(
    *, check_id: str, target: str, actual: int, expected: int, context: str
) -> CheckEvidence:
    passed = actual == expected
    detail = f"{context}: expected {expected}, got {actual}"
    return CheckEvidence(check_id=check_id, target=target, passed=passed, detail=detail)


def _check_endpoint(client: TestClient, path: str) -> list[CheckEvidence]:
    anonymous = client.get(path)
    user = client.get(path, headers={"Authorization": f"Bearer {USER_TOKEN}"})
    admin = client.get(path, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    return [
        _expect(
            check_id=CHECK_UNAUTHENTICATED,
            target=path,
            actual=anonymous.status_code,
            expected=401,
            context="no credentials",
        ),
        _expect(
            check_id=CHECK_NON_ADMIN,
            target=path,
            actual=user.status_code,
            expected=403,
            context="non-admin user",
        ),
        _expect(
            check_id=CHECK_ADMIN,
            target=path,
            actual=admin.status_code,
            expected=200,
            context="administrator",
        ),
    ]


def run_admin_checks(app: FastAPI, declared_scope: Sequence[str]) -> AttemptReport:
    """Execute the approved checks once against a fresh test client."""
    try:
        actual = admin_route_paths(app)
    except Exception as exc:
        return AttemptReport(
            AttemptOutcome.INFRA_FAILURE, (), f"route inventory unavailable: {exc}"
        )
    declared = tuple(sorted(set(declared_scope)))
    if actual != declared:
        detail = f"scope mismatch: declared={list(declared)} actual={list(actual)}"
        check = CheckEvidence(CHECK_SCOPE, ",".join(declared), False, detail)
        return AttemptReport(AttemptOutcome.INFRA_FAILURE, (check,), detail)
    checks: list[CheckEvidence] = [
        CheckEvidence(CHECK_SCOPE, ",".join(declared), True, f"covers {len(declared)} route(s)")
    ]
    try:
        client = TestClient(app)
        for path in declared:
            checks.extend(_check_endpoint(client, path))
    except Exception as exc:
        return AttemptReport(
            AttemptOutcome.INFRA_FAILURE, tuple(checks), f"check execution failed: {exc}"
        )
    failures = [check for check in checks if not check.passed]
    if failures:
        return AttemptReport(
            AttemptOutcome.VIOLATION, tuple(checks), f"{len(failures)} sub-check(s) failed"
        )
    return AttemptReport(
        AttemptOutcome.PASS, tuple(checks), f"all {len(checks)} sub-check(s) passed"
    )


def scope_coverage(evidence: Sequence[EvidenceRecord], attempts: int) -> str:
    """Return 'established' only if every attempt covers the declared scope."""
    for attempt_no in range(1, attempts + 1):
        covered = any(
            record.check_id == CHECK_SCOPE
            and record.outcome == "PASS"
            and record.attempt == attempt_no
            for record in evidence
        )
        if not covered:
            return "failed"
    return "established"


def run_target_attempt(target: str, scope: Sequence[str]) -> AttemptReport:
    """Run one attempt against a named demo fixture (top-level: picklable)."""
    factories = {
        "vulnerable": create_vulnerable_app,
        "incomplete": create_incomplete_repair_app,
        "repaired": create_repaired_app,
        "hanging": create_hanging_app,
        "crashing": create_crashing_app,
    }
    try:
        factory = factories[target]
    except KeyError:
        raise ValueError(f"unknown target: {target}") from None
    return run_admin_checks(factory(), scope)
