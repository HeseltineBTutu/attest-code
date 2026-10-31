"""P5 API commitments: export types, routing, and documented constants."""

from __future__ import annotations

from pathlib import Path

from p3_fixtures import load_auth_invariant, make_registry
from p4_fixtures import COMMIT_A, issued, passing_report

import attest_sdk
from attest_sdk import errors
from attest_sdk.events import ApprovalEvent, LifecycleEvent

_REGISTRY_FILES = ("approval-valid", "lifecycle-active")


def test_history_types_flow_through_public_api(tmp_path: Path) -> None:
    registry = make_registry(tmp_path / "reg", *_REGISTRY_FILES)
    approvals = registry.approval_chain("AUTH-ADMIN-001", 1)
    assert type(approvals).__name__ == "ApprovalHistory"
    assert all(type(item) is ApprovalEvent for item in approvals.events)
    lifecycle = registry.lifecycle_chain("AUTH-ADMIN-001", 1)
    assert type(lifecycle).__name__ == "LifecycleHistory"
    assert all(type(item) is LifecycleEvent for item in lifecycle.events)


def test_attestation_types_flow_through_public_api(tmp_path: Path) -> None:
    root = tmp_path / "reg"
    report = passing_report(make_registry(root, *_REGISTRY_FILES))
    payload, digest = issued(report)
    parsed = attest_sdk.parse_attestation(payload)
    assert type(parsed).__name__ == "AttestationV3"
    assert type(parsed.registry_commit).__name__ == "RegistryCommit"
    seen: list[str] = []

    def resolve(commit: attest_sdk.RegistryCommit) -> Path:
        seen.append(commit.commit)
        return root

    result = attest_sdk.verify_historical(
        payload, load_auth_invariant(), digest, resolve, report.evidence
    )
    assert type(result).__name__ == "HistoricalAttestation"
    assert seen == [COMMIT_A]


def test_documented_constants() -> None:
    assert attest_sdk.SUPPORTED_SPEC_VERSIONS == (1,)
    assert attest_sdk.EXECUTION_PROFILES == ("standard", "contained", "hardened")
    assert "http-auth-probe/1" in attest_sdk.KNOWN_VERIFICATION_TYPES
    assert attest_sdk.schema_version_of({"schema_version": 2}) == 2
    assert issubclass(errors.HistoryUnavailableError, errors.AttestError)
