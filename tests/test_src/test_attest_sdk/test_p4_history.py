"""P4 tests: v3 historical replay against materialized commits."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest
from p3_fixtures import DIGEST, load_auth_invariant, make_registry
from p4_fixtures import (
    COMMIT_A,
    COMMIT_B,
    eligible_registry,
    fork,
    issued,
    passing_report,
    revoke_approval,
    transition_lifecycle,
)

from attest_sdk import canonical
from attest_sdk.commits import RegistryCommit
from attest_sdk.errors import (
    AmbiguousHistoryError,
    ApprovalError,
    AttestationError,
    EligibilityError,
    HistoryUnavailableError,
)
from attest_sdk.history import verify_historical
from attest_sdk.registry import Registry


def _materializer(mapping: dict[str, Path]) -> Any:
    calls: list[str] = []

    def resolve(commit: RegistryCommit) -> Path:
        calls.append(commit.commit)
        return mapping[commit.commit]

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


def test_replay_valid(tmp_path: Path) -> None:
    root = tmp_path / "reg"
    report = passing_report(eligible_registry(root))
    payload, digest = issued(report)
    resolve = _materializer({COMMIT_A: root})
    result = verify_historical(payload, load_auth_invariant(), digest, resolve, report.evidence)
    assert result.approval_event_id == report.approval_event_id
    assert result.lifecycle_state == "active"
    assert result.warnings == ()
    assert result.registry_commit.commit == COMMIT_A
    assert resolve.calls == [COMMIT_A]


def test_revoked_approval_history_survives(tmp_path: Path) -> None:
    """Acceptance: revoke after issuance; replay holds, new runs refuse."""
    past = tmp_path / "past"
    report = passing_report(eligible_registry(past))
    payload, digest = issued(report)
    present = fork(past, tmp_path / "present")
    revoke_approval(present)
    with pytest.raises(ApprovalError):
        Registry(present).check_eligible("AUTH-ADMIN-001", 1, DIGEST)
    resolve = _materializer({COMMIT_A: past, COMMIT_B: present})
    result = verify_historical(payload, load_auth_invariant(), digest, resolve)
    assert result.attestation.verdict == "PASSED"
    assert resolve.calls == [COMMIT_A]


def test_revoked_invariant_history_survives(tmp_path: Path) -> None:
    past = tmp_path / "past"
    report = passing_report(eligible_registry(past))
    payload, digest = issued(report)
    present = fork(past, tmp_path / "present")
    transition_lifecycle(present, "REVOKE_INVARIANT")
    with pytest.raises(EligibilityError):
        Registry(present).check_eligible("AUTH-ADMIN-001", 1, DIGEST)
    resolve = _materializer({COMMIT_A: past})
    result = verify_historical(payload, load_auth_invariant(), digest, resolve)
    assert result.lifecycle_state == "active"


def test_deprecated_replay_warns(tmp_path: Path) -> None:
    root = tmp_path / "reg"
    registry = eligible_registry(root)
    transition_lifecycle(root, "DEPRECATE")
    report = passing_report(registry)
    assert report.lifecycle_state == "deprecated"
    payload, digest = issued(report)
    resolve = _materializer({COMMIT_A: root})
    result = verify_historical(payload, load_auth_invariant(), digest, resolve)
    assert result.warnings == ("deprecated",)


def test_superseded_permits_historical_reproduction(tmp_path: Path) -> None:
    root = tmp_path / "reg"
    eligible_registry(root)
    transition_lifecycle(root, "SUPERSEDE", successor_version=2)
    with pytest.raises(EligibilityError):
        Registry(root).check_eligible("AUTH-ADMIN-001", 1, DIGEST)
    report = passing_report(eligible_registry(tmp_path / "other"))
    evolved = dict(issued(report)[0])
    evolved["lifecycle_state"] = "superseded"
    resealed = canonical.digest_of(evolved)
    resolve = _materializer({COMMIT_A: root})
    result = verify_historical(evolved, load_auth_invariant(), resealed, resolve)
    assert result.lifecycle_state == "superseded"


def test_replay_at_revoked_commit_refuses(tmp_path: Path) -> None:
    past = tmp_path / "past"
    report = passing_report(eligible_registry(past))
    payload, digest = issued(report)
    present = fork(past, tmp_path / "present")
    revoke_approval(present)
    resolve = _materializer({COMMIT_A: present})
    with pytest.raises(AttestationError, match="revoked"):
        verify_historical(payload, load_auth_invariant(), digest, resolve)


def test_replay_lifecycle_mismatch_refuses(tmp_path: Path) -> None:
    root = tmp_path / "reg"
    eligible_registry(root)
    transition_lifecycle(root, "DEPRECATE")
    report = passing_report(eligible_registry(tmp_path / "other"))
    payload, digest = issued(report)
    resolve = _materializer({COMMIT_A: root})
    with pytest.raises(AttestationError, match="lifecycle"):
        verify_historical(payload, load_auth_invariant(), digest, resolve)


def test_replay_unavailable_and_unknown_vcs(tmp_path: Path) -> None:
    root = tmp_path / "reg"
    report = passing_report(eligible_registry(root))
    payload, digest = issued(report)
    invariant = load_auth_invariant()

    def missing(commit: RegistryCommit) -> Path:
        raise FileNotFoundError(commit.commit)

    with pytest.raises(HistoryUnavailableError, match="materialize"):
        verify_historical(payload, invariant, digest, missing)
    gone = _materializer({COMMIT_A: tmp_path / "nope"})
    with pytest.raises(HistoryUnavailableError, match="open registry"):
        verify_historical(payload, invariant, digest, gone)
    foreign = dict(payload)
    foreign["registry_commit"] = {"vcs": "hg", "commit": COMMIT_A}
    with pytest.raises(HistoryUnavailableError, match="vcs"):
        verify_historical(foreign, invariant, canonical.digest_of(foreign), gone)


def test_replay_ambiguous_history_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "reg"
    make_registry(root, "approval-fork", "lifecycle-active")
    report = passing_report(eligible_registry(tmp_path / "other"))
    payload, digest = issued(report)
    resolve = _materializer({COMMIT_A: root})
    with pytest.raises(AmbiguousHistoryError):
        verify_historical(payload, load_auth_invariant(), digest, resolve)


def test_replay_checks_evidence_order(tmp_path: Path) -> None:
    root = tmp_path / "reg"
    report = passing_report(eligible_registry(root))
    payload, digest = issued(report)
    resolve = _materializer({COMMIT_A: root})
    tampered = dataclasses.replace(report.evidence[0], detail="forged")
    records = [tampered, *report.evidence[1:]]
    with pytest.raises(AttestationError, match="evidence hashes"):
        verify_historical(payload, load_auth_invariant(), digest, resolve, records)
