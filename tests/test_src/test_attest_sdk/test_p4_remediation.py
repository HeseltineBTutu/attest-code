"""P4 acceptance-remediation tests (audit C2/L1).

Replay refusal branches, mutable-ref handling, and malformed-input
validation: every case below must refuse with a documented error and
never produce a successful verification.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, cast

import pytest
from p3_fixtures import load_auth_invariant, materialize
from p4_fixtures import (
    COMMIT_A,
    eligible_registry,
    fork,
    issued,
    passing_attestation,
    passing_report,
    reapprove,
    revoke_approval,
)

from attest_sdk.commits import RegistryCommit
from attest_sdk.errors import AttestationError
from attest_sdk.history import verify_historical, verify_v3
from attest_sdk.issuance import issue_attestation


def _resolve(mapping: dict[str, Path]) -> Any:
    def resolve(commit: RegistryCommit) -> Path:
        return mapping[commit.commit]

    return resolve


def test_replay_without_approval_refuses(tmp_path: Path) -> None:
    """M1a: no effective approval at the recorded commit refuses replay."""
    root = tmp_path / "reg"
    materialize("lifecycle-active", root)
    report = passing_report(eligible_registry(tmp_path / "other"))
    payload, digest = issued(report)
    resolve = _resolve({COMMIT_A: root})
    with pytest.raises(AttestationError, match="no approval") as caught:
        verify_historical(payload, load_auth_invariant(), digest, resolve)
    assert caught.value.reason_class == "approval-absent-at-commit"


def test_replay_after_reapproval_refuses(tmp_path: Path) -> None:
    """M1b: revoke-then-reapprove makes the recorded approval stale."""
    past = tmp_path / "past"
    report = passing_report(eligible_registry(past))
    payload, digest = issued(report)
    present = fork(past, tmp_path / "present")
    revoke_approval(present)
    fresh = reapprove(present)
    assert fresh["event_id"] != report.approval_event_id
    resolve = _resolve({COMMIT_A: present})
    with pytest.raises(AttestationError, match="not effective") as caught:
        verify_historical(payload, load_auth_invariant(), digest, resolve)
    assert caught.value.reason_class == "approval-mismatch-at-commit"


def test_mutable_ref_ignored_for_resolution(tmp_path: Path) -> None:
    """M4: replay resolves the immutable commit despite a misleading ref."""
    root = tmp_path / "reg"
    report = passing_report(eligible_registry(root))
    commit = RegistryCommit("git", COMMIT_A, ref="main")
    payload, digest = issue_attestation(
        report, spec_version=1, registry_commit=commit, statement="s"
    )
    seen: list[RegistryCommit] = []

    def resolve(received: RegistryCommit) -> Path:
        seen.append(received)
        return {COMMIT_A: root}[received.commit]

    result = verify_historical(payload, load_auth_invariant(), digest, resolve)
    assert result.lifecycle_state == "active"
    assert len(seen) == 1
    assert seen[0].commit == COMMIT_A
    assert seen[0].ref == "main"


_MALFORMED: tuple[tuple[str, Any, str], ...] = (
    ("content_digest", 5, "64-hex digest"),
    ("content_digest", True, "64-hex digest"),
    ("approval_event_id", 5, "64-hex digest"),
    ("evidence_hashes", 5, "evidence_hashes"),
    ("evidence_hashes", None, "evidence_hashes"),
    ("evidence_hashes", ["0" * 64, 5], "evidence_hashes"),
    ("evidence_hashes", "ab" * 32, "evidence_hashes"),
)


def test_malformed_scalar_types_refused(tmp_path: Path) -> None:
    """L1: non-string/non-list scalars refuse as AttestationError."""
    _, payload, digest = passing_attestation(tmp_path / "reg")
    invariant = load_auth_invariant()
    for field, bad, match in _MALFORMED:
        mutated = dict(payload)
        mutated[field] = bad
        with pytest.raises(AttestationError, match=match):
            verify_v3(mutated, invariant, digest)


def test_verify_v3_rejects_bad_invariant(tmp_path: Path) -> None:
    """L1: a non-Invariant invariant refuses instead of crashing."""
    _, payload, digest = passing_attestation(tmp_path / "reg")
    with pytest.raises(AttestationError, match="Invariant instance"):
        verify_v3(payload, cast(Any, None), digest)
    with pytest.raises(AttestationError, match="Invariant instance"):
        verify_v3(payload, cast(Any, {"not": "invariant"}), digest)


def test_issue_rejects_plain_string_verdict(tmp_path: Path) -> None:
    """L1: a raw "PASSED" str is not a verdict enum member."""
    report = passing_report(eligible_registry(tmp_path / "reg"))
    commit = RegistryCommit("git", COMMIT_A)
    impostor = dataclasses.replace(report, verdict=cast(Any, "PASSED"))
    with pytest.raises(AttestationError, match="invalid verdict"):
        issue_attestation(impostor, spec_version=1, registry_commit=commit, statement="s")
