"""Shared P4 fixtures: passing reports, registry mutations, v2 records."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from p3_fixtures import (
    DIGEST,
    FakeVerifier,
    load_auth_invariant,
    make_obs,
    make_registry,
    make_request,
)

from attest_core.evidence import (
    ATTESTATION_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    Attestation,
    EvidenceRecord,
)
from attest_core.invariants import invariant_content_digest
from attest_sdk import canonical, verify
from attest_sdk.commits import RegistryCommit
from attest_sdk.engine import Report
from attest_sdk.issuance import issue_attestation
from attest_sdk.registry import Registry
from attest_spec import AttemptOutcome, Invariant

COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
REVISION = "c" * 40
REPO_ID = "registry-fixture"


def eligible_registry(root: Path) -> Registry:
    """Materialize the eligible approval+active pair under root."""
    return make_registry(root, "approval-valid", "lifecycle-active")


def passing_report(registry: Registry) -> Report:
    """Run the engine to PASSED with a scripted all-pass verifier."""
    script = [make_obs(AttemptOutcome.PASS) for _ in range(3)]
    return verify(make_request(), load_auth_invariant(), FakeVerifier(script), registry)


def issued(region: Report, commit: str = COMMIT_A) -> tuple[dict[str, Any], str]:
    """Issue a v3 payload+digest for a report at one registry commit."""
    return issue_attestation(
        region,
        spec_version=1,
        registry_commit=RegistryCommit("git", commit),
        statement="P4 fixture attestation",
    )


def passing_attestation(root: Path) -> tuple[Report, dict[str, Any], str]:
    """Run to PASSED on an eligible registry and issue a v3 record."""
    report = passing_report(eligible_registry(root))
    payload, digest = issued(report)
    return report, payload, digest


def seal(payload: dict[str, Any]) -> dict[str, Any]:
    """Set event_id to the digest of the canonical id-less payload."""
    inner = {key: item for key, item in payload.items() if key != "event_id"}
    return {**payload, "event_id": canonical.digest_of(inner)}


def tip_of(root: Path, kind: str) -> tuple[int, str]:
    """Return the (seq, event_id) tip of one materialized chain."""
    chain_dir = root / "registry" / kind / "AUTH-ADMIN-001" / "1"
    best = (-1, "")
    for path in sorted(chain_dir.glob("*.json")):
        event = json.loads(path.read_bytes())
        if isinstance(event.get("seq"), int) and event["seq"] > best[0]:
            best = (event["seq"], str(event["event_id"]))
    if best[0] < 0:
        raise AssertionError(f"empty chain: {chain_dir}")
    return best


def append_event(root: Path, kind: str, event: dict[str, Any]) -> dict[str, Any]:
    """Seal one event and write it to the named chain directory."""
    sealed = seal(event)
    chain_dir = root / "registry" / kind / "AUTH-ADMIN-001" / "1"
    chain_dir.mkdir(parents=True, exist_ok=True)
    (chain_dir / f"{sealed['event_id']}.json").write_bytes(canonical.canonicalize(sealed))
    return sealed


def fork(root: Path, target: Path) -> Path:
    """Copy one registry tree so a mutation can diverge from a snapshot."""
    shutil.copytree(root, target)
    return target


def revoke_approval(root: Path) -> dict[str, Any]:
    """Append a REVOKE_APPROVAL binding the AUTH-ADMIN-001 digest."""
    seq, prev = tip_of(root, "approvals")
    return append_event(
        root,
        "approvals",
        {
            "seq": seq + 1,
            "prev": prev,
            "invariant_id": "AUTH-ADMIN-001",
            "invariant_version": 1,
            "invariant_digest": DIGEST,
            "event_type": "REVOKE_APPROVAL",
            "approver": "R",
            "method": "cli-review",
            "timestamp": "2026-11-01T00:00:00+00:00",
        },
    )


def reapprove(root: Path) -> dict[str, Any]:
    """Append a fresh APPROVE binding the AUTH-ADMIN-001 digest."""
    seq, prev = tip_of(root, "approvals")
    return append_event(
        root,
        "approvals",
        {
            "seq": seq + 1,
            "prev": prev,
            "invariant_id": "AUTH-ADMIN-001",
            "invariant_version": 1,
            "invariant_digest": DIGEST,
            "event_type": "APPROVE",
            "approver": "R2",
            "method": "cli-review",
            "timestamp": "2026-11-02T00:00:00+00:00",
        },
    )


def transition_lifecycle(root: Path, event_type: str, **over: Any) -> dict[str, Any]:
    """Append one lifecycle transition to the materialized chain."""
    seq, prev = tip_of(root, "lifecycle")
    base: dict[str, Any] = {
        "seq": seq + 1,
        "prev": prev,
        "invariant_id": "AUTH-ADMIN-001",
        "invariant_version": 1,
        "event_type": event_type,
        "actor": "R",
        "timestamp": "2026-11-01T00:00:00+00:00",
    }
    base.update(over)
    return append_event(root, "lifecycle", base)


def legacy_evidence() -> EvidenceRecord:
    """Build one legacy evidence record for v2 dual-read tests."""
    return EvidenceRecord(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        check_id="unauthenticated-access",
        target="/admin/users",
        outcome="VIOLATION",
        detail="returned 200 without credentials",
        revision="rev-1",
        config_digest="cfg-1",
        attempt=1,
    )


def legacy_setup() -> tuple[dict[str, Any], str, Invariant, list[EvidenceRecord]]:
    """Build a valid v2 (payload, digest, invariant, evidence) tuple."""
    invariant = Invariant(
        invariant_id="AUTH-ADMIN-001",
        version=1,
        title="Admin endpoints require admin role",
        requirement="Every endpoint in scope must reject unauthenticated requests.",
        scope=("/admin/users", "/admin/settings"),
    )
    evidence = [legacy_evidence()]
    record = Attestation(
        schema_version=ATTESTATION_SCHEMA_VERSION,
        verdict="FAILED",
        invariant_id=invariant.invariant_id,
        invariant_version=invariant.version,
        content_digest=invariant_content_digest(invariant),
        evidence_hashes=tuple(item.digest() for item in evidence),
        statement="reproducible violation across three attempts",
    )
    return record.to_payload(), record.digest(), invariant, evidence
