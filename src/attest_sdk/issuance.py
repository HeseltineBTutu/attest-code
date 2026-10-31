"""Attestation v3 emission from parent-engine reports (§11).

The report's verdict is transcribed, never re-decided; the caller
supplies the spec version, the registry state that authorized the
run, and the human-readable statement. The emitted payload is
structurally validated before its digest is computed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from attest_sdk import canonical
from attest_sdk.attestations import ATTESTATION_V3, parse_attestation
from attest_sdk.commits import RegistryCommit
from attest_sdk.errors import AttestationError, UnsupportedSpecVersionError
from attest_sdk.verifiers import ArtifactState, VerifierRef
from attest_sdk.version import SUPPORTED_SPEC_VERSIONS
from attest_spec import Verdict

if TYPE_CHECKING:
    from attest_sdk.engine import Report


def _artifact_to_wire(artifact: ArtifactState) -> dict[str, Any]:
    if artifact.available:
        return {
            "status": "available",
            "algorithm": artifact.algorithm,
            "value": artifact.value,
        }
    return {"status": "unavailable", "reason": artifact.reason}


def issue_attestation(
    report: Report,
    *,
    spec_version: int,
    registry_commit: RegistryCommit,
    statement: str,
) -> tuple[dict[str, Any], str]:
    """Emit a v3 payload plus its full-payload digest from an engine report."""
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise UnsupportedSpecVersionError(f"unsupported spec_version: {spec_version}")
    if not isinstance(registry_commit, RegistryCommit):
        raise AttestationError("registry_commit must be a RegistryCommit")
    if registry_commit.vcs != "git":
        raise AttestationError("v1 emission requires a git registry_commit")
    if not isinstance(statement, str):
        raise AttestationError("statement must be a string")
    ref = report.verifier_ref
    if not isinstance(ref, VerifierRef):
        raise AttestationError("report verifier_ref is malformed")
    if not isinstance(report.verdict, Verdict):
        raise AttestationError(f"report has invalid verdict: {report.verdict!r}")
    if not report.evidence:
        raise AttestationError("report has no evidence")
    hashes: list[str] = []
    for record in report.evidence:
        to_payload = getattr(record, "to_payload", None)
        if not callable(to_payload):
            raise AttestationError("report evidence is malformed")
        hashes.append(canonical.digest_of(to_payload()))
    payload: dict[str, Any] = {
        "schema_version": ATTESTATION_V3,
        "verdict": report.verdict.value,
        "invariant_id": report.invariant_id,
        "invariant_version": report.invariant_version,
        "content_digest": report.content_digest,
        "evidence_hashes": hashes,
        "statement": statement,
        "spec_version": spec_version,
        "approval_event_id": report.approval_event_id,
        "registry_commit": registry_commit.to_wire(),
        "verification_type": ref.type,
        "verifier": {
            "implementation": ref.implementation,
            "version": ref.version,
            "artifact": _artifact_to_wire(ref.artifact),
        },
        "revision": report.revision,
        "execution_profile": report.execution_profile,
        "lifecycle_state": report.lifecycle_state,
    }
    parse_attestation(payload)
    return payload, canonical.digest_of(payload)
