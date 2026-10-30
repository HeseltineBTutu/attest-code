"""Versioned evidence records and SHA-256 integrity digests."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from attest_core.invariants import invariant_content_digest
from attest_spec import Invariant, Verdict

EVIDENCE_SCHEMA_VERSION = 1
ATTESTATION_SCHEMA_VERSION = 2


class AttestationError(Exception):
    """Raised when an attestation fails validation."""


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Serialize a payload to canonical bytes for hashing."""
    return json.dumps(
        dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


@dataclasses.dataclass(frozen=True)
class EvidenceRecord:
    """One observed check result. Versioned and content-addressed.

    ``resources`` holds parent-collected quota evidence on attempt
    summaries only; per-check records leave it empty.
    """

    schema_version: int
    check_id: str
    target: str
    outcome: str
    detail: str
    revision: str
    config_digest: str
    attempt: int
    resources: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "check_id": self.check_id,
            "target": self.target,
            "outcome": self.outcome,
            "detail": self.detail,
            "revision": self.revision,
            "config_digest": self.config_digest,
            "attempt": self.attempt,
            "resources": self.resources,
        }

    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self.to_payload()))


@dataclasses.dataclass(frozen=True)
class Attestation:
    """A verdict statement referencing evidence hashes.

    The digest covers a canonical payload that excludes the digest field
    itself, so the digest is deterministic over the referenced content.
    The payload commits to the exact invariant content verified, not just
    its id and version labels.
    """

    schema_version: int
    verdict: str
    invariant_id: str
    invariant_version: int
    content_digest: str
    evidence_hashes: tuple[str, ...]
    statement: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "verdict": self.verdict,
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "content_digest": self.content_digest,
            "evidence_hashes": list(self.evidence_hashes),
            "statement": self.statement,
        }

    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self.to_payload()))


def _require_str(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise AttestationError(f"attestation missing required field: {key}")
    return value


def _require_version(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise AttestationError(f"attestation missing required field: {key}")
    return value


def verify_attestation(
    payload: Mapping[str, Any],
    invariant: Invariant,
    expected_digest: str,
    evidence: Sequence[EvidenceRecord] | None = None,
) -> Attestation:
    """Validate a presented attestation payload, failing closed.

    Recomputes the integrity digest and compares it to the claimed digest,
    then binds the attestation to the exact invariant content supplied by
    recomputing its content digest. When evidence records are supplied,
    their digests must reproduce the referenced evidence hashes in order.
    Returns the validated attestation. A digest match proves integrity of
    the covered fields only — never authorship.
    """
    if not isinstance(payload, Mapping):
        raise AttestationError("attestation payload must be a mapping")
    if not isinstance(invariant, Invariant):
        raise AttestationError(
            f"attestation invariant must be an Invariant instance, got {type(invariant).__name__}"
        )
    schema_version = _require_version(payload, "schema_version")
    if schema_version != ATTESTATION_SCHEMA_VERSION:
        raise AttestationError(
            f"unsupported attestation schema: {schema_version!r} "
            f"(expected {ATTESTATION_SCHEMA_VERSION})"
        )
    verdict = _require_str(payload, "verdict")
    if verdict not in {item.value for item in Verdict}:
        raise AttestationError(f"attestation has invalid verdict: {verdict!r}")
    invariant_id = _require_str(payload, "invariant_id")
    invariant_version = _require_version(payload, "invariant_version")
    content_digest = _require_str(payload, "content_digest")
    raw_hashes = payload.get("evidence_hashes")
    if (
        not isinstance(raw_hashes, (list, tuple))
        or not raw_hashes
        or not all(isinstance(item, str) and item for item in raw_hashes)
    ):
        raise AttestationError("attestation missing required field: evidence_hashes")
    statement = payload.get("statement")
    if not isinstance(statement, str):
        raise AttestationError("attestation missing required field: statement")
    attestation = Attestation(
        schema_version=schema_version,
        verdict=verdict,
        invariant_id=invariant_id,
        invariant_version=invariant_version,
        content_digest=content_digest,
        evidence_hashes=tuple(raw_hashes),
        statement=statement,
    )
    if attestation.digest() != expected_digest:
        raise AttestationError("attestation digest mismatch")
    if invariant_id != invariant.invariant_id or invariant_version != invariant.version:
        raise AttestationError("attestation refers to a different invariant")
    if content_digest != invariant_content_digest(invariant):
        raise AttestationError("attestation content digest does not match invariant")
    if evidence is not None:
        actual = [record.digest() for record in evidence]
        if actual != list(attestation.evidence_hashes):
            raise AttestationError("attestation evidence hashes do not match records")
    return attestation
