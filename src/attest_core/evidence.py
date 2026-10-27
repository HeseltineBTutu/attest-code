"""Versioned evidence records and SHA-256 integrity digests."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping
from typing import Any

EVIDENCE_SCHEMA_VERSION = 1
ATTESTATION_SCHEMA_VERSION = 1


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
    """One observed check result. Versioned and content-addressed."""

    schema_version: int
    check_id: str
    target: str
    outcome: str
    detail: str
    revision: str
    config_digest: str
    attempt: int

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
        }

    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self.to_payload()))


@dataclasses.dataclass(frozen=True)
class Attestation:
    """A verdict statement referencing evidence hashes.

    The digest covers a canonical payload that excludes the digest field
    itself, so the digest is deterministic over the referenced content.
    """

    schema_version: int
    verdict: str
    invariant_id: str
    invariant_version: int
    evidence_hashes: tuple[str, ...]
    statement: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "verdict": self.verdict,
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "evidence_hashes": list(self.evidence_hashes),
            "statement": self.statement,
        }

    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self.to_payload()))
