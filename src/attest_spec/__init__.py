"""Shared data contracts for Attest Code.

This package holds the stable types shared across the verifier. It has no
dependencies on other attest packages.
"""

from __future__ import annotations

import dataclasses
import enum


class Verdict(enum.StrEnum):
    """Final verification verdict determined by the verifier, never the model."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class AttemptOutcome(enum.StrEnum):
    """Outcome of a single independent verification attempt."""

    PASS = "PASS"
    VIOLATION = "VIOLATION"
    INFRA_FAILURE = "INFRA_FAILURE"


@dataclasses.dataclass(frozen=True)
class Invariant:
    """An approved, versioned requirement.

    Approval is recorded separately in an :class:`ApprovalRecord`. Any
    ``approved`` flag embedded in a definition file is ignored.
    """

    invariant_id: str
    version: int
    title: str
    requirement: str
    scope: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.invariant_id.strip():
            raise ValueError("invariant_id must be non-empty")
        if self.version < 1:
            raise ValueError("version must be >= 1")
        if not self.requirement.strip():
            raise ValueError("requirement must be non-empty")
        if not self.scope:
            raise ValueError("scope must list at least one target")


@dataclasses.dataclass(frozen=True)
class ApprovalRecord:
    """Explicit human approval for one exact invariant version and content."""

    invariant_id: str
    invariant_version: int
    approver: str
    approved_at: str
    content_digest: str
    method: str

    def __post_init__(self) -> None:
        if not self.invariant_id.strip():
            raise ValueError("invariant_id must be non-empty")
        if self.invariant_version < 1:
            raise ValueError("invariant_version must be >= 1")
        if not self.approver.strip():
            raise ValueError("approver must be a named human reviewer")
        if len(self.content_digest) != 64:
            raise ValueError("content_digest must be a SHA-256 hex string")
        if not self.method.strip():
            raise ValueError("method must describe how approval was granted")
