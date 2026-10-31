"""Stable SDK exception hierarchy.

Every error below signals refusal: the caller learns that no verdict
was produced. SDK code raises these instead of returning a verdict;
execution uncertainty inside an attempt is reported as INCONCLUSIVE
through the normal report path, never through these types.
"""

from __future__ import annotations


class AttestError(Exception):
    """Base class for all attest_sdk refusals and failures."""

    def __init__(self, message: str = "", *, reason_class: str = "") -> None:
        super().__init__(message)
        self.reason_class = reason_class


class ParseError(AttestError):
    """Source bytes could not be parsed (encoding, syntax, structure)."""


class SchemaError(AttestError):
    """A parsed value violates its specification-version schema."""


class CanonicalizationError(AttestError):
    """A value cannot be canonicalized under attest-canonical-json v1."""


class LimitExceededError(CanonicalizationError):
    """Canonicalization refused: a documented resource limit was exceeded."""

    def __init__(self, limit: str) -> None:
        super().__init__(
            f"canonicalization limit exceeded: {limit}",
            reason_class=f"limit-{limit}",
        )
        self.limit = limit


class UnsupportedSpecVersionError(AttestError):
    """A document, request, or vector targets an unsupported spec version."""


class RegistryError(AttestError):
    """Registry history is unreadable or unusable."""


class AmbiguousHistoryError(RegistryError):
    """Approval or lifecycle history is ambiguous; fail closed, no verdict."""


class ApprovalError(AttestError):
    """No usable approval binds the requested invariant content."""


class NoApprovalError(ApprovalError):
    """No approval record exists for the requested invariant version."""


class StaleApprovalError(ApprovalError):
    """Stored approval digest does not match current invariant content."""


class RevokedApprovalError(ApprovalError):
    """Approval was withdrawn; it cannot authorize new runs."""


class EligibilityError(AttestError):
    """Lifecycle state forbids verification of this invariant version."""


class VerifierError(AttestError):
    """The referenced verifier cannot be used for this request."""


class UnknownVerificationTypeError(VerifierError):
    """No known normative procedure matches the requested type."""


class UnsupportedVerifierSpecError(VerifierError):
    """The verifier does not support the requested spec version."""


class VerifierRefusedError(VerifierError):
    """The verifier declined to execute faithfully (fail closed)."""


class VerifierParameterError(VerifierError):
    """Request parameters violate the verifier's parameter schema."""


class AttestationError(AttestError):
    """An attestation payload failed validation."""


class HistoryUnavailableError(AttestError):
    """Recorded registry history cannot be materialized for replay."""
