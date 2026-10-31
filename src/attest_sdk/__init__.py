"""Stable programmatic interface over frozen attest-spec v1.

Sync-only: verification paths serialize through the parent engine,
which retains sole verdict authority. Normative rules live in
docs/attest-spec-v1.md; this package implements them.
"""

from __future__ import annotations

from attest_sdk import errors
from attest_sdk.attestations import AttestationV3, parse_attestation
from attest_sdk.canonical import (
    canonicalize,
    canonicalize_bytes,
    digest_bytes,
    digest_of,
    unicode_version,
)
from attest_sdk.commits import RegistryCommit
from attest_sdk.documents import (
    KNOWN_VERIFICATION_TYPES,
    Invariant,
    ensure_known_verification_type,
    invariant_digest,
    load_invariant,
)
from attest_sdk.engine import Report, verify
from attest_sdk.errors import (
    AmbiguousHistoryError,
    ApprovalError,
    AttestationError,
    AttestError,
    CanonicalizationError,
    EligibilityError,
    HistoryUnavailableError,
    LimitExceededError,
    NoApprovalError,
    ParseError,
    RegistryError,
    RevokedApprovalError,
    SchemaError,
    StaleApprovalError,
    UnknownVerificationTypeError,
    UnsupportedSpecVersionError,
    UnsupportedVerifierSpecError,
    VerifierError,
    VerifierParameterError,
    VerifierRefusedError,
)
from attest_sdk.events import ApprovalEvent, LifecycleEvent
from attest_sdk.history import (
    HistoricalAttestation,
    schema_version_of,
    verify_historical,
    verify_v2,
    verify_v3,
)
from attest_sdk.issuance import issue_attestation
from attest_sdk.registry import (
    ApprovalHistory,
    Eligibility,
    LifecycleHistory,
    Policy,
    Registry,
)
from attest_sdk.requests import EXECUTION_PROFILES, VerificationRequest, parse_request
from attest_sdk.verifiers import ArtifactState, AttemptObservation, Verifier, VerifierRef
from attest_sdk.version import SUPPORTED_SPEC_VERSIONS, __version__

__all__ = [
    "AmbiguousHistoryError",
    "ApprovalError",
    "ApprovalEvent",
    "ApprovalHistory",
    "ArtifactState",
    "AttemptObservation",
    "AttestError",
    "AttestationError",
    "AttestationV3",
    "CanonicalizationError",
    "EXECUTION_PROFILES",
    "Eligibility",
    "EligibilityError",
    "HistoricalAttestation",
    "HistoryUnavailableError",
    "Invariant",
    "KNOWN_VERIFICATION_TYPES",
    "LifecycleEvent",
    "LifecycleHistory",
    "LimitExceededError",
    "NoApprovalError",
    "ParseError",
    "Policy",
    "Registry",
    "RegistryCommit",
    "RegistryError",
    "Report",
    "RevokedApprovalError",
    "SUPPORTED_SPEC_VERSIONS",
    "SchemaError",
    "StaleApprovalError",
    "UnknownVerificationTypeError",
    "UnsupportedSpecVersionError",
    "UnsupportedVerifierSpecError",
    "VerificationRequest",
    "Verifier",
    "VerifierError",
    "VerifierParameterError",
    "VerifierRef",
    "VerifierRefusedError",
    "__version__",
    "canonicalize",
    "canonicalize_bytes",
    "digest_bytes",
    "digest_of",
    "ensure_known_verification_type",
    "errors",
    "invariant_digest",
    "issue_attestation",
    "load_invariant",
    "parse_attestation",
    "parse_request",
    "schema_version_of",
    "unicode_version",
    "verify",
    "verify_historical",
    "verify_v2",
    "verify_v3",
]
