"""Historical attestation verification: v2 dual-read and v3 replay (§12–§13).

Integrity checks a record against its digest and bindings; replay
additionally folds approval and lifecycle chains as of the recorded
``registry_commit``. Git materialization stays outside the SDK:
callers supply a materializer mapping a commit to a path.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

from attest_sdk import canonical, documents
from attest_sdk.attestations import ATTESTATION_V3, AttestationV3, parse_attestation
from attest_sdk.commits import RegistryCommit
from attest_sdk.errors import (
    AttestationError,
    HistoryUnavailableError,
    NoApprovalError,
    RegistryError,
    RevokedApprovalError,
)
from attest_sdk.registry import Registry

if TYPE_CHECKING:
    from attest_core.evidence import Attestation as LegacyAttestation
    from attest_core.evidence import EvidenceRecord
    from attest_sdk.documents import Invariant
    from attest_spec import Invariant as LegacyInvariant

_ELIGIBLE_THEN: Final = frozenset({"active", "deprecated", "superseded"})


@dataclasses.dataclass(frozen=True)
class HistoricalAttestation:
    """A v3 record plus its replayed execution-time context."""

    attestation: AttestationV3
    approval_event_id: str
    lifecycle_state: str
    registry_commit: RegistryCommit
    warnings: tuple[str, ...] = ()


def schema_version_of(payload: object) -> int:
    """Read a record's schema version so callers can route explicitly."""
    if not isinstance(payload, Mapping):
        raise AttestationError("attestation payload must be a mapping")
    version = payload.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise AttestationError("attestation missing required field: schema_version")
    return version


def verify_v2(
    payload: object,
    invariant: LegacyInvariant,
    expected_digest: str,
    evidence: Sequence[EvidenceRecord] | None = None,
) -> LegacyAttestation:
    """Dual-read: v2 records verify under exact legacy semantics.

    Accept/reject decisions match the retained v2 path; only the
    error type is unified into the SDK hierarchy, chained to the
    original. Unknown versions never reach this function.
    """
    from attest_core.evidence import (
        AttestationError as LegacyAttestationError,
    )
    from attest_core.evidence import (
        EvidenceRecord,
    )
    from attest_core.evidence import (
        verify_attestation as legacy_verify,
    )

    if not isinstance(payload, Mapping):
        raise AttestationError("v2 attestation must be a mapping")
    if evidence is not None:
        for record in evidence:
            if not isinstance(record, EvidenceRecord):
                raise AttestationError("v2 evidence must be EvidenceRecord objects")
    try:
        return legacy_verify(payload, invariant, expected_digest, evidence)
    except LegacyAttestationError as exc:
        raise AttestationError(str(exc)) from exc


def verify_v3(
    payload: object,
    invariant: Invariant,
    expected_digest: str,
    evidence: Sequence[EvidenceRecord] | None = None,
) -> AttestationV3:
    """Verify v3 integrity: structure, digest, bindings, ordered evidence.

    ``evidence=None`` skips ordered record binding only; structure,
    digest, and invariant bindings still apply.
    """
    from attest_core.evidence import EvidenceRecord

    if not isinstance(payload, Mapping):
        raise AttestationError("v3 attestation must be a mapping")
    if not isinstance(invariant, documents.Invariant):
        raise AttestationError("attestation invariant must be an Invariant instance")
    attestation = parse_attestation(payload)
    if canonical.digest_of(dict(payload)) != expected_digest:
        raise AttestationError("attestation digest mismatch")
    if (
        attestation.invariant_id != invariant.invariant_id
        or attestation.invariant_version != invariant.version
    ):
        raise AttestationError("attestation refers to a different invariant")
    if attestation.content_digest != documents.invariant_digest(invariant):
        raise AttestationError("attestation content digest does not match invariant")
    if attestation.verification_type != invariant.verification_type:
        raise AttestationError("attestation verification_type does not match invariant")
    if attestation.spec_version != invariant.spec_version:
        raise AttestationError("attestation spec_version does not match invariant")
    if evidence is not None:
        actual_hashes: list[str] = []
        for record in evidence:
            if not isinstance(record, EvidenceRecord):
                raise AttestationError("v3 evidence must be EvidenceRecord objects")
            actual_hashes.append(canonical.digest_of(record.to_payload()))
        if actual_hashes != list(attestation.evidence_hashes):
            raise AttestationError("attestation evidence hashes do not match records")
    return attestation


def verify_historical(
    payload: object,
    invariant: Invariant,
    expected_digest: str,
    materialize: Callable[[RegistryCommit], Path],
    evidence: Sequence[EvidenceRecord] | None = None,
) -> HistoricalAttestation:
    """Verify v3 integrity, then replay approval/lifecycle as of commit.

    Later revocations cannot touch this result: eligibility is folded
    at the recorded commit, never at current state. Unresolvable
    history refuses with no verdict and no current-state fallback.
    ``evidence=None`` skips ordered record binding only.

    Materializer contract (full text in
    docs/attest-sdk-history-contract.md): trusted, verifier-controlled,
    never presenter-supplied. It receives the exact recorded commit,
    resolves the immutable commit while ignoring ``ref``, and returns
    one stable snapshot for both folds. The SDK cannot prove
    materializer honesty. Deprecated replays eligible with a warning:
    v3 records no policy, so strict-then is unknowable.
    """
    if schema_version_of(payload) != ATTESTATION_V3:
        raise HistoryUnavailableError("historical replay requires a v3 attestation")
    attestation = verify_v3(payload, invariant, expected_digest, evidence)
    commit = attestation.registry_commit
    if commit.vcs != "git":
        raise HistoryUnavailableError(f"unsupported registry vcs: {commit.vcs!r}")
    try:
        root = Path(materialize(commit))
    except HistoryUnavailableError:
        raise
    except Exception as exc:
        raise HistoryUnavailableError(f"cannot materialize {commit.commit}") from exc
    try:
        registry = Registry(root)
    except RegistryError as exc:
        raise HistoryUnavailableError(f"cannot open registry at {commit.commit}") from exc
    definition = documents.invariant_digest(invariant)
    try:
        approval = registry.effective_approval(
            attestation.invariant_id, attestation.invariant_version, definition
        )
    except RevokedApprovalError as exc:
        raise AttestationError(
            f"approval revoked at {commit.commit}", reason_class="approval-revoked-at-commit"
        ) from exc
    except NoApprovalError as exc:
        raise AttestationError(
            f"no approval at {commit.commit}", reason_class="approval-absent-at-commit"
        ) from exc
    if approval.event_id != attestation.approval_event_id:
        raise AttestationError(
            "recorded approval was not effective", reason_class="approval-mismatch-at-commit"
        )
    state = registry.lifecycle_state(attestation.invariant_id, attestation.invariant_version)
    if state != attestation.lifecycle_state or state not in _ELIGIBLE_THEN:
        raise AttestationError(
            "recorded lifecycle state was not eligible",
            reason_class="lifecycle-mismatch-at-commit",
        )
    warnings = ("deprecated",) if state == "deprecated" else ()
    return HistoricalAttestation(attestation, approval.event_id, state, commit, warnings)
