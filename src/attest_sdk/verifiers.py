"""Verifier protocol: observations and evidence, never verdicts.

A verifier reports per-attempt outcomes, check records, and detail;
the parent engine validates every observation, runs the attempts,
and alone classifies PASSED/FAILED/INCONCLUSIVE. Normative
procedure and evidence expectations come from the invariant's
verification type (§10); implementations document how they meet
them and MUST NOT weaken them.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Any, Protocol

from attest_sdk.errors import (
    SchemaError,
    UnsupportedVerifierSpecError,
    VerifierError,
    VerifierRefusedError,
)
from attest_sdk.registry import Policy
from attest_spec import AttemptOutcome

if TYPE_CHECKING:
    from attest_core.verification import CheckEvidence


@dataclasses.dataclass(frozen=True)
class ArtifactState:
    """Exact artifact-digest state: available or explicitly unavailable."""

    available: bool
    algorithm: str | None = None
    value: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.available, bool):
            raise SchemaError("artifact available must be a boolean")
        if self.available:
            if not isinstance(self.algorithm, str) or not self.algorithm:
                raise SchemaError("available artifact needs an algorithm")
            if not isinstance(self.value, str) or not self.value:
                raise SchemaError("available artifact needs a digest value")
            if self.reason is not None:
                raise SchemaError("available artifact takes no reason")
        else:
            if not isinstance(self.reason, str) or not self.reason:
                raise SchemaError("unavailable artifact needs a reason")
            if self.algorithm is not None or self.value is not None:
                raise SchemaError("unavailable artifact takes no digest")


@dataclasses.dataclass(frozen=True)
class VerifierRef:
    """Exact pinned verifier identity (request-only, never in documents)."""

    type: str  # noqa: A003 - §9 wire name is `type`
    implementation: str
    version: str
    artifact: ArtifactState

    def __post_init__(self) -> None:
        for field in ("type", "implementation", "version"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value:
                raise SchemaError(f"verifier_ref.{field} must be a non-empty string")
        if not isinstance(self.artifact, ArtifactState):
            raise SchemaError("verifier_ref.artifact is malformed")


@dataclasses.dataclass(frozen=True)
class AttemptObservation:
    """One verifier-reported attempt: outcome, checks, detail."""

    outcome: AttemptOutcome
    checks: tuple[CheckEvidence, ...]
    detail: str


class Verifier(Protocol):
    """Exact-pinned executable behind one normative verification type."""

    verification_type: str
    implementation: str
    version: str
    spec_versions: tuple[int, ...]
    inventory_mechanism: str

    def run(
        self, scope: tuple[str, ...], target: str | None, params: dict[str, Any]
    ) -> AttemptObservation:
        """Execute one attempt; report observations, never a verdict."""
        ...


_NORMATIVE_PROBES = ("unauthenticated-rejected", "non-admin-denied", "admin-allowed")
_SCOPE_CHECK = "scope-coverage"


def _infra(num: int, why: str) -> tuple[AttemptOutcome, tuple[Any, ...], str]:
    return (AttemptOutcome.INFRA_FAILURE, (), f"attempt {num}: {why}")


def _gate_decisive(
    outcome: AttemptOutcome,
    checks: tuple[Any, ...],
    scope: tuple[str, ...],
    num: int,
    detail: str,
) -> tuple[AttemptOutcome, tuple[Any, ...], str]:
    """PASS/VIOLATION need coverage plus a complete coherent probe matrix."""
    coverage = [item for item in checks if item.check_id == _SCOPE_CHECK]
    if not coverage or not all(item.passed for item in coverage):
        return _infra(num, "missing passing scope-coverage")
    probes = [item for item in checks if item.check_id in _NORMATIVE_PROBES]
    for endpoint in scope:
        for probe_id in _NORMATIVE_PROBES:
            present = any(item.target == endpoint and item.check_id == probe_id for item in probes)
            if not present:
                return _infra(num, f"missing probe {probe_id} for {endpoint}")
    failed = [item for item in probes if not item.passed]
    if outcome is AttemptOutcome.PASS and failed:
        return _infra(num, "failed probe under PASS outcome")
    if outcome is AttemptOutcome.VIOLATION and not failed:
        return _infra(num, "violation without failing probe")
    return outcome, checks, detail


def validate_observation(
    observation: object, scope: tuple[str, ...], attempt_no: int
) -> tuple[AttemptOutcome, tuple[Any, ...], str]:
    """Validate one observation; incoherent or unfaithful becomes INFRA."""
    from attest_core.verification import CheckEvidence

    if not isinstance(observation, AttemptObservation):
        return _infra(attempt_no, "malformed observation")
    raw: Any = observation
    outcome = raw.outcome
    if not isinstance(outcome, AttemptOutcome):
        return _infra(attempt_no, "invalid outcome")
    detail = raw.detail
    if not isinstance(detail, str):
        return _infra(attempt_no, "malformed detail")
    checks = raw.checks
    if not isinstance(checks, (tuple, list)):
        return _infra(attempt_no, "malformed checks")
    for item in checks:
        if (
            not isinstance(item, CheckEvidence)
            or not isinstance(item.check_id, str)
            or not isinstance(item.target, str)
            or not isinstance(item.passed, bool)
            or not isinstance(item.detail, str)
        ):
            return _infra(attempt_no, "malformed evidence")
    if outcome is AttemptOutcome.INFRA_FAILURE:
        return outcome, tuple(checks), detail
    return _gate_decisive(outcome, tuple(checks), scope, attempt_no, detail)


def match_pin(
    pin: VerifierRef,
    *,
    verification_type: str,
    spec_version: int,
    verifier: Verifier,
    policy: Policy,
) -> None:
    """Refuse unless pin, verifier object, and invariant agree exactly."""
    if pin.type != verification_type:
        raise VerifierError(
            "pin type must equal verification_type", reason_class="verifier-type-mismatch"
        )
    if getattr(verifier, "verification_type", None) != verification_type:
        raise VerifierError(
            "verifier type must equal verification_type", reason_class="verifier-type-mismatch"
        )
    implementation = getattr(verifier, "implementation", None)
    version = getattr(verifier, "version", None)
    if implementation != pin.implementation or version != pin.version:
        raise VerifierError("verifier does not match pin", reason_class="verifier-pin-mismatch")
    specs = getattr(verifier, "spec_versions", ())
    if not isinstance(specs, (tuple, list)) or spec_version not in specs:
        raise UnsupportedVerifierSpecError(f"verifier lacks spec {spec_version}")
    mechanism = getattr(verifier, "inventory_mechanism", None)
    if not isinstance(mechanism, str) or not mechanism:
        raise VerifierRefusedError(
            "no inventory mechanism", reason_class="missing-inventory-mechanism"
        )
    if not callable(getattr(verifier, "run", None)):
        raise VerifierRefusedError("verifier not runnable", reason_class="verifier-not-callable")
    if policy.require_artifact_digest and not pin.artifact.available:
        raise VerifierRefusedError("artifact digest required", reason_class="artifact-unavailable")
