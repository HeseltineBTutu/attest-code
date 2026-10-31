"""Verification-request representation and validation (§9).

Wire shapes are validated here; binding checks against the
invariant, registry, and verifier live in the engine. Unknown
fields refuse at every level. The artifact state uses an
explicit ``status`` discriminator (``available`` with
``algorithm`` + ``value``, or ``unavailable`` with ``reason``)
so availability is never silently omitted.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from typing import Any, Final

from attest_sdk.errors import SchemaError, UnsupportedSpecVersionError
from attest_sdk.registry import Policy
from attest_sdk.verifiers import ArtifactState, VerifierRef
from attest_sdk.version import SUPPORTED_SPEC_VERSIONS

EXECUTION_PROFILES: Final = ("standard", "contained", "hardened")
"""Normative v1 execution-profile set (§9, F2)."""

_HEX64: Final = re.compile(r"[0-9a-f]{64}")
_REVISION_RE: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REQUIRED: Final = frozenset(
    {
        "invariant_id",
        "invariant_version",
        "spec_version",
        "expected_content_digest",
        "approval_ref",
        "repo",
        "revision",
        "verifier_ref",
        "execution_profile",
    }
)
_OPTIONAL: Final = frozenset({"timeout", "target_selector", "client", "policy", "request_metadata"})


@dataclasses.dataclass(frozen=True)
class VerificationRequest:
    """Validated §9 verification request (structure only)."""

    invariant_id: str
    invariant_version: int
    spec_version: int
    expected_content_digest: str
    approval_ref: str
    repo: str
    revision: str
    verifier_ref: VerifierRef
    execution_profile: str
    timeout: int | None = None
    target_selector: str | None = None
    client: str | None = None
    policy: Policy | None = None
    request_metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.invariant_id, str) or not self.invariant_id:
            raise SchemaError("invariant_id must be a non-empty string")
        if (
            not isinstance(self.invariant_version, int)
            or isinstance(self.invariant_version, bool)
            or self.invariant_version < 1
        ):
            raise SchemaError("invariant_version must be an integer >= 1")
        if not isinstance(self.spec_version, int) or isinstance(self.spec_version, bool):
            raise SchemaError("spec_version must be an integer")
        if self.spec_version not in SUPPORTED_SPEC_VERSIONS:
            raise UnsupportedSpecVersionError(f"unsupported spec_version: {self.spec_version}")
        for field in ("expected_content_digest", "approval_ref"):
            value = getattr(self, field)
            if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
                raise SchemaError(f"{field} must be a 64-hex digest")
        if not isinstance(self.repo, str) or not self.repo:
            raise SchemaError("repo must be a non-empty string")
        if not isinstance(self.revision, str) or _REVISION_RE.fullmatch(self.revision) is None:
            raise SchemaError("revision must be a 40- or 64-hex commit id")
        if not isinstance(self.verifier_ref, VerifierRef):
            raise SchemaError("verifier_ref is malformed")
        if self.execution_profile not in EXECUTION_PROFILES:
            raise SchemaError(f"unsupported execution_profile: {self.execution_profile!r}")
        if self.timeout is not None and (
            not isinstance(self.timeout, int) or isinstance(self.timeout, bool) or self.timeout < 1
        ):
            raise SchemaError("timeout must be a positive integer")
        for field in ("target_selector", "client"):
            value = getattr(self, field)
            if value is not None and (not isinstance(value, str) or not value):
                raise SchemaError(f"{field} must be a non-empty string")
        if self.policy is not None and not isinstance(self.policy, Policy):
            raise SchemaError("policy is malformed")
        if self.request_metadata is not None and not isinstance(self.request_metadata, dict):
            raise SchemaError("request_metadata must be an object")


def _artifact_from_wire(value: object) -> ArtifactState:
    if not isinstance(value, dict):
        raise SchemaError("verifier_ref.artifact must be an object")
    status = value.get("status")
    if status == "available":
        unknown = set(value) - {"status", "algorithm", "value"}
        if unknown:
            raise SchemaError(f"unknown artifact field: {sorted(unknown)[0]!r}")
        return ArtifactState(True, algorithm=value.get("algorithm"), value=value.get("value"))
    if status == "unavailable":
        unknown = set(value) - {"status", "reason"}
        if unknown:
            raise SchemaError(f"unknown artifact field: {sorted(unknown)[0]!r}")
        return ArtifactState(False, reason=value.get("reason"))
    raise SchemaError("artifact status must be available or unavailable")


def _ref_from_wire(value: object) -> VerifierRef:
    if not isinstance(value, dict):
        raise SchemaError("verifier_ref must be an object")
    unknown = set(value) - {"type", "implementation", "version", "artifact"}
    if unknown:
        raise SchemaError(f"unknown verifier_ref field: {sorted(unknown)[0]!r}")
    for field in ("type", "implementation", "version", "artifact"):
        if field not in value:
            raise SchemaError(f"verifier_ref missing required field: {field}")
    return VerifierRef(
        type=value["type"],
        implementation=value["implementation"],
        version=value["version"],
        artifact=_artifact_from_wire(value["artifact"]),
    )


def _policy_from_wire(value: object) -> Policy:
    if not isinstance(value, dict):
        raise SchemaError("policy must be an object")
    unknown = set(value) - {"strict_deprecated", "require_artifact_digest"}
    if unknown:
        raise SchemaError(f"unknown policy field: {sorted(unknown)[0]!r}")
    flags: dict[str, bool] = {}
    for field in ("strict_deprecated", "require_artifact_digest"):
        if field in value:
            if not isinstance(value[field], bool):
                raise SchemaError(f"policy.{field} must be a boolean")
            flags[field] = value[field]
    return Policy(**flags)


def parse_request(data: object) -> VerificationRequest:
    """Validate untrusted wire data into a verification request."""
    if not isinstance(data, Mapping):
        raise SchemaError("request must be an object")
    unknown = set(data) - _REQUIRED - _OPTIONAL
    if unknown:
        raise SchemaError(f"unknown request field: {sorted(unknown)[0]!r}")
    for field in sorted(_REQUIRED):
        if field not in data:
            raise SchemaError(f"missing required field: {field}")
    policy = data.get("policy")
    metadata = data.get("request_metadata")
    return VerificationRequest(
        invariant_id=data["invariant_id"],
        invariant_version=data["invariant_version"],
        spec_version=data["spec_version"],
        expected_content_digest=data["expected_content_digest"],
        approval_ref=data["approval_ref"],
        repo=data["repo"],
        revision=data["revision"],
        verifier_ref=_ref_from_wire(data["verifier_ref"]),
        execution_profile=data["execution_profile"],
        timeout=data.get("timeout"),
        target_selector=data.get("target_selector"),
        client=data.get("client"),
        policy=None if policy is None else _policy_from_wire(policy),
        request_metadata=metadata,
    )
