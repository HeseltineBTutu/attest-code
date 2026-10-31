"""Attestation v3 record and integrity verification (§§11-12).

Full-payload digest, no exclusions; evidence hashes use the same
profile. Emission in ``issuance``; v2 dual-read/replay in ``history``.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from typing import Any, Final

from attest_sdk.commits import RegistryCommit
from attest_sdk.errors import AttestationError, UnsupportedSpecVersionError
from attest_sdk.verifiers import ArtifactState
from attest_sdk.version import SUPPORTED_SPEC_VERSIONS
from attest_spec import Verdict

ATTESTATION_V3: Final = 3
_HEX64: Final = re.compile(r"[0-9a-f]{64}")
_OID: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_VERDICTS: Final = frozenset(item.value for item in Verdict)
_V3_REQUIRED: Final = frozenset(
    {
        "approval_event_id",
        "content_digest",
        "evidence_hashes",
        "execution_profile",
        "invariant_id",
        "invariant_version",
        "lifecycle_state",
        "registry_commit",
        "revision",
        "schema_version",
        "spec_version",
        "statement",
        "verdict",
        "verification_type",
        "verifier",
    }
)


def _is_hex64(item: object) -> bool:
    return isinstance(item, str) and _HEX64.fullmatch(item) is not None


@dataclasses.dataclass(frozen=True)
class AttestationV3:
    """Validated v3 attestation: verdict plus execution-time context."""

    schema_version: int
    verdict: str
    invariant_id: str
    invariant_version: int
    content_digest: str
    evidence_hashes: tuple[str, ...]
    statement: str
    spec_version: int
    approval_event_id: str
    registry_commit: RegistryCommit
    verification_type: str
    verifier_implementation: str
    verifier_version: str
    artifact: ArtifactState
    revision: str
    execution_profile: str
    lifecycle_state: str

    def __post_init__(self) -> None:
        if self.schema_version != ATTESTATION_V3:
            raise AttestationError(f"schema_version must be {ATTESTATION_V3}")
        if self.verdict not in _VERDICTS:
            raise AttestationError(f"invalid verdict: {self.verdict!r}")
        for field in (
            "invariant_id",
            "verification_type",
            "verifier_implementation",
            "verifier_version",
            "execution_profile",
            "lifecycle_state",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not value:
                raise AttestationError(f"{field} must be a non-empty string")
        for field in ("content_digest", "approval_event_id"):
            if not _is_hex64(getattr(self, field)):
                raise AttestationError(f"{field} must be a 64-hex digest")
        if (
            not isinstance(self.invariant_version, int)
            or isinstance(self.invariant_version, bool)
            or self.invariant_version < 1
        ):
            raise AttestationError("invariant_version must be an integer >= 1")
        if not isinstance(self.spec_version, int) or isinstance(self.spec_version, bool):
            raise AttestationError("spec_version must be an integer")
        if self.spec_version not in SUPPORTED_SPEC_VERSIONS:
            raise UnsupportedSpecVersionError(f"unsupported spec_version: {self.spec_version}")
        if (
            not isinstance(self.evidence_hashes, (tuple, list))
            or not self.evidence_hashes
            or any(not _is_hex64(item) for item in self.evidence_hashes)
        ):
            raise AttestationError("evidence_hashes must be a non-empty list of 64-hex digests")
        if not isinstance(self.statement, str):
            raise AttestationError("statement must be a string")
        if not isinstance(self.registry_commit, RegistryCommit):
            raise AttestationError("registry_commit is malformed")
        if not isinstance(self.artifact, ArtifactState):
            raise AttestationError("verifier.artifact is malformed")
        if not isinstance(self.revision, str) or _OID.fullmatch(self.revision) is None:
            raise AttestationError("revision must be a 40- or 64-hex commit id")


def _artifact_from_wire(value: object) -> ArtifactState:
    if not isinstance(value, Mapping):
        raise AttestationError("verifier.artifact must be an object")
    status = value.get("status")
    if status == "available":
        allowed = {"status", "algorithm", "value"}
    elif status == "unavailable":
        allowed = {"status", "reason"}
    else:
        raise AttestationError("artifact status must be available or unavailable")
    unknown = set(value) - allowed
    if unknown:
        raise AttestationError(f"unknown artifact field: {sorted(unknown)[0]!r}")
    if status == "available":
        return ArtifactState(True, algorithm=value.get("algorithm"), value=value.get("value"))
    return ArtifactState(False, reason=value.get("reason"))


def parse_attestation(payload: Mapping[str, Any]) -> AttestationV3:
    """Validate one wire mapping structurally (no digest or binding check).

    Parsing alone never verifies a record; use ``history.verify_v3``
    or ``history.verify_historical`` for integrity and replay.
    """
    unknown = set(payload) - _V3_REQUIRED
    if unknown:
        raise AttestationError(f"unknown attestation field: {sorted(unknown)[0]!r}")
    for field in sorted(_V3_REQUIRED):
        if field not in payload:
            raise AttestationError(f"missing required field: {field}")
    verifier = payload["verifier"]
    if not isinstance(verifier, Mapping):
        raise AttestationError("verifier must be an object")
    extra = set(verifier) - {"implementation", "version", "artifact"}
    if extra:
        raise AttestationError(f"unknown verifier field: {sorted(extra)[0]!r}")
    for field in ("implementation", "version", "artifact"):
        if field not in verifier:
            raise AttestationError(f"verifier missing required field: {field}")
    hashes = payload["evidence_hashes"]
    if not isinstance(hashes, (list, tuple)):
        raise AttestationError("evidence_hashes must be a non-empty list of 64-hex digests")
    fields = dict(payload)
    fields["evidence_hashes"] = tuple(hashes)
    fields["registry_commit"] = RegistryCommit.from_wire(payload["registry_commit"])
    fields["verifier_implementation"] = verifier["implementation"]
    fields["verifier_version"] = verifier["version"]
    fields["artifact"] = _artifact_from_wire(verifier["artifact"])
    del fields["verifier"]
    return AttestationV3(**fields)
