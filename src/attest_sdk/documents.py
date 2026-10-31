"""v1 invariant documents: types, loading, and content digests.

Loading follows the frozen acceptance sequence: parse, schema
validation, then digest over the covered-field projection.
`publisher` and `metadata` are preserved but never digested.
Unknown verification types load successfully; execution-time
refusal is a separate explicit check.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Final

from attest_sdk import canonical, schema
from attest_sdk.errors import UnknownVerificationTypeError

KNOWN_VERIFICATION_TYPES: Final = frozenset({"http-auth-probe/1"})
_COVERED_OPTIONAL: Final = (
    "description",
    "applicability",
    "parameters",
    "evidence_expectations",
)


@dataclasses.dataclass(frozen=True)
class Invariant:
    """Validated v1 invariant document with preserved extras."""

    spec_version: int
    invariant_id: str
    version: int
    title: str
    requirement: str
    scope: tuple[str, ...]
    invariant_type: str
    verification_type: str
    description: str | None = None
    applicability: dict[str, Any] | None = None
    parameters: dict[str, Any] | None = None
    evidence_expectations: dict[str, Any] | None = None
    publisher: str | None = None
    metadata: dict[str, Any] | None = None
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)


def ensure_known_verification_type(invariant: Invariant) -> None:
    """Refuse unknown verification types (execution boundary check)."""
    if invariant.verification_type not in KNOWN_VERIFICATION_TYPES:
        raise UnknownVerificationTypeError(
            f"unknown verification_type: {invariant.verification_type!r}"
        )


def invariant_digest(invariant: Invariant) -> str:
    """Content digest over the covered-field projection (no publisher)."""
    payload: dict[str, Any] = {
        "spec_version": invariant.spec_version,
        "id": invariant.invariant_id,
        "version": invariant.version,
        "title": invariant.title,
        "requirement": invariant.requirement,
        "scope": list(invariant.scope),
        "invariant_type": invariant.invariant_type,
        "verification_type": invariant.verification_type,
    }
    for key in _COVERED_OPTIONAL:
        field = getattr(invariant, key)
        if field is not None:
            payload[key] = field
    payload.update(invariant.extra)
    return canonical.digest_of(payload)


def _build(value: dict[str, Any]) -> Invariant:
    return Invariant(
        spec_version=value["spec_version"],
        invariant_id=value["id"],
        version=value["version"],
        title=value["title"],
        requirement=value["requirement"],
        scope=tuple(value["scope"]),
        invariant_type=value["invariant_type"],
        verification_type=value["verification_type"],
        description=value.get("description"),
        applicability=value.get("applicability"),
        parameters=value.get("parameters"),
        evidence_expectations=value.get("evidence_expectations"),
        publisher=value.get("publisher"),
        metadata=value.get("metadata"),
        extra={key: item for key, item in value.items() if key.startswith("x-")},
    )


def load_invariant(source: Path | bytes, source_format: str = "json") -> Invariant:
    """Parse, validate, and bind a v1 invariant document from bytes or path.

    File-system errors propagate unwrapped; document problems raise
    ParseError, SchemaError, or CanonicalizationError.
    """
    if source_format not in ("json", "yaml"):
        raise ValueError(f"unsupported format: {source_format!r}")
    data = source.read_bytes() if isinstance(source, Path) else source
    value = canonical.parse_bytes(data, source_format=source_format)
    schema.validate_document(value)
    return _build(value)
