"""v1 invariant document validation (acceptance step 2).

Checks declared field shapes against the supported spec_version.
Free-form values (parameters, metadata, x- fields) are validated for
declared type only; the canonical layer enforces the value model.
"""

from __future__ import annotations

import re
from typing import Any, Final

from attest_sdk.errors import SchemaError, UnsupportedSpecVersionError
from attest_sdk.version import SUPPORTED_SPEC_VERSIONS

_REQUIRED_STRINGS: Final = (
    "id",
    "title",
    "requirement",
    "invariant_type",
    "verification_type",
)
_COVERED_OBJECTS: Final = ("applicability", "parameters", "evidence_expectations")
_KNOWN_FIELDS: Final = frozenset(
    {
        "spec_version",
        "id",
        "version",
        "title",
        "requirement",
        "scope",
        "invariant_type",
        "verification_type",
        "description",
        "applicability",
        "parameters",
        "evidence_expectations",
        "publisher",
        "metadata",
    }
)
_LIFECYCLE_APPROVAL_KEYS: Final = frozenset({"status", "approved", "approval"})
_TAXONOMY_RE: Final = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)*")
_PUBLISHER_SEGMENT_RE: Final = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_spec_version(value: dict[str, Any]) -> None:
    if "spec_version" not in value:
        raise SchemaError("missing required field: spec_version")
    spec = value["spec_version"]
    if not _is_int(spec):
        raise SchemaError("spec_version must be an integer")
    if spec not in SUPPORTED_SPEC_VERSIONS:
        raise UnsupportedSpecVersionError(f"unsupported spec_version: {spec}")


def _check_required(value: dict[str, Any]) -> None:
    for key in _REQUIRED_STRINGS:
        if key not in value:
            raise SchemaError(f"missing required field: {key}")
        field = value[key]
        if not isinstance(field, str) or not field:
            raise SchemaError(f"{key} must be a non-empty string")
    if "version" not in value:
        raise SchemaError("missing required field: version")
    version = value["version"]
    if not _is_int(version) or version < 1:
        raise SchemaError("version must be an integer >= 1")
    if "scope" not in value:
        raise SchemaError("missing required field: scope")
    scope = value["scope"]
    if not isinstance(scope, list) or not scope:
        raise SchemaError("scope must be a non-empty array of strings")
    for entry in scope:
        if not isinstance(entry, str) or not entry:
            raise SchemaError("scope entries must be non-empty strings")
    if _TAXONOMY_RE.fullmatch(value["invariant_type"]) is None:
        raise SchemaError(f"malformed invariant_type: {value['invariant_type']!r}")


def _check_optional(value: dict[str, Any]) -> None:
    if "description" in value and not isinstance(value["description"], str):
        raise SchemaError("description must be a string")
    for key in _COVERED_OBJECTS:
        if key in value and not isinstance(value[key], dict):
            raise SchemaError(f"{key} must be an object")
    if "publisher" in value:
        _check_publisher(value["publisher"])
    if "metadata" in value and not isinstance(value["metadata"], dict):
        raise SchemaError("metadata must be an object")


def _check_publisher(value: object) -> None:
    if not isinstance(value, str):
        raise SchemaError("publisher must be a string")
    segments = value.split(".")
    if (
        not 1 <= len(value) <= 128
        or len(segments) > 8
        or any(_PUBLISHER_SEGMENT_RE.fullmatch(part) is None for part in segments)
    ):
        raise SchemaError(f"malformed publisher: {value!r}")


def _check_unknown_fields(value: dict[str, Any]) -> None:
    for key in value:
        if not isinstance(key, str):
            raise SchemaError(f"non-string field name: {key!r}")
        if key in _KNOWN_FIELDS or key.startswith("x-"):
            continue
        if key in _LIFECYCLE_APPROVAL_KEYS:
            raise SchemaError(f"lifecycle/approval field rejected in invariant document: {key}")
        raise SchemaError(f"unknown field: {key}")


def validate_document(value: object) -> None:
    """Validate a parsed value against the v1 invariant schema."""
    if not isinstance(value, dict):
        raise SchemaError("invariant document must be an object")
    _check_spec_version(value)
    _check_required(value)
    _check_optional(value)
    _check_unknown_fields(value)
