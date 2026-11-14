"""F3 digest projection v1 and record digest calculation (§8.2).

Projection removes exactly the excluded fields, then hashes the
canonical bytes with the pinned attest-canonical-json v1. Schema
validation always runs before projection (pipeline order), so
unknown fields are rejected, never silently dropped. Record
digests use attest_sdk.canonical exclusively; the stdlib-based
attest_core.evidence.canonical_bytes emits different bytes and
MUST NOT be substituted here.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from attest_core import f3_records_campaign, f3_records_env, f3_records_summary
from attest_core import f3_schema as sc
from attest_core.f3_errors import F3SchemaError
from attest_core.f3_records import validate_attempt, validate_total
from attest_sdk import canonical
from attest_sdk.errors import AttestError

PROJECTION_NAME = "f3-digest-projection"
PROJECTION_VERSION = 1
CANONICAL_NAME = "attest-canonical-json"
CANONICAL_VERSION = 1

# NOTE: the canonicalizer module carries no version marker of its own;
# behavior is pinned by golden vectors (tests), and manifests pin the
# versions this code implements (refused unless exactly matched).
EXCLUDED_BY_KIND: dict[str, frozenset[str]] = {
    "attempt": frozenset(),
    "invocation_total": frozenset(),
    "environment": frozenset(),
    "campaign": frozenset({"observed_start_wallclock"}),
    "summary": frozenset(),
}


@dataclasses.dataclass(frozen=True)
class DigestCheck:
    """Outcome of a digest comparison (data never raises)."""

    ok: bool
    reason: str


def _validate_record(kind: str, record: dict[str, Any]) -> dict[str, Any]:
    """Schema-validate a record object, enforcing pipeline order."""
    validators = {
        "attempt": validate_attempt,
        "invocation_total": validate_total,
        "environment": f3_records_env.validate_environment,
        "campaign": f3_records_campaign.validate_campaign,
        "summary": f3_records_summary.validate_summary,
    }
    validate = validators.get(kind) if isinstance(kind, str) else None
    if validate is None:
        raise F3SchemaError(
            rule="V-B6", section="8.2", location="$", reason=f"unknown kind: {kind!r}"
        )
    validate(record)
    return record


def project(kind: str, record: Any, section: str = "8.2", location: str = "$") -> dict[str, Any]:
    """Project a record to its exact digest input (new dict, input kept).

    Record kinds are schema-validated first. The "manifest"
    pseudo-kind is object-checked only: its caller (manifest
    validation) MUST shape-validate first. Projections are
    fresh dicts; inputs are never mutated.
    """
    if kind == "manifest":
        obj = sc.check_object(record, section, location)
        return {key: obj[key] for key in obj if not key.startswith("observed_")}
    validated = _validate_record(kind, record)
    excluded = EXCLUDED_BY_KIND[kind]
    return {key: validated[key] for key in validated if key not in excluded}


def record_digest(kind: str, record: Any, section: str = "8.2", location: str = "$") -> str:
    """SHA-256 hex over the canonical bytes of the projected record."""
    projected = project(kind, record, section, location)
    try:
        return canonical.digest_of(projected)
    except AttestError as exc:
        raise F3SchemaError(
            rule="V-B6",
            section=section,
            location=location,
            reason=f"canonicalizer refused: {exc.reason_class}: {exc}",
        ) from exc


def verify_record_digest(kind: str, record: Any, expected: Any) -> DigestCheck:
    """Compare a recomputed digest against a listed one (no raise on data)."""
    try:
        computed = record_digest(kind, record)
    except F3SchemaError as exc:
        return DigestCheck(ok=False, reason=f"unverifiable record: {exc}")
    if computed != expected:
        return DigestCheck(
            ok=False, reason=f"digest mismatch: computed {computed} != listed {expected!r}"
        )
    return DigestCheck(ok=True, reason="match")


def _require_pin(pin: Any, name: str, version: int, what: str, section: str, location: str) -> None:
    """Exact-version-or-refuse for a manifest version pin."""
    obj = sc.check_object(pin, section, location)
    sc.reject_unknown(obj, frozenset({"name", "version"}), section, location)
    if obj.get("name") != name:
        raise F3SchemaError(
            rule="V-B6",
            section=section,
            location=f"{location}.name",
            reason=f"unsupported {what} name: {obj.get('name')!r} (implements {name!r})",
        )
    found = obj.get("version")
    if type(found) is not int or found != version:
        raise F3SchemaError(
            rule="V-B6",
            section=section,
            location=f"{location}.version",
            reason=f"unsupported {what} version: {found!r} (implements {version})",
        )


def require_projection(pin: Any, section: str = "8.2", location: str = "$") -> None:
    """Refuse any digest-projection pin other than v1 exactly."""
    _require_pin(pin, PROJECTION_NAME, PROJECTION_VERSION, "digest projection", section, location)


def require_canonicalizer(pin: Any, section: str = "8.2", location: str = "$") -> None:
    """Refuse any canonicalizer pin other than v1 exactly."""
    _require_pin(pin, CANONICAL_NAME, CANONICAL_VERSION, "canonicalizer", section, location)
