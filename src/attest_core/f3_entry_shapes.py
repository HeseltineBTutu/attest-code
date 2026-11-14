"""F3 manifest entry shapes (V-B6 structural validation)."""

from __future__ import annotations

from typing import Any

from attest_core import f3_fields as ff
from attest_core import f3_schema as sc

ENTRY_RECORD_KEYS = frozenset(
    {"record_id", "kind", "invocation_id", "record_digest_sha256", "relpath"}
)
ENTRY_EVIDENCE_KEYS = frozenset({"invocation_id", "role", "relpath", "evidence_digest_sha256"})


def _relpath_str(value: Any, section: str, location: str) -> str:
    """Entry relpaths must be strings here; V-P1 judges values later."""
    if not isinstance(value, str):
        sc.fail(section, location, "relpath must be a string")
    return value


def _s3_role(value: Any, section: str, location: str) -> str:
    """v1 admits exactly the s3-report role."""
    if value != "s3-report":
        sc.fail(section, location, 'role must be exactly "s3-report"')
    return "s3-report"


def validate_record_entry(value: Any, section: str, location: str) -> dict[str, Any]:
    """Shape-validate one records[] entry (V-B6)."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, ENTRY_RECORD_KEYS, section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    kind = one("kind", ff.record_kind)
    invocation: str | None
    if kind in ("campaign", "summary"):
        invocation = one("invocation_id", ff.null_invocation)
    else:
        invocation = one("invocation_id", ff.uuid4)
    return {
        "record_id": one("record_id", ff.uuid4),
        "kind": kind,
        "invocation_id": invocation,
        "record_digest_sha256": one("record_digest_sha256", ff.digest64),
        "relpath": one("relpath", _relpath_str),
    }


def validate_evidence_entry(value: Any, section: str, location: str) -> dict[str, Any]:
    """Shape-validate one evidence[] entry (V-B6)."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, ENTRY_EVIDENCE_KEYS, section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    return {
        "invocation_id": one("invocation_id", ff.uuid4),
        "role": one("role", _s3_role),
        "relpath": one("relpath", _relpath_str),
        "evidence_digest_sha256": one("evidence_digest_sha256", ff.digest64),
    }
