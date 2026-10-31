"""Approval/lifecycle event parsing, hashing, and chain validation."""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Final, TypeGuard

from attest_sdk import canonical
from attest_sdk.errors import AmbiguousHistoryError, CanonicalizationError

APPROVAL_TYPES: Final = frozenset({"APPROVE", "REVOKE_APPROVAL", "NOTE"})
LIFECYCLE_TYPES: Final = frozenset({"ACTIVATE", "DEPRECATE", "SUPERSEDE", "REVOKE_INVARIANT"})
_APPROVAL_FIELDS: Final = frozenset(
    {
        "seq",
        "prev",
        "event_id",
        "invariant_id",
        "invariant_version",
        "invariant_digest",
        "event_type",
        "approver",
        "approver_id",
        "method",
        "timestamp",
        "reason",
        "supersedes",
    }
)
_LIFECYCLE_FIELDS: Final = frozenset(
    {
        "seq",
        "prev",
        "event_id",
        "invariant_id",
        "invariant_version",
        "event_type",
        "actor",
        "timestamp",
        "reason",
        "successor_version",
    }
)
_HEX64: Final = re.compile(r"[0-9a-f]{64}")
_METHOD_RE: Final = re.compile(r"[a-z0-9][a-z0-9.\-]{0,63}")


@dataclasses.dataclass(frozen=True)
class ApprovalEvent:
    """Validated approval-history event (§7)."""

    seq: int
    prev: str | None
    event_id: str
    invariant_id: str
    invariant_version: int
    invariant_digest: str
    event_type: str
    approver: str
    approver_id: str | None
    method: str
    timestamp: str
    reason: str | None
    supersedes: str | None


@dataclasses.dataclass(frozen=True)
class LifecycleEvent:
    """Validated lifecycle-history event (§8)."""

    seq: int
    prev: str | None
    event_id: str
    invariant_id: str
    invariant_version: int
    event_type: str
    actor: str
    timestamp: str
    reason: str | None
    successor_version: int | None


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _fail(message: str, reason: str) -> AmbiguousHistoryError:
    return AmbiguousHistoryError(message, reason_class=reason)


def _verify_event_id(value: dict[str, Any], event_id: str) -> None:
    """Require hash(canonical payload without event_id) == embedded id."""
    payload = {key: item for key, item in value.items() if key != "event_id"}
    try:
        recomputed = canonical.digest_of(payload)
    except CanonicalizationError as exc:
        raise _fail(f"event not canonicalizable: {exc}", exc.reason_class) from exc
    if recomputed != event_id:
        raise _fail("event hash mismatch", "event-hash-mismatch")


def _opt_str(value: dict[str, Any], field: str) -> str | None:
    field_value = value.get(field)
    if field_value is not None and not isinstance(field_value, str):
        raise _fail(f"{field} must be a string", "malformed-event")
    return field_value


def _common(
    value: object, allowed: frozenset[str], kinds: frozenset[str], others: frozenset[str]
) -> dict[str, Any]:
    """Validate shared event shape; kind membership refuses first."""
    if not isinstance(value, dict):
        raise _fail("event must be an object", "malformed-event")
    event_type = value.get("event_type")
    if event_type in others:
        raise _fail(f"misplaced event type: {event_type!r}", "misplaced-event")
    if event_type not in kinds:
        raise _fail(f"unknown event type: {event_type!r}", "malformed-event")
    unknown = set(value) - allowed
    if unknown:
        raise _fail(f"unknown event field: {sorted(unknown)[0]!r}", "malformed-event")
    seq = value.get("seq")
    if not _is_int(seq):
        raise _fail("seq must be an integer", "malformed-event")
    prev = value.get("prev")
    if prev is not None and (not isinstance(prev, str) or _HEX64.fullmatch(prev) is None):
        raise _fail("prev must be null or an event id", "malformed-event")
    event_id = value.get("event_id")
    if not isinstance(event_id, str):
        raise _fail("event_id must be a string", "malformed-event")
    invariant_id = value.get("invariant_id")
    if not isinstance(invariant_id, str):
        raise _fail("invariant_id must be a string", "malformed-event")
    invariant_version = value.get("invariant_version")
    if not _is_int(invariant_version):
        raise _fail("invariant_version must be an integer", "malformed-event")
    timestamp = value.get("timestamp")
    if not isinstance(timestamp, str):
        raise _fail("timestamp must be a string", "malformed-event")
    return {
        "seq": seq,
        "prev": prev,
        "event_id": event_id,
        "invariant_id": invariant_id,
        "invariant_version": invariant_version,
        "event_type": event_type,
        "timestamp": timestamp,
        "reason": _opt_str(value, "reason"),
    }


def parse_approval_event(value: object) -> ApprovalEvent:
    """Validate one approval event object (§7)."""
    base = _common(value, _APPROVAL_FIELDS, APPROVAL_TYPES, LIFECYCLE_TYPES)
    assert isinstance(value, dict)
    digest = value.get("invariant_digest")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise _fail("invariant_digest must be a 64-hex digest", "malformed-event")
    approver = value.get("approver")
    if not isinstance(approver, str):
        raise _fail("approver must be a string", "malformed-event")
    method = value.get("method")
    if not isinstance(method, str) or _METHOD_RE.fullmatch(method) is None:
        raise _fail(f"malformed method: {method!r}", "malformed-event")
    approver_id = _opt_str(value, "approver_id")
    supersedes = _opt_str(value, "supersedes")
    _verify_event_id(value, base["event_id"])
    return ApprovalEvent(
        **base,
        invariant_digest=digest,
        approver=approver,
        approver_id=approver_id,
        method=method,
        supersedes=supersedes,
    )


def parse_lifecycle_event(value: object) -> LifecycleEvent:
    """Validate one lifecycle event object (§8)."""
    base = _common(value, _LIFECYCLE_FIELDS, LIFECYCLE_TYPES, APPROVAL_TYPES)
    assert isinstance(value, dict)
    actor = value.get("actor")
    if not isinstance(actor, str):
        raise _fail("actor must be a string", "malformed-event")
    successor = value.get("successor_version")
    if base["event_type"] == "SUPERSEDE":
        if not _is_int(successor) or successor < 1:
            raise _fail("successor_version must be an integer >= 1", "malformed-event")
    elif "successor_version" in value:
        raise _fail("successor_version only on SUPERSEDE", "malformed-event")
    _verify_event_id(value, base["event_id"])
    return LifecycleEvent(
        **base, actor=actor, successor_version=successor if _is_int(successor) else None
    )
