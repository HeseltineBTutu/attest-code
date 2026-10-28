"""Loading, validating, versioning, and resolving approved invariants."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from attest_spec import ApprovalRecord, Invariant

IGNORED_DEFINITION_KEYS = frozenset({"approved", "approval"})
"""Keys accepted in definition files but never treated as proof of approval."""


class InvariantRegistryError(Exception):
    """Raised when invariant definitions or approvals are invalid."""


def parse_invariant(data: Mapping[str, object]) -> Invariant:
    """Validate one invariant definition mapping.

    An ``approved`` key is explicitly ignored: only a separate
    :class:`ApprovalRecord` created through :func:`create_approval`
    confers authority.
    """
    try:
        invariant_id = str(data["id"])
        version = int(str(data["version"]))
        title = str(data.get("title", invariant_id))
        requirement = str(data["requirement"])
        raw_scope = data["scope"]
    except KeyError as exc:
        raise InvariantRegistryError(f"missing required key: {exc}") from exc
    if not isinstance(raw_scope, Sequence) or isinstance(raw_scope, (str, bytes)):
        raise InvariantRegistryError("scope must be a list of strings")
    scope = tuple(str(item) for item in raw_scope)
    try:
        return Invariant(
            invariant_id=invariant_id,
            version=version,
            title=title,
            requirement=requirement,
            scope=scope,
        )
    except ValueError as exc:
        raise InvariantRegistryError(str(exc)) from exc


def invariant_content_digest(invariant: Invariant) -> str:
    """Digest of the exact content an approval binds to."""
    payload = {
        "id": invariant.invariant_id,
        "version": invariant.version,
        "title": invariant.title,
        "requirement": invariant.requirement,
        "scope": list(invariant.scope),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def approval_digest(approval: ApprovalRecord) -> str:
    """Digest of the complete validated approval record."""
    payload = {
        "invariant_id": approval.invariant_id,
        "invariant_version": approval.invariant_version,
        "approver": approval.approver,
        "approved_at": approval.approved_at,
        "content_digest": approval.content_digest,
        "method": approval.method,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def create_approval(
    invariant: Invariant,
    *,
    approver: str,
    approved_at: str,
    method: str,
) -> ApprovalRecord:
    """Record explicit human approval for one exact invariant version.

    This is the approval boundary: it must be invoked by a human-driven
    flow (CLI command, review UI), never by the model's repair workflow.
    """
    if not approver.strip():
        raise InvariantRegistryError("approver must be a named human reviewer")
    return ApprovalRecord(
        invariant_id=invariant.invariant_id,
        invariant_version=invariant.version,
        approver=approver,
        approved_at=approved_at,
        content_digest=invariant_content_digest(invariant),
        method=method,
    )


def is_approval_valid(invariant: Invariant, approval: ApprovalRecord) -> bool:
    """Check that an approval binds to this exact invariant content."""
    return (
        approval.invariant_id == invariant.invariant_id
        and approval.invariant_version == invariant.version
        and approval.content_digest == invariant_content_digest(invariant)
    )


def load_definitions(path: Path) -> list[Invariant]:
    """Load invariant definitions from a YAML file (untrusted until approved)."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise InvariantRegistryError("definition file must contain a list")
    definitions: list[Invariant] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise InvariantRegistryError("each definition must be a mapping")
        definitions.append(parse_invariant(item))
    return definitions


class Registry:
    """Holds definitions and separate approvals; resolves only approved items."""

    def __init__(self) -> None:
        self._definitions: dict[tuple[str, int], Invariant] = {}
        self._approvals: dict[tuple[str, int], ApprovalRecord] = {}

    def register_definition(self, invariant: Invariant) -> None:
        self._definitions[(invariant.invariant_id, invariant.version)] = invariant

    def register_approval(self, approval: ApprovalRecord) -> None:
        key = (approval.invariant_id, approval.invariant_version)
        definition = self._definitions.get(key)
        if definition is None:
            raise InvariantRegistryError(f"no definition for approval {key}")
        if not is_approval_valid(definition, approval):
            raise InvariantRegistryError(f"approval does not match definition {key}")
        self._approvals[key] = approval

    def approved_invariants(self) -> list[Invariant]:
        """Return definitions with a valid, matching approval."""
        approved: list[Invariant] = []
        for key, definition in sorted(self._definitions.items()):
            approval = self._approvals.get(key)
            if approval is not None and is_approval_valid(definition, approval):
                approved.append(definition)
        return approved
