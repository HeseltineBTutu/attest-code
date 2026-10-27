"""Approval record store: a YAML file keyed by invariant id and version."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from attest_core.invariants import InvariantRegistryError
from attest_spec import ApprovalRecord, Invariant

DEFAULT_APPROVALS_FILE = "approvals.yaml"


class ApprovalStoreError(Exception):
    """Raised when the approval store is unreadable or invalid."""


def _parse_record(item: Mapping[str, Any]) -> ApprovalRecord:
    try:
        return ApprovalRecord(
            invariant_id=str(item["invariant_id"]),
            invariant_version=int(str(item["invariant_version"])),
            approver=str(item["approver"]),
            approved_at=str(item["approved_at"]),
            content_digest=str(item["content_digest"]),
            method=str(item["method"]),
        )
    except KeyError as exc:
        raise ApprovalStoreError(f"approval record missing key: {exc}") from exc
    except ValueError as exc:
        raise ApprovalStoreError(f"invalid approval record: {exc}") from exc


def load_approvals(path: Path) -> list[ApprovalRecord]:
    """Load approvals; a missing file means no previous approvals."""
    if not path.exists():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ApprovalStoreError(f"cannot parse {path}: {exc}") from exc
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ApprovalStoreError(f"{path} must contain a list of approvals")
    records: list[ApprovalRecord] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise ApprovalStoreError(f"{path} entries must be mappings")
        records.append(_parse_record(item))
    return records


def save_approvals(path: Path, records: Sequence[ApprovalRecord]) -> None:
    """Write approvals deterministically sorted by id and version."""
    payload = [
        {
            "invariant_id": record.invariant_id,
            "invariant_version": record.invariant_version,
            "approver": record.approver,
            "approved_at": record.approved_at,
            "content_digest": record.content_digest,
            "method": record.method,
        }
        for record in sorted(records, key=lambda r: (r.invariant_id, r.invariant_version))
    ]
    path.write_text(
        yaml.safe_dump(payload, sort_keys=True, default_flow_style=False),
        encoding="utf-8",
    )


def upsert_approval(
    records: Sequence[ApprovalRecord], approval: ApprovalRecord
) -> list[ApprovalRecord]:
    """Replace any prior approval for the same id and version."""
    kept = [
        record
        for record in records
        if (record.invariant_id, record.invariant_version)
        != (approval.invariant_id, approval.invariant_version)
    ]
    return [*kept, approval]


def find_approval(
    records: Sequence[ApprovalRecord], invariant_id: str, version: int
) -> ApprovalRecord | None:
    """Return the stored approval for one id and version, if any."""
    for record in records:
        if record.invariant_id == invariant_id and record.invariant_version == version:
            return record
    return None


def select_invariant(definitions: Sequence[Invariant], invariant_id: str | None) -> Invariant:
    """Select one invariant from a definition file, failing closed."""
    if invariant_id is None:
        if len(definitions) != 1:
            raise InvariantRegistryError("file holds multiple invariants; pass --id")
        return definitions[0]
    matches = [d for d in definitions if d.invariant_id == invariant_id]
    if not matches:
        raise InvariantRegistryError(f"unknown invariant id: {invariant_id}")
    if len(matches) != 1:
        raise InvariantRegistryError(f"multiple versions of {invariant_id}; unsupported")
    return matches[0]
