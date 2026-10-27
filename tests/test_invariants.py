"""Invariant policy: approval boundary, versioning, and registry."""

from __future__ import annotations

import pytest

from attest_core.invariants import (
    InvariantRegistryError,
    Registry,
    create_approval,
    is_approval_valid,
    parse_invariant,
)


def _definition() -> dict[str, object]:
    return {
        "id": "AUTH-ADMIN-001",
        "version": 1,
        "title": "Admin endpoints require admin role",
        "requirement": "Every endpoint in scope rejects unauthenticated requests.",
        "scope": ["/admin/users", "/admin/settings"],
    }


def test_yaml_approved_flag_is_ignored() -> None:
    data = _definition() | {"approved": True}
    invariant = parse_invariant(data)
    assert invariant.invariant_id == "AUTH-ADMIN-001"
    registry = Registry()
    registry.register_definition(invariant)
    assert registry.approved_invariants() == []


def test_approval_makes_definition_authoritative() -> None:
    invariant = parse_invariant(_definition())
    approval = create_approval(
        invariant, approver="ada", approved_at="2026-01-01T00:00:00Z", method="cli-review"
    )
    registry = Registry()
    registry.register_definition(invariant)
    registry.register_approval(approval)
    assert registry.approved_invariants() == [invariant]


def test_modified_requirement_invalidates_approval() -> None:
    invariant = parse_invariant(_definition())
    approval = create_approval(
        invariant, approver="ada", approved_at="2026-01-01T00:00:00Z", method="cli-review"
    )
    tampered = parse_invariant(_definition() | {"requirement": "weakened"})
    assert not is_approval_valid(tampered, approval)


def test_new_version_requires_renewed_approval() -> None:
    v1 = parse_invariant(_definition())
    approval_v1 = create_approval(
        v1, approver="ada", approved_at="2026-01-01T00:00:00Z", method="cli-review"
    )
    v2 = parse_invariant(_definition() | {"version": 2})
    assert not is_approval_valid(v2, approval_v1)
    registry = Registry()
    registry.register_definition(v2)
    with pytest.raises(InvariantRegistryError):
        registry.register_approval(approval_v1)


def test_approval_without_definition_is_rejected() -> None:
    invariant = parse_invariant(_definition())
    approval = create_approval(
        invariant, approver="ada", approved_at="2026-01-01T00:00:00Z", method="cli-review"
    )
    registry = Registry()
    with pytest.raises(InvariantRegistryError):
        registry.register_approval(approval)
