"""F3 pairwise series comparability function (§10.7).

Computed by consumers and future tooling over two validated
series — never by the single-package validator. Outcomes:
comparable | conditional(reasons) | incomparable(reasons) |
unknown(missing). Established incompatibility beats unknown
context; unknown beats conditional; conditional beats
comparable. Counts and cgroup envelopes ride along as
reported context, never decisive.
"""

from __future__ import annotations

import dataclasses

from attest_core.f3_compare_attrs import InvAttributes


@dataclasses.dataclass(frozen=True)
class ComparabilityResult:
    """One pairwise comparability decision with provenance."""

    outcome: str
    reasons: tuple[str, ...]
    missing: tuple[str, ...]
    context_notes: tuple[str, ...]


def compare(left: list[InvAttributes], right: list[InvAttributes]) -> ComparabilityResult:
    """Pairwise comparability over two validated series' attribute blocks."""
    both = [*left, *right]
    reasons: list[str] = []
    missing: list[str] = []
    for field in ("workload_id", "input_digest", "profile", "timeout_s"):
        _require_equal(both, field, reasons, missing)
    for field in ("pyproject_digest", "uv_lock_digest"):
        _require_known_equal(both, field, reasons, missing)
    _require_class(both, reasons, missing)
    for item in both:
        if item.interference == "unknown":
            missing.append(f"interference:{item.invocation_id}")
    observed = [(item, cond) for item in both for cond in item.conditions]
    if reasons:
        return ComparabilityResult(
            outcome="incomparable",
            reasons=tuple(sorted(reasons)),
            missing=tuple(sorted(missing)),
            context_notes=_context_notes(both),
        )
    if missing:
        return ComparabilityResult(
            outcome="unknown",
            reasons=(),
            missing=tuple(sorted(missing)),
            context_notes=_context_notes(both),
        )
    if observed:
        quoted = sorted(f"{item.invocation_id}:{cond}" for item, cond in observed)
        return ComparabilityResult(
            outcome="conditional",
            reasons=tuple(f"interference observed: {item}" for item in quoted),
            missing=(),
            context_notes=_context_notes(both),
        )
    return ComparabilityResult(
        outcome="comparable", reasons=(), missing=(), context_notes=_context_notes(both)
    )


def _require_equal(
    both: list[InvAttributes], field: str, reasons: list[str], missing: list[str]
) -> None:
    """Always-known scalar fields: any inequality is incompatibility."""
    values = {getattr(item, field) for item in both}
    known = {value for value in values if value}
    if len(known) > 1:
        detail = "; ".join(f"{item.invocation_id}={getattr(item, field)!r}" for item in both)
        reasons.append(f"{field} differs: {detail}")
    for item in both:
        if not getattr(item, field):
            missing.append(f"{field}:{item.invocation_id}")


def _require_known_equal(
    both: list[InvAttributes], field: str, reasons: list[str], missing: list[str]
) -> None:
    """Marker-capable fields: unknown is missing, never equal or unequal."""
    for item in both:
        if getattr(item, field) is None:
            missing.append(f"{field}:{item.invocation_id}")
    known = {getattr(item, field) for item in both if getattr(item, field) is not None}
    if len(known) > 1:
        detail = "; ".join(
            f"{item.invocation_id}={getattr(item, field)!r}"
            for item in both
            if getattr(item, field) is not None
        )
        reasons.append(f"{field} differs: {detail}")


def _require_class(both: list[InvAttributes], reasons: list[str], missing: list[str]) -> None:
    """Machine class must be equal and known on every invocation."""
    for item in both:
        if item.machine_class is None:
            missing.append(f"machine_class:{item.invocation_id}")
    known = {item.machine_class for item in both if item.machine_class is not None}
    if len(known) > 1:
        detail = "; ".join(
            f"{item.invocation_id}={item.machine_class!r}"
            for item in both
            if item.machine_class is not None
        )
        reasons.append(f"machine_class differs: {detail}")


def _context_notes(both: list[InvAttributes]) -> tuple[str, ...]:
    """Count/envelope divergence notes (reported context, never decisive)."""
    notes: list[str] = []
    counts = {item.logical_processor_count for item in both}
    counts.discard(None)
    if len(counts) > 1:
        detail = "; ".join(f"{item.invocation_id}={item.logical_processor_count}" for item in both)
        notes.append(f"logical_processor_count differs (context): {detail}")
    if any(item.logical_processor_count is None for item in both):
        who = sorted(item.invocation_id for item in both if item.logical_processor_count is None)
        notes.append(f"logical_processor_count unknown (context): {', '.join(who)}")
    envelopes = {item.cgroup_envelope for item in both}
    envelopes.discard(None)
    if len(envelopes) > 1:
        notes.append("cgroup_envelope differs (context)")
    if any(item.cgroup_envelope is None for item in both):
        who = sorted(item.invocation_id for item in both if item.cgroup_envelope is None)
        notes.append(f"cgroup_envelope unknown (context): {', '.join(who)}")
    return tuple(sorted(notes))
