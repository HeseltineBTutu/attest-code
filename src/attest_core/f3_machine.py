"""F3 machine-class consistency within a series (W4, §6.3).

Class is (normalized_cpu_model, memory_total_bytes); either
field unavailable yields UNKNOWN for that invocation. Known
mismatches are INVALID; UNKNOWN, envelope divergence, and
cpu-count notes are mandatory diagnostics that never fail.
Invocations without exactly one environment record are
skipped: P3 owns their completeness finding. Available
memory, container runtime, and distribution have no R5
comparison rule and are never compared here.
"""

from __future__ import annotations

from typing import Any

from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records_env import EnvRecord
from attest_core.f3_series import Diagnostic, Series, SeriesMember


def normalize_cpu(value: str) -> str:
    """Strip ends and collapse inner whitespace runs to single spaces."""
    return " ".join(value.split())


def machine_class(env: EnvRecord) -> tuple[str, int] | None:
    """The W4 class tuple, or None when a defining field is unavailable."""
    cpu = env.cpu_model
    memory = env.memory_total_bytes
    if not isinstance(cpu, str) or not isinstance(memory, int):
        return None
    return (normalize_cpu(cpu), memory)


def missing_class_fields(env: EnvRecord) -> list[str]:
    """Which class-defining fields are unavailable markers."""
    missing = []
    if not isinstance(env.cpu_model, str):
        missing.append("cpu_model")
    if not isinstance(env.memory_total_bytes, int):
        missing.append("memory_total_bytes")
    return missing


def envelope(env: EnvRecord) -> dict[str, Any] | None:
    """The cgroup envelope, or None when unavailable."""
    limits = env.cgroup_limits
    if "unavailable" in limits:
        return None
    return dict(limits)


def check_series_class(
    series: Series, envs_by_inv: dict[str, list[tuple[str, EnvRecord]]]
) -> tuple[tuple[Finding, ...], tuple[Diagnostic, ...]]:
    """W4 for one series: class equality plus envelope/count diagnostics."""
    known: list[tuple[SeriesMember, str, EnvRecord, tuple[str, int]]] = []
    unknowns: list[tuple[SeriesMember, str, EnvRecord]] = []
    for member in series.members:
        held = envs_by_inv.get(member.invocation_id, [])
        if len(held) != 1:
            continue
        label, env = held[0]
        got = machine_class(env)
        if got is None:
            unknowns.append((member, label, env))
        else:
            known.append((member, label, env, got))
    findings = _class_findings(series, known)
    notes: list[Diagnostic] = []
    for member, label, env in unknowns:
        fields = ", ".join(missing_class_fields(env))
        notes.append(
            Diagnostic(
                rule="W4",
                location=label,
                reason=(
                    f"machine-class unknown for invocation "
                    f"{member.invocation_id} (missing: {fields}); "
                    "comparability involving it is unknown"
                ),
            )
        )
    notes.extend(_envelope_notes(series, known, unknowns))
    if len({got for _, _, _, got in known}) <= 1:
        notes.extend(_count_notes(series, known, unknowns))
    return tuple(findings), tuple(notes)


def _class_findings(
    series: Series, known: list[tuple[SeriesMember, str, EnvRecord, tuple[str, int]]]
) -> list[Finding]:
    """INVALID when known classes disagree, naming fields and invocations."""
    by_class: dict[tuple[str, int], list[tuple[SeriesMember, str]]] = {}
    for member, label, _, got in known:
        by_class.setdefault(got, []).append((member, label))
    if len(by_class) <= 1:
        return []
    ordered = sorted(by_class, key=repr)
    first, second = ordered[0], ordered[1]
    fields = []
    if first[0] != second[0]:
        fields.append("cpu_model")
    if first[1] != second[1]:
        fields.append("memory_total_bytes")
    detail = "; ".join(
        f"{got!r} at {', '.join(m.invocation_id for m, _ in holders)}"
        for got, holders in sorted(by_class.items(), key=lambda pair: repr(pair[0]))
    )
    return [
        Finding(
            severity="INVALID",
            rule="W4",
            location=by_class[second][0][1],
            reason=(
                f"machine-class mismatch in series {series.ordinal} "
                f"(differing: {', '.join(fields)}): {detail}"
            ),
        )
    ]


def _envelope_notes(
    series: Series,
    known: list[tuple[SeriesMember, str, EnvRecord, tuple[str, int]]],
    unknowns: list[tuple[SeriesMember, str, EnvRecord]],
) -> list[Diagnostic]:
    """Effective-envelope divergence/unknown notes (never class equality)."""
    notes: list[Diagnostic] = []
    held: list[tuple[str, str, dict[str, Any] | None]] = [
        (label, member.invocation_id, envelope(env)) for member, label, env, _ in known
    ]
    held.extend((label, member.invocation_id, envelope(env)) for member, label, env in unknowns)
    missing = sorted(inv for _, inv, value in held if value is None)
    if missing:
        where = next(label for label, _, value in held if value is None)
        notes.append(
            Diagnostic(
                rule="W4",
                location=where,
                reason=(
                    f"cgroup envelope unknown for {', '.join(missing)} (series {series.ordinal})"
                ),
            )
        )
    present = [(label, value) for label, _, value in held if value is not None]
    baseline = present[0][1] if present else None
    differ = next((label for label, value in present if value != baseline), None)
    if differ is not None:
        notes.append(
            Diagnostic(
                rule="W4",
                location=differ,
                reason=(
                    "cgroup envelope differs within series "
                    f"{series.ordinal} (unequal effective envelope)"
                ),
            )
        )
    return notes


def _count_notes(
    series: Series,
    known: list[tuple[SeriesMember, str, EnvRecord, tuple[str, int]]],
    unknowns: list[tuple[SeriesMember, str, EnvRecord]],
) -> list[Diagnostic]:
    """Logical-processor-count mismatch notes (recorded, never class-defining)."""
    counts: dict[str, int] = {}
    labels: dict[str, str] = {}
    for member, label, env, _ in known:
        if isinstance(env.logical_processor_count, int):
            counts[member.invocation_id] = env.logical_processor_count
            labels[member.invocation_id] = label
    for member, label, env in unknowns:
        if isinstance(env.logical_processor_count, int):
            counts[member.invocation_id] = env.logical_processor_count
            labels[member.invocation_id] = label
    if len(set(counts.values())) <= 1:
        return []
    first = sorted(set(counts.values()))[0]
    other = next(inv for inv in sorted(counts) if counts[inv] != first)
    detail = ", ".join(f"{inv}={counts[inv]}" for inv in sorted(counts))
    return [
        Diagnostic(
            rule="W4",
            location=labels[other],
            reason=(
                "logical_processor_count differs within series "
                f"{series.ordinal} (same class): {detail}"
            ),
        )
    ]
