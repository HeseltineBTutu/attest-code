"""F3 per-invocation comparability attribute derivation (§10.7).

Derives one invocation's attribute block from bound attempt
and environment records. Gaps (missing env, split profiles,
unavailable markers) surface as None/unknown — never as
invented values and never as equality. git_revision is
reported for provenance and never equality-gated by the
pairwise function.
"""

from __future__ import annotations

import dataclasses

from attest_core.f3_records import AttemptRecord
from attest_core.f3_records_env import EnvRecord


@dataclasses.dataclass(frozen=True)
class InvAttributes:
    """Per-invocation comparability inputs derived from bound records."""

    invocation_id: str
    workload_id: str
    input_digest: str
    profile: str | None
    timeout_s: str | None
    pyproject_digest: str | None
    uv_lock_digest: str | None
    git_revision: str | None
    machine_class: tuple[str, int] | None
    interference: str
    conditions: tuple[str, ...]
    logical_processor_count: int | None
    cgroup_envelope: str | None


def derive_attributes(
    invocation_id: str,
    attempts: list[AttemptRecord],
    env: EnvRecord | None,
) -> InvAttributes:
    """Derive one invocation's attribute block (None/unknown on gaps)."""
    profiles = {record.profile for record in attempts}
    timeouts = {record.timeout_s for record in attempts}
    profile = next(iter(profiles)) if len(profiles) == 1 else None
    timeout = next(iter(timeouts)) if len(timeouts) == 1 else None
    first = attempts[0] if attempts else None
    return InvAttributes(
        invocation_id=invocation_id,
        workload_id=first.workload_id if first else "",
        input_digest=first.input_digest if first else "",
        profile=profile,
        timeout_s=timeout,
        pyproject_digest=_known_str(env, "pyproject_digest"),
        uv_lock_digest=_known_str(env, "uv_lock_digest"),
        git_revision=_known_str(env, "git_revision"),
        machine_class=_class_of(env),
        interference=_interference(env)[0],
        conditions=_interference(env)[1],
        logical_processor_count=_known_int(env, "logical_processor_count"),
        cgroup_envelope=_envelope(env),
    )


def _known_str(env: EnvRecord | None, field: str) -> str | None:
    """A string field's value, or None when missing/marked/unavailable."""
    if env is None:
        return None
    value = getattr(env, field)
    return value if isinstance(value, str) else None


def _known_int(env: EnvRecord | None, field: str) -> int | None:
    """An integer field's value, or None when missing/marked/unavailable."""
    if env is None:
        return None
    value = getattr(env, field)
    return value if isinstance(value, int) else None


def _class_of(env: EnvRecord | None) -> tuple[str, int] | None:
    """Normalized (cpu, memory) class, or None when either is unavailable."""
    if env is None or not isinstance(env.cpu_model, str):
        return None
    if not isinstance(env.memory_total_bytes, int):
        return None
    return (" ".join(env.cpu_model.split()), env.memory_total_bytes)


def _interference(env: EnvRecord | None) -> tuple[str, tuple[str, ...]]:
    """(status, condition categories); missing env reads as unknown."""
    if env is None:
        return ("unknown", ())
    data = env.interference
    status = str(data.get("assessment", "unknown"))
    if status != "observed":
        return (status, ())
    conditions = tuple(str(item.get("category", "?")) for item in data.get("conditions", []))
    return (status, conditions)


def _envelope(env: EnvRecord | None) -> str | None:
    """Canonical envelope rendering, or None when unavailable."""
    if env is None or "unavailable" in env.cgroup_limits:
        return None
    limits = env.cgroup_limits
    if limits.get("limited") is True:
        return f"limited:{limits.get('memory_max_bytes')}"
    return "unlimited"
