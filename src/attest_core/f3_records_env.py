"""F3 environment records: strict validation against §7.3."""

from __future__ import annotations

import dataclasses
import functools
from typing import Any

from attest_core import f3_env_shapes as shapes
from attest_core import f3_fields as ff
from attest_core import f3_schema as sc

_ENV_KEYS = frozenset(
    {
        "record_id",
        "record_version",
        "record_kind",
        "campaign_id",
        "invocation_id",
        "emitted_by",
        "sample_class",
        "target",
        "workload_class",
        "workload_id",
        "input_digest",
        "profile",
        "command",
        "git_revision",
        "worktree",
        "python",
        "uv",
        "os",
        "distribution",
        "kernel",
        "cpu_model",
        "logical_processor_count",
        "memory_total_bytes",
        "memory_available_bytes",
        "cgroup_limits",
        "container_runtime",
        "pyproject_digest",
        "uv_lock_digest",
        "runner_settings",
        "environment",
        "interference",
    }
)
_ENV_KIND: sc.Check = functools.partial(
    sc.enum, allowed=frozenset({"environment"}), name="record_kind"
)


def _nonempty(value: Any, section: str, location: str) -> str:
    """Non-empty string (mirrors the command-arg check exactly)."""
    if not isinstance(value, str) or not value:
        sc.fail(section, location, "must be a non-empty string")
    return value


_os = sc.value_or_marker(sc.nonblank_str)
_kernel = sc.value_or_marker(sc.nonblank_str)
_cpu_model = sc.value_or_marker(sc.nonblank_str)
_uv = sc.value_or_marker(sc.nonblank_str)
_git_revision = sc.value_or_marker(ff.git_sha)
_pyproject_digest = sc.value_or_marker(ff.digest64)
_uv_lock_digest = sc.value_or_marker(ff.digest64)
_memory_total = sc.value_or_marker(sc.positive_int)
_memory_available = sc.value_or_marker(sc.positive_int)
_cpu_count = sc.value_or_marker(sc.positive_int)
_distribution = sc.value_or_marker(functools.partial(sc.ascii_bounded, max_len=128))


@dataclasses.dataclass(frozen=True)
class EnvRecord:
    """One validated environment record (§7.3)."""

    record_id: str
    record_version: int
    record_kind: str
    campaign_id: str
    invocation_id: str
    emitted_by: str
    sample_class: str
    target: str
    workload_class: str
    workload_id: str
    input_digest: str
    profile: str
    command: str
    git_revision: str | dict[str, str]
    worktree: dict[str, Any]
    python: dict[str, Any]
    uv: str | dict[str, str]
    os: str | dict[str, str]
    distribution: str | dict[str, str]
    kernel: str | dict[str, str]
    cpu_model: str | dict[str, str]
    logical_processor_count: int | dict[str, str]
    memory_total_bytes: int | dict[str, str]
    memory_available_bytes: int | dict[str, str]
    cgroup_limits: dict[str, Any]
    container_runtime: dict[str, Any]
    pyproject_digest: str | dict[str, str]
    uv_lock_digest: str | dict[str, str]
    runner_settings: dict[str, str]
    environment: dict[str, str]
    interference: dict[str, Any]


def validate_environment(value: Any, section: str = "7.3", location: str = "$") -> EnvRecord:
    """Validate an environment record object (§7.3)."""

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _ENV_KEYS, section, location)
    return EnvRecord(
        record_id=one("record_id", ff.uuid4),
        record_version=one("record_version", ff.record_version),
        record_kind=one("record_kind", _ENV_KIND),
        campaign_id=one("campaign_id", ff.uuid4),
        invocation_id=one("invocation_id", ff.uuid4),
        emitted_by=one("emitted_by", ff.emitter),
        sample_class=one("sample_class", ff.sample_class),
        target=one("target", ff.target),
        workload_class=one("workload_class", ff.workload_class),
        workload_id=one("workload_id", ff.workload_id),
        input_digest=one("input_digest", ff.digest64),
        profile=one("profile", ff.profile),
        command=one("command", _nonempty),
        git_revision=one("git_revision", _git_revision),
        worktree=one("worktree", shapes.worktree),
        python=one("python", shapes.python_info),
        uv=one("uv", _uv),
        os=one("os", _os),
        distribution=one("distribution", _distribution),
        kernel=one("kernel", _kernel),
        cpu_model=one("cpu_model", _cpu_model),
        logical_processor_count=one("logical_processor_count", _cpu_count),
        memory_total_bytes=one("memory_total_bytes", _memory_total),
        memory_available_bytes=one("memory_available_bytes", _memory_available),
        cgroup_limits=one("cgroup_limits", shapes.cgroup_limits),
        container_runtime=one("container_runtime", shapes.container_runtime),
        pyproject_digest=one("pyproject_digest", _pyproject_digest),
        uv_lock_digest=one("uv_lock_digest", _uv_lock_digest),
        runner_settings=one("runner_settings", shapes.runner_settings),
        environment=one("environment", shapes.env_map),
        interference=one("interference", shapes.interference),
    )
