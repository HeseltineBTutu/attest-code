"""F3 environment record validation (§7.3)."""

from __future__ import annotations

from typing import Any

import pytest
from f3_fixtures import DIGEST, assert_fails, valid_env

from attest_core.f3_records_env import validate_environment

MARK = {"unavailable": "probe-failed"}


def test_env_valid() -> None:
    record = validate_environment(valid_env())
    assert record.record_kind == "environment"
    assert record.logical_processor_count == 8
    assert record.runner_settings == {"unavailable": "runner-settings-undefined-in-v1"}


def test_env_markers_accepted() -> None:
    payload = valid_env(
        git_revision=dict(MARK),
        worktree=dict(MARK),
        python=dict(MARK),
        uv=dict(MARK),
        os=dict(MARK),
        distribution=dict(MARK),
        kernel=dict(MARK),
        cpu_model=dict(MARK),
        logical_processor_count=dict(MARK),
        memory_total_bytes=dict(MARK),
        memory_available_bytes=dict(MARK),
        cgroup_limits=dict(MARK),
        container_runtime=dict(MARK),
        pyproject_digest=dict(MARK),
        uv_lock_digest=dict(MARK),
    )
    record = validate_environment(payload)
    assert record.git_revision == MARK
    assert record.cgroup_limits == MARK


def test_env_missing_and_unknown() -> None:
    payload = valid_env()
    del payload["cpu_model"]
    assert_fails(
        validate_environment,
        payload,
        rule="V-B6",
        section="7.3",
        location="$.cpu_model",
        reason="missing",
    )
    assert_fails(
        validate_environment,
        {**valid_env(), "zzz": 1},
        rule="V-B6",
        section="7.3",
        location="$",
        reason="'zzz'",
    )


@pytest.mark.parametrize(
    ("key", "value", "location"),
    [
        ("invocation_id", None, "$.invocation_id"),
        ("emitted_by", "worker", "$.emitted_by"),
        ("sample_class", "cold", "$.sample_class"),
        ("target", "Bad Target", "$.target"),
        ("workload_class", "medium", "$.workload_class"),
        ("workload_id", "", "$.workload_id"),
        ("input_digest", "zz", "$.input_digest"),
        ("profile", "turbo", "$.profile"),
        ("command", "", "$.command"),
        ("command", None, "$.command"),
        ("git_revision", "xyz", "$.git_revision"),
        ("git_revision", {"unavailable": ""}, "$.git_revision"),
        ("worktree", {"state": "clean", "status": "x"}, "$.worktree"),
        ("worktree", {"state": "dirty"}, "$.worktree"),
        ("worktree", {"state": "dirty", "status": "  "}, "$.worktree.status"),
        ("worktree", {"state": "messy"}, "$.worktree"),
        ("python", {"implementation": "CPython"}, "$.python.version"),
        ("python", {"implementation": "", "version": "3"}, "$.python.implementation"),
        ("uv", "  ", "$.uv"),
        ("os", 7, "$.os"),
        ("distribution", "x" * 129, "$.distribution"),
        ("distribution", "héllo", "$.distribution"),
        ("kernel", None, "$.kernel"),
        ("cpu_model", "", "$.cpu_model"),
        ("logical_processor_count", 0, "$.logical_processor_count"),
        ("logical_processor_count", True, "$.logical_processor_count"),
        ("memory_total_bytes", -1, "$.memory_total_bytes"),
        ("memory_available_bytes", 0, "$.memory_available_bytes"),
        ("cgroup_limits", {"limited": False, "memory_max_bytes": 8}, "$.cgroup_limits"),
        ("cgroup_limits", {"limited": True}, "$.cgroup_limits"),
        ("cgroup_limits", {"limited": "yes"}, "$.cgroup_limits"),
        ("container_runtime", {"bare_metal": False}, "$.container_runtime"),
        ("container_runtime", {"runtime": "docker"}, "$.container_runtime.version"),
        ("container_runtime", {"runtime": "d", "version": "v", "x": 1}, "$.container_runtime"),
        ("pyproject_digest", DIGEST.upper(), "$.pyproject_digest"),
        ("uv_lock_digest", 5, "$.uv_lock_digest"),
        ("runner_settings", {"unavailable": "other"}, "$.runner_settings"),
        ("runner_settings", {}, "$.runner_settings"),
        ("environment", {"PATH": 7}, "$.environment.PATH"),
        ("environment", {"": "x"}, "$.environment"),
        ("environment", [], "$.environment"),
    ],
)
def test_env_rejects_bad_fields(key: str, value: Any, location: str) -> None:
    assert_fails(
        validate_environment,
        valid_env(**{key: value}),
        rule="V-B6",
        section="7.3",
        location=location,
    )


def test_env_interference_shapes() -> None:
    assert validate_environment(valid_env()).interference == {"assessment": "unknown"}
    none_declared = valid_env(interference={"assessment": "none-declared"})
    assert validate_environment(none_declared).interference == {"assessment": "none-declared"}
    observed = valid_env(
        interference={
            "assessment": "observed",
            "conditions": [
                {"category": "thermal-throttling", "detail": "cpu0 hot"},
                {"category": "other", "detail": "x"},
            ],
        }
    )
    assert len(validate_environment(observed).interference["conditions"]) == 2


@pytest.mark.parametrize(
    ("value", "location"),
    [
        ({"assessment": "maybe"}, "$.interference"),
        ({"assessment": "unknown", "extra": 1}, "$.interference"),
        ({"assessment": "observed", "conditions": []}, "$.interference"),
        ({"assessment": "observed"}, "$.interference"),
        (
            {"assessment": "observed", "conditions": [{"category": "aliens", "detail": "x"}]},
            "$.interference.conditions[0].category",
        ),
        (
            {"assessment": "observed", "conditions": [{"category": "other", "detail": ""}]},
            "$.interference.conditions[0].detail",
        ),
        (
            {"assessment": "observed", "conditions": [{"category": "other"}]},
            "$.interference.conditions[0].detail",
        ),
        (
            {
                "assessment": "observed",
                "conditions": [{"category": "other", "detail": "x", "z": 1}],
            },
            "$.interference.conditions[0]",
        ),
        ({"assessment": "observed", "conditions": ["x"]}, "$.interference.conditions[0]"),
        ({"assessment": "none-declared", "conditions": []}, "$.interference"),
        ("unknown", "$.interference"),
    ],
)
def test_env_interference_rejects(value: Any, location: str) -> None:
    assert_fails(
        validate_environment,
        valid_env(interference=value),
        rule="V-B6",
        section="7.3",
        location=location,
    )


def test_env_real_shapes() -> None:
    payload = valid_env(
        worktree={"state": "dirty", "status": " M src/x.py"},
        cgroup_limits={"limited": True, "memory_max_bytes": 1073741824},
        container_runtime={"runtime": "docker", "version": "24.0"},
        environment={"PATH": "/x", "EMPTY": ""},
    )
    record = validate_environment(payload)
    assert record.worktree["state"] == "dirty"
    assert record.cgroup_limits["memory_max_bytes"] == 1073741824
    assert record.container_runtime["runtime"] == "docker"
    assert record.environment["EMPTY"] == ""
