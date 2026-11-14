"""Shared builders for F3 schema/record tests (hand-built, deterministic)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from attest_core.f3_errors import F3Error

UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-9222-222222222222"
UUID_C = "33333333-3333-4333-a333-333333333333"
UUID_D = "44444444-4444-4444-b444-444444444444"
UUID_E = "550e8400-e29b-41d4-a716-446655440000"
DIGEST = "ab" * 32
SHA40 = "cd" * 20


def to_bytes(payload: Any) -> bytes:
    return (json.dumps(payload) + "\n").encode("utf-8")


def _envelope(kind: str, rid: str, iid: Any, emitter: str) -> dict[str, Any]:
    return {
        "record_id": rid,
        "record_version": 1,
        "record_kind": kind,
        "campaign_id": UUID_B,
        "invocation_id": iid,
        "emitted_by": emitter,
    }


def assert_fails(
    func: Callable[[Any], Any],
    arg: Any,
    *,
    rule: str,
    section: str,
    location: str,
    reason: str = "",
) -> None:
    """Assert exact error classification, not merely an exception."""
    with pytest.raises(F3Error) as caught:
        func(arg)
    err = caught.value
    assert err.rule == rule, err
    assert err.section == section, err
    assert err.location == location, err
    assert reason in err.reason, err


def valid_attempt(**overrides: Any) -> dict[str, Any]:
    """A fully valid attempt record object."""
    base: dict[str, Any] = {
        **_envelope("attempt", UUID_A, UUID_C, "parent"),
        "target": "repaired",
        "workload_class": "Medium",
        "workload_id": "auth-admin-001",
        "input_digest": DIGEST,
        "attempt": 2,
        "sample_class": "measured",
        "elapsed_s": "3.770075605",
        "outcome": "PASS",
        "censored": False,
        "profile": "hardened",
        "timeout_s": "60.000000000",
        "pid": 41822,
    }
    base.update(overrides)
    return base


def valid_total(**overrides: Any) -> dict[str, Any]:
    """A fully valid invocation_total record object."""
    base: dict[str, Any] = {
        **_envelope("invocation_total", UUID_D, UUID_C, "parent"),
        "target": "repaired",
        "workload_class": "Medium",
        "workload_id": "auth-admin-001",
        "input_digest": DIGEST,
        "sample_class": "measured",
        "elapsed_s": "13.987803432",
        "profile": "hardened",
        "verdict": "PASSED",
        "attempts_completed": 3,
        "attempts_total": 3,
        "attempt_outcomes": {"PASS": 3},
    }
    base.update(overrides)
    return base


def valid_env(**overrides: Any) -> dict[str, Any]:
    """A fully valid environment record object (mixed values/markers)."""
    base: dict[str, Any] = {
        **_envelope("environment", UUID_E, UUID_C, "parent"),
        "sample_class": "measured",
        "target": "repaired",
        "workload_class": "Medium",
        "workload_id": "auth-admin-001",
        "input_digest": DIGEST,
        "profile": "hardened",
        "command": "attest verify x",
        "git_revision": SHA40,
        "worktree": {"state": "clean"},
        "python": {"implementation": "CPython", "version": "3.11.0"},
        "uv": "uv 0.5.0",
        "os": "Linux",
        "distribution": "Ubuntu 24.04",
        "kernel": "6.8.0",
        "cpu_model": "AMD EPYC 7763",
        "logical_processor_count": 8,
        "memory_total_bytes": 17179869184,
        "memory_available_bytes": 8589934592,
        "cgroup_limits": {"limited": False},
        "container_runtime": {"bare_metal": True},
        "pyproject_digest": DIGEST,
        "uv_lock_digest": DIGEST,
        "runner_settings": {"unavailable": "runner-settings-undefined-in-v1"},
        "environment": {"PATH": "/usr/bin"},
        "interference": {"assessment": "unknown"},
    }
    base.update(overrides)
    return base


def _workload() -> dict[str, Any]:
    return {
        "workload_class": "Medium",
        "workload_id": "auth-admin-001",
        "input_digest": DIGEST,
        "input_manifest": {
            "manifest_version": 1,
            "entries": [
                {
                    "kind": "file",
                    "relpath": "inputs/auth-admin-001.yaml",
                    "size_bytes": 5231,
                    "sha256": "cd" * 32,
                }
            ],
        },
    }


def valid_campaign(**overrides: Any) -> dict[str, Any]:
    """A fully valid campaign record object."""
    base: dict[str, Any] = {
        **_envelope("campaign", UUID_A, None, "orchestrator"),
        "campaign_id": UUID_A,
        "observed_start_wallclock": "2026-11-13T10:00:00Z",
        "protocol": {
            "benchmark_category": "end-to-end",
            "required_successful": 5,
            "attempts_per_invocation": 3,
            "warmup_invocations": [1, 2],
            "targets": ["repaired"],
            "profile": "hardened",
        },
        "invocations": [
            {
                "run_sequence": 1,
                "invocation_id": UUID_C,
                "sample_class": "warmup",
                "target": "repaired",
                "workload": _workload(),
            }
        ],
    }
    base.update(overrides)
    return base


def valid_summary(**overrides: Any) -> dict[str, Any]:
    """A fully valid summary record object."""
    base: dict[str, Any] = {
        **_envelope("summary", UUID_D, None, "composer"),
        "target": "repaired",
        "workload_class": "Medium",
        "workload_id": "auth-admin-001",
        "input_digest": DIGEST,
        "series": "repaired/b1/latency",
        "statistic": "attempt",
        "observation_ids": [UUID_A, UUID_E],
        "excluded_warmups": [UUID_C],
        "n_total": 15,
        "n_successful": 15,
        "outcome_counts": {"PASS": 15},
        "min_s": "3.703622808",
        "median_s": "3.770075605",
        "max_s": "3.841365206",
        "range_s": "0.137742398",
        "context": {"campaign": "s3-m5-1-campaign-03", "revision": "975d511"},
    }
    base.update(overrides)
    return base
