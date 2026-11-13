"""Benchmark environment record: assembly, validation, allowlist."""

import os
from pathlib import Path
from typing import Any

import pytest

from attest_core import bench_env, bench_env_probes
from attest_core.git import GitError

_KEYS = (
    "profile",
    "command",
    "git_revision",
    "worktree",
    "python",
    "uv",
    "os",
    "kernel",
    "cpu_model",
    "memory_total_bytes",
    "pyproject_digest",
    "uv_lock_digest",
    "environment",
)
_REV = "f" * 40


@pytest.fixture()
def isolated_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    env: dict[str, str] = {}
    monkeypatch.setattr(os, "environ", env)
    return env


@pytest.fixture()
def probed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(bench_env_probes, "resolve_base", lambda: tmp_path)
    monkeypatch.setattr(bench_env_probes, "collect_revision", lambda base: _REV)
    monkeypatch.setattr(bench_env_probes, "collect_worktree", lambda base: {"state": "clean"})
    monkeypatch.setattr(
        bench_env_probes, "collect_lock_digest", lambda base, name: f"digest-{name}"
    )
    monkeypatch.setattr(
        bench_env_probes,
        "collect_python",
        lambda: {"implementation": "CPython", "version": "3.11.9"},
    )
    monkeypatch.setattr(bench_env_probes, "collect_uv", lambda: "uv 0.5.1")
    monkeypatch.setattr(bench_env_probes, "collect_os", lambda: "Linux")
    monkeypatch.setattr(bench_env_probes, "collect_kernel", lambda: "6.8.0")
    monkeypatch.setattr(bench_env_probes, "collect_cpu_model", lambda: "Fake CPU")
    monkeypatch.setattr(bench_env_probes, "collect_memory_total_bytes", lambda: 2048)
    return tmp_path


def test_successful_collection(probed: Path, isolated_env: dict[str, str]) -> None:
    isolated_env["OMP_NUM_THREADS"] = "4"
    record = bench_env.collect_environment(profile="hardened", command="uv run bench")
    assert list(record) == list(_KEYS)
    assert record["profile"] == "hardened"
    assert record["command"] == "uv run bench"
    assert record["git_revision"] == _REV
    assert record["worktree"] == {"state": "clean"}
    assert record["python"] == {"implementation": "CPython", "version": "3.11.9"}
    assert record["uv"] == "uv 0.5.1"
    assert record["os"] == "Linux"
    assert record["kernel"] == "6.8.0"
    assert record["cpu_model"] == "Fake CPU"
    assert record["memory_total_bytes"] == 2048
    assert record["pyproject_digest"] == "digest-pyproject.toml"
    assert record["uv_lock_digest"] == "digest-uv.lock"
    assert record["environment"] == {"OMP_NUM_THREADS": "4"}


def test_git_failure_marks_git_fields_only(
    probed: Path, isolated_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom() -> Path:
        raise GitError("not a git work tree")

    monkeypatch.setattr(bench_env_probes, "resolve_base", _boom)
    record = bench_env.collect_environment(profile="standard", command="x")
    assert record["git_revision"] == {"unavailable": "not a git work tree"}
    assert record["worktree"] == {"unavailable": "not a git work tree"}
    assert record["cpu_model"] == "Fake CPU"
    assert record["pyproject_digest"] == "digest-pyproject.toml"


def test_head_failure_keeps_worktree(
    probed: Path, isolated_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        bench_env_probes, "collect_revision", lambda base: {"unavailable": "no head"}
    )
    record = bench_env.collect_environment(profile="standard", command="x")
    assert record["git_revision"] == {"unavailable": "no head"}
    assert record["worktree"] == {"state": "clean"}


def test_allowlist_blocks_secrets(probed: Path, isolated_env: dict[str, str]) -> None:
    isolated_env.update(
        {
            "PATH": "/bin",
            "OMP_NUM_THREADS": "2",
            "SECRET_TOKEN": "s3cr3t",
            "AWS_SECRET_ACCESS_KEY": "key",
            "DATABASE_PASSWORD": "pw",
            "RANDOM_VAR": "zzz",
        }
    )
    record = bench_env.collect_environment(profile="standard", command="x")
    assert list(record["environment"]) == ["OMP_NUM_THREADS", "PATH"]
    blob = repr(record)
    assert "s3cr3t" not in blob and "zzz" not in blob and "RANDOM_VAR" not in blob


def test_empty_environment_is_empty_dict(probed: Path, isolated_env: dict[str, str]) -> None:
    record = bench_env.collect_environment(profile="standard", command="x")
    assert record["environment"] == {}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://user:pass@proxy:8080", "http://***@proxy:8080"),
        ("https://proxy:8080", "https://proxy:8080"),
        ("user@host", "***@host"),
    ],
)
def test_proxy_userinfo_redacted(
    probed: Path, isolated_env: dict[str, str], raw: str, expected: str
) -> None:
    isolated_env["http_proxy"] = raw
    record = bench_env.collect_environment(profile="standard", command="x")
    assert record["environment"] == {"http_proxy": expected}


@pytest.mark.parametrize("profile", ["turbo", "", "HARDENED", None, 123])
def test_invalid_profile_rejected(profile: Any) -> None:
    with pytest.raises((TypeError, ValueError)):
        bench_env.collect_environment(profile=profile, command="x")


@pytest.mark.parametrize("command", ["", None, ["uv", "run"]])
def test_invalid_command_rejected(command: Any) -> None:
    with pytest.raises((TypeError, ValueError)):
        bench_env.collect_environment(profile="standard", command=command)


def test_failed_probes_stay_markers(
    probed: Path, isolated_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def _marker(*args: Any) -> dict[str, str]:
        return {"unavailable": "probe failed"}

    monkeypatch.setattr(bench_env_probes, "collect_revision", _marker)
    monkeypatch.setattr(bench_env_probes, "collect_worktree", _marker)
    monkeypatch.setattr(bench_env_probes, "collect_lock_digest", _marker)
    monkeypatch.setattr(bench_env_probes, "collect_python", _marker)
    monkeypatch.setattr(bench_env_probes, "collect_uv", _marker)
    monkeypatch.setattr(bench_env_probes, "collect_os", _marker)
    monkeypatch.setattr(bench_env_probes, "collect_kernel", _marker)
    monkeypatch.setattr(bench_env_probes, "collect_cpu_model", _marker)
    monkeypatch.setattr(bench_env_probes, "collect_memory_total_bytes", _marker)
    record = bench_env.collect_environment(profile="standard", command="x")
    for key in (
        "git_revision",
        "worktree",
        "python",
        "uv",
        "os",
        "kernel",
        "cpu_model",
        "memory_total_bytes",
        "pyproject_digest",
        "uv_lock_digest",
    ):
        assert record[key] == {"unavailable": "probe failed"}
    assert record["profile"] == "standard" and record["command"] == "x"


def test_unexpected_probe_error_propagates(
    probed: Path, isolated_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def _bug() -> str:
        raise RuntimeError("probe defect")

    monkeypatch.setattr(bench_env_probes, "collect_uv", _bug)
    with pytest.raises(RuntimeError):
        bench_env.collect_environment(profile="standard", command="x")
