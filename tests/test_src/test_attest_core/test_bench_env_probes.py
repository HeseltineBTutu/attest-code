"""Benchmark environment probes: collectors, markers, failure modes."""

import hashlib
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from attest_core import bench_env_probes as probes
from attest_core.git import GitError

_REV = "f" * 40
_CPUINFO = "processor\t: 0\nmodel name\t: Fake CPU 9000\n"
_MEMINFO = "MemTotal:        2048 kB\nMemFree:         1024 kB\n"
_UV_OK = subprocess.CompletedProcess(args=[], returncode=0, stdout="uv 0.5.1\n", stderr="")


def _raise_git_error(*args: Any) -> Any:
    raise GitError("git unavailable")


@pytest.fixture()
def base(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_bytes(b"[project]\n")
    (tmp_path / "uv.lock").write_bytes(b"lock\n")
    return tmp_path


def test_resolve_base_returns_top_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "repo_root", lambda repo: Path("/repo"))
    assert probes.resolve_base() == Path("/repo")


def test_resolve_base_propagates_git_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "repo_root", _raise_git_error)
    with pytest.raises(GitError):
        probes.resolve_base()


def test_collect_revision(base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "resolve_revision", lambda repo, rev: _REV)
    assert probes.collect_revision(base) == _REV
    monkeypatch.setattr(probes, "resolve_revision", _raise_git_error)
    assert probes.collect_revision(base) == {"unavailable": "git unavailable"}


@pytest.mark.parametrize(
    ("status", "expected"),
    [("", {"state": "clean"}), (" M a.py\n", {"state": "dirty", "status": " M a.py\n"})],
)
def test_collect_worktree_states(
    base: Path, monkeypatch: pytest.MonkeyPatch, status: str, expected: dict[str, str]
) -> None:
    monkeypatch.setattr(probes, "relevant_status", lambda repo: status)
    assert probes.collect_worktree(base) == expected


def test_collect_worktree_long_status_clipped(base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "relevant_status", lambda repo: " M f\n" * 500)
    found = probes.collect_worktree(base)
    assert found["state"] == "dirty" and found["status"].endswith("...(truncated)")


def test_collect_worktree_git_error(base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "relevant_status", _raise_git_error)
    assert probes.collect_worktree(base) == {"unavailable": "git unavailable"}


def test_collect_lock_digest(base: Path) -> None:
    assert (
        probes.collect_lock_digest(base, "pyproject.toml")
        == hashlib.sha256(b"[project]\n").hexdigest()
    )


def test_collect_lock_digest_absent(base: Path) -> None:
    assert probes.collect_lock_digest(base, "missing.txt") == {"unavailable": "absent:missing.txt"}


def test_collect_lock_digest_unreadable(base: Path) -> None:
    (base / "pyproject.toml").unlink()
    (base / "pyproject.toml").mkdir()
    marker = cast("dict[str, str]", probes.collect_lock_digest(base, "pyproject.toml"))
    reason = marker["unavailable"]
    assert reason.startswith("unreadable:pyproject.toml:") and len(reason) <= 80


def test_collect_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "python_implementation", lambda: "CPython")
    monkeypatch.setattr(platform, "python_version", lambda: "3.11.9")
    assert probes.collect_python() == {"implementation": "CPython", "version": "3.11.9"}


@pytest.mark.parametrize("impl,version", [("", "3.11.9"), ("CPython", ""), ("", "")])
def test_collect_python_blank(monkeypatch: pytest.MonkeyPatch, impl: str, version: str) -> None:
    monkeypatch.setattr(platform, "python_implementation", lambda: impl)
    monkeypatch.setattr(platform, "python_version", lambda: version)
    assert probes.collect_python() == {"unavailable": "empty-implementation-or-version"}


def test_collect_uv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: "/bin/uv")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _UV_OK)
    assert probes.collect_uv() == "uv 0.5.1"


def test_collect_uv_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert probes.collect_uv() == {"unavailable": "uv-not-on-path"}
    monkeypatch.setattr(shutil, "which", lambda name: "/bin/uv")
    failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="x")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: failed)
    assert probes.collect_uv() == {"unavailable": "uv-exit-1"}

    def _timeout(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="uv", timeout=10)

    monkeypatch.setattr(subprocess, "run", _timeout)
    marker = cast("dict[str, str]", probes.collect_uv())
    assert "uv-execution-failed" in marker["unavailable"]


def test_collect_os_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "release", lambda: "6.8.0")
    assert probes.collect_os() == "Linux"
    assert probes.collect_kernel() == "6.8.0"
    monkeypatch.setattr(platform, "system", lambda: "")
    monkeypatch.setattr(platform, "release", lambda: "")
    assert probes.collect_os() == {"unavailable": "unknown-os"}
    assert probes.collect_kernel() == {"unavailable": "unknown-kernel"}


@pytest.mark.parametrize(
    ("content", "expected"),
    [("model name\t: X\n", "X"), ("processor: 0\n", {"unavailable": "model-name-not-found"})],
)
def test_collect_cpu_model(monkeypatch: pytest.MonkeyPatch, content: str, expected: Any) -> None:
    monkeypatch.setattr(probes, "_read_text_file", lambda path: content)
    assert probes.collect_cpu_model() == expected


def test_collect_cpu_model_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _read(path: str) -> str:
        raise OSError("denied")

    monkeypatch.setattr(probes, "_read_text_file", _read)
    marker = cast("dict[str, str]", probes.collect_cpu_model())
    assert marker["unavailable"].startswith("cpuinfo-unreadable:")


def test_collect_memory_from_meminfo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probes, "_read_text_file", lambda path: _MEMINFO)
    assert probes.collect_memory_total_bytes() == 2048 * 1024


@pytest.mark.parametrize("meminfo", ["raise", "MemTotal: nope kB\n", "MemFree: 1 kB\n"])
def test_collect_memory_sysconf_fallback(monkeypatch: pytest.MonkeyPatch, meminfo: str) -> None:
    def _read(path: str) -> str:
        if meminfo == "raise":
            raise OSError("no proc")
        return meminfo

    sizes = {"SC_PAGE_SIZE": 4096, "SC_PHYS_PAGES": 512}
    monkeypatch.setattr(probes, "_read_text_file", _read)
    monkeypatch.setattr(os, "sysconf", lambda name: sizes[name])
    assert probes.collect_memory_total_bytes() == 4096 * 512


def test_collect_memory_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def _read(path: str) -> str:
        raise OSError("no proc")

    def _conf(name: str) -> int:
        raise ValueError("unknown name")

    monkeypatch.setattr(probes, "_read_text_file", _read)
    monkeypatch.setattr(os, "sysconf", _conf)
    marker = cast("dict[str, str]", probes.collect_memory_total_bytes())
    assert marker["unavailable"].startswith("memory-unknown:")


def test_unexpected_errors_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    def _bug(path: str) -> str:
        raise RuntimeError("reader defect")

    monkeypatch.setattr(probes, "_read_text_file", _bug)
    with pytest.raises(RuntimeError):
        probes.collect_cpu_model()

    def _platform_bug() -> str:
        raise RuntimeError("platform defect")

    monkeypatch.setattr(platform, "python_version", _platform_bug)
    with pytest.raises(RuntimeError):
        probes.collect_python()
