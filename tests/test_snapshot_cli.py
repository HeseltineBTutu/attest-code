"""Snapshot and environment gates end to end: fresh-process refusal paths."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from apps.review import run_review


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


def _commit(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _verify(staged: Any, *extra: str, env: Any = None) -> subprocess.CompletedProcess[str]:
    proc: subprocess.CompletedProcess[str] = staged.run(
        "verify",
        str(staged.invariant),
        "--revision",
        "HEAD",
        "--repo",
        str(staged.root),
        "--approvals",
        str(staged.approvals),
        *extra,
        env=env,
    )
    return proc


def test_dirty_lockfile_is_refused(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (staged_repo.root / "uv.lock").write_text("pinned\n", encoding="utf-8")
    _commit(staged_repo.root, "add", "pyproject.toml", "uv.lock")
    _commit(staged_repo.root, "commit", "-qm", "manifests")
    (staged_repo.root / "uv.lock").write_text("tampered\n", encoding="utf-8")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "uncommitted" in proc.stderr


def test_ignored_executable_is_refused_end_to_end(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.src / "stray.pyc").write_bytes(b"fake bytecode")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "ignored executable" in proc.stderr


def test_pythonhome_is_refused(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, env={"PYTHONHOME": sys.base_prefix})
    assert proc.returncode == 3
    assert "PYTHONHOME" in proc.stderr


def test_pythonpath_escape_is_refused(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir(parents=True, exist_ok=True)
    proc = _verify(
        staged_repo,
        env={"PYTHONPATH": os.pathsep.join([str(staged_repo.src), str(outside)])},
    )
    assert proc.returncode == 3
    assert "escapes the repository tree" in proc.stderr


def test_clean_manifests_still_pass(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (staged_repo.root / "uv.lock").write_text("pinned\n", encoding="utf-8")
    _commit(staged_repo.root, "add", "pyproject.toml", "uv.lock")
    _commit(staged_repo.root, "commit", "-qm", "manifests")
    proc = _verify(staged_repo, "--target", "repaired")
    assert proc.returncode == 0, proc.stderr
    assert "verdict: PASSED" in proc.stdout
