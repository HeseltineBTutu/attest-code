"""Git adapter: revision resolution, snapshot policy, fingerprints."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from attest_core.git import (
    GitError,
    check_snapshot,
    fingerprint,
    relevant_status,
    resolve_revision,
)

_FULL_OID = re.compile(r"^[0-9a-f]{40}$")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _commit(repo: Path, name: str, content: str) -> None:
    target = repo / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-qm", f"add {name}")


def test_resolve_returns_full_oid(git_repo: Path) -> None:
    oid = resolve_revision(git_repo, "HEAD")
    assert _FULL_OID.match(oid)
    assert resolve_revision(git_repo, oid[:7]) == oid


def test_unknown_revision_raises(git_repo: Path) -> None:
    with pytest.raises(GitError):
        resolve_revision(git_repo, "no-such-rev")
    with pytest.raises(GitError):
        resolve_revision(git_repo, "  ")


def test_clean_tree_passes_snapshot(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    snapshot = check_snapshot(git_repo, "HEAD")
    assert snapshot.clean
    assert _FULL_OID.match(snapshot.revision)


def test_head_mismatch_is_refused(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    first = resolve_revision(git_repo, "HEAD")
    _commit(git_repo, "src/app.py", "x = 2\n")
    with pytest.raises(GitError, match="check out"):
        check_snapshot(git_repo, first)


def test_dirty_tracked_file_is_refused(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    (git_repo / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
    assert relevant_status(git_repo).strip()
    with pytest.raises(GitError, match="uncommitted"):
        check_snapshot(git_repo, "HEAD")


def test_untracked_file_under_relevant_paths_is_refused(git_repo: Path) -> None:
    (git_repo / "tests").mkdir()
    (git_repo / "tests" / "scratch.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(GitError, match="uncommitted"):
        check_snapshot(git_repo, "HEAD")


def test_untracked_file_elsewhere_is_allowed(git_repo: Path) -> None:
    (git_repo / "notes.txt").write_text("scratch\n", encoding="utf-8")
    assert check_snapshot(git_repo, "HEAD").clean


def test_fingerprint_detects_changes(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    before = fingerprint(git_repo)
    assert fingerprint(git_repo) == before
    (git_repo / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
    assert fingerprint(git_repo) != before


def test_non_repository_raises(tmp_path: Path) -> None:
    with pytest.raises(GitError):
        resolve_revision(tmp_path, "HEAD")
