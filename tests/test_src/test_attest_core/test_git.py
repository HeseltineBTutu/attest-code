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
    ignored_executable_files,
    relevant_status,
    repo_root,
    resolve_revision,
    suspicious_index_entries,
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


def test_repo_root_returns_canonical_top_level(git_repo: Path) -> None:
    assert repo_root(git_repo) == git_repo.resolve()
    subdir = git_repo / "src"
    subdir.mkdir()
    assert repo_root(subdir) == git_repo.resolve()


def test_non_repository_raises(tmp_path: Path) -> None:
    with pytest.raises(GitError):
        resolve_revision(tmp_path, "HEAD")


@pytest.mark.parametrize("name", ["pyproject.toml", "uv.lock", ".gitignore", ".gitattributes"])
def test_dirty_config_file_is_refused(git_repo: Path, name: str) -> None:
    _commit(git_repo, name, "pinned = true\n")
    (git_repo / name).write_text("pinned = false\n", encoding="utf-8")
    with pytest.raises(GitError, match="uncommitted"):
        check_snapshot(git_repo, "HEAD")


def test_untracked_config_file_is_refused(git_repo: Path) -> None:
    (git_repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    with pytest.raises(GitError, match="uncommitted"):
        check_snapshot(git_repo, "HEAD")


def test_missing_config_files_pass(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    assert check_snapshot(git_repo, "HEAD").clean


def _ignore(git_repo: Path, rule: str) -> None:
    (git_repo / ".gitignore").write_text(rule, encoding="utf-8")
    _git(git_repo, "add", ".gitignore")
    _git(git_repo, "commit", "-qm", "ignore rules")


def test_ignored_executable_under_src_is_refused(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _ignore(git_repo, "*.pyc\n")
    (git_repo / "src" / "shadow.pyc").write_bytes(b"fake bytecode")
    assert ignored_executable_files(git_repo) == ["src/shadow.pyc"]
    with pytest.raises(GitError, match="ignored executable"):
        check_snapshot(git_repo, "HEAD")


def test_ignored_executable_in_nested_dir_is_refused(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _ignore(git_repo, "vendor/\n")
    nested = git_repo / "src" / "vendor"
    nested.mkdir()
    (nested / "evil.py").write_text("evil = 1\n", encoding="utf-8")
    assert ignored_executable_files(git_repo) == ["src/vendor/evil.py"]
    with pytest.raises(GitError, match="ignored executable"):
        check_snapshot(git_repo, "HEAD")


def test_ignored_non_executable_under_src_is_allowed(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _ignore(git_repo, "*.log\n")
    (git_repo / "src" / "debug.log").write_text("noise\n", encoding="utf-8")
    assert ignored_executable_files(git_repo) == []
    assert check_snapshot(git_repo, "HEAD").clean


def test_ignored_pycache_is_allowed(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _ignore(git_repo, "__pycache__/\n")
    cachedir = git_repo / "src" / "__pycache__"
    cachedir.mkdir()
    (cachedir / "app.cpython-311.pyc").write_bytes(b"fake bytecode")
    assert ignored_executable_files(git_repo) == []
    assert check_snapshot(git_repo, "HEAD").clean


def test_ignored_executable_outside_src_is_allowed(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _ignore(git_repo, "*.log\n")
    (git_repo / "scratch.log").write_text("noise\n", encoding="utf-8")
    (git_repo / "tools").mkdir()
    (git_repo / "tools" / "helper.py").write_text("x = 1\n", encoding="utf-8")
    assert ignored_executable_files(git_repo) == []
    assert check_snapshot(git_repo, "HEAD").clean


def _lsfiles_v(repo: Path, target: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-v", "--", target],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout


def _require_flag_visible(repo: Path, target: str, markers: str, label: str) -> None:
    """Fail the test only via skip when this git cannot show the flag."""
    output = _lsfiles_v(repo, target)
    if not any(line and line[0] in markers for line in output.splitlines()):
        pytest.skip(f"git cannot expose {label} for {target}: {output!r}")


def test_assume_valid_file_is_refused(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _git(git_repo, "update-index", "--assume-unchanged", "src/app.py")
    _require_flag_visible(git_repo, "src/app.py", "h", "assume-unchanged")
    (git_repo / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
    assert relevant_status(git_repo).strip() == ""
    assert suspicious_index_entries(git_repo) == ["src/app.py"]
    with pytest.raises(GitError, match="index flags"):
        check_snapshot(git_repo, "HEAD")


def test_skip_worktree_file_is_refused(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _git(git_repo, "update-index", "--skip-worktree", "src/app.py")
    _require_flag_visible(git_repo, "src/app.py", "S", "skip-worktree")
    (git_repo / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
    assert relevant_status(git_repo).strip() == ""
    assert suspicious_index_entries(git_repo) == ["src/app.py"]
    with pytest.raises(GitError, match="index flags"):
        check_snapshot(git_repo, "HEAD")


def test_both_index_flags_are_detected(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _git(git_repo, "update-index", "--assume-unchanged", "src/app.py")
    _git(git_repo, "update-index", "--skip-worktree", "src/app.py")
    _require_flag_visible(git_repo, "src/app.py", "sS", "combined index flags")
    (git_repo / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
    assert suspicious_index_entries(git_repo) == ["src/app.py"]


def test_flagged_tests_file_is_refused(git_repo: Path) -> None:
    _commit(git_repo, "tests/test_app.py", "x = 1\n")
    _git(git_repo, "update-index", "--skip-worktree", "tests/test_app.py")
    _require_flag_visible(git_repo, "tests/test_app.py", "S", "skip-worktree")
    (git_repo / "tests" / "test_app.py").write_text("x = 2\n", encoding="utf-8")
    with pytest.raises(GitError, match="index flags"):
        check_snapshot(git_repo, "HEAD")


def test_flagged_config_file_is_refused(git_repo: Path) -> None:
    _commit(git_repo, "pyproject.toml", "[project]\n")
    _git(git_repo, "update-index", "--skip-worktree", "pyproject.toml")
    _require_flag_visible(git_repo, "pyproject.toml", "S", "skip-worktree")
    (git_repo / "pyproject.toml").write_text("[project]\n# tampered\n", encoding="utf-8")
    assert relevant_status(git_repo).strip() == ""
    with pytest.raises(GitError, match="index flags"):
        check_snapshot(git_repo, "HEAD")


def test_flagged_absent_config_files_pass(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    assert suspicious_index_entries(git_repo) == []
    assert check_snapshot(git_repo, "HEAD").clean


def test_source_in_pycache_is_flagged(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _ignore(git_repo, "__pycache__/\n")
    cache = git_repo / "src" / "__pycache__"
    cache.mkdir()
    (cache / "evil.py").write_text("evil = 1\n", encoding="utf-8")
    assert ignored_executable_files(git_repo) == ["src/__pycache__/evil.py"]
    with pytest.raises(GitError, match="ignored executable"):
        check_snapshot(git_repo, "HEAD")


def test_nested_pycache_bytecode_is_allowed(git_repo: Path) -> None:
    _commit(git_repo, "src/pkg/mod.py", "x = 1\n")
    _ignore(git_repo, "__pycache__/\n")
    cache = git_repo / "src" / "pkg" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "mod.cpython-311.pyc").write_bytes(b"fake bytecode")
    assert ignored_executable_files(git_repo) == []
    assert check_snapshot(git_repo, "HEAD").clean


def test_ignored_symlink_to_python_is_flagged(git_repo: Path, tmp_path: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _ignore(git_repo, "linked.py\n")
    target = tmp_path / "target.py"
    target.write_text("evil = 1\n", encoding="utf-8")
    (git_repo / "src" / "linked.py").symlink_to(target)
    assert ignored_executable_files(git_repo) == ["src/linked.py"]
    with pytest.raises(GitError, match="ignored executable"):
        check_snapshot(git_repo, "HEAD")


def test_fingerprint_detects_ignored_executable(git_repo: Path) -> None:
    _commit(git_repo, "src/app.py", "x = 1\n")
    _ignore(git_repo, "*.pyc\n")
    before = fingerprint(git_repo)
    (git_repo / "src" / "shadow.pyc").write_bytes(b"fake bytecode")
    assert fingerprint(git_repo) != before
