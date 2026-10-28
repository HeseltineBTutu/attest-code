"""Focused Git adapter for revision integrity (MVP policy).

The verifier tests the current working tree. It records a revision only
when the requested commit is checked out and the relevant paths are clean,
and it fingerprints the snapshot before and after verification so a change
during the run is detected instead of silently recorded.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import subprocess
from pathlib import Path

RELEVANT_PATHS = ("src", "tests", "invariants")
"""Source directories whose modifications or untracked files invalidate a snapshot."""

RELEVANT_FILES = ("pyproject.toml", "uv.lock", ".gitignore", ".gitattributes")
"""Root config files that must be committed and clean, or absent.

These pin the dependency manifest (pyproject/uv.lock) and the worktree
semantics git itself applies (.gitignore/.gitattributes). An untracked or
modified copy means the recorded OID does not fully describe the tree.
"""

SNAPSHOT_PATHS = RELEVANT_PATHS + RELEVANT_FILES
"""Full clean-tree scope: source directories plus root configuration files."""

EXECUTABLE_SUFFIXES = frozenset({".py", ".pyc", ".pyo", ".so", ".pyd"})
"""Suffixes Python can import; ignored files with these can shadow real code."""

BYTECODE_SUFFIXES = frozenset({".pyc", ".pyo"})
"""Bytecode suffixes whose `__pycache__/` copies are not directly importable."""

_FULL_OID = re.compile(r"^[0-9a-f]{40}$")


class GitError(Exception):
    """Raised when the requested source snapshot cannot be established."""


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """A verified-clean source snapshot."""

    revision: str
    clean: bool
    status: str


def _git(repo: Path, *args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git command timed out: {exc.cmd}") from exc


def repo_root(repo: Path) -> Path:
    """Return the canonical top-level directory of the containing work tree."""
    proc = _git(repo, "rev-parse", "--show-toplevel")
    top = proc.stdout.strip()
    if proc.returncode != 0 or not top:
        detail = proc.stderr.strip() or f"not a git work tree: {repo}"
        raise GitError(detail)
    return Path(top).resolve()


def resolve_revision(repo: Path, revision: str) -> str:
    """Resolve a revision to a full 40-hex commit object ID."""
    if not revision.strip():
        raise GitError("revision must be non-empty")
    proc = _git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}")
    oid = proc.stdout.strip()
    if proc.returncode != 0 or not _FULL_OID.match(oid):
        detail = proc.stderr.strip() or f"cannot resolve revision {revision!r}"
        raise GitError(detail)
    return oid


def relevant_status(repo: Path, paths: tuple[str, ...] = SNAPSHOT_PATHS) -> str:
    """Porcelain status (including untracked files) for the snapshot scope."""
    proc = _git(repo, "status", "--porcelain", "--", *paths)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "cannot read git status"
        raise GitError(detail)
    return proc.stdout


def _iter_ignored(repo: Path, scope: str) -> list[str]:
    """List git-ignored paths beneath a scope directory, expanding collapsed dirs."""
    proc = _git(repo, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", scope)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "cannot list ignored files"
        raise GitError(detail)
    entries: list[str] = []
    for entry in proc.stdout.split("\0"):
        if not entry:
            continue
        if not entry.endswith("/"):
            entries.append(entry)
            continue
        scope_dir = repo / entry
        if scope_dir.is_dir():
            entries.extend(
                found.relative_to(repo).as_posix()
                for found in sorted(scope_dir.rglob("*"))
                if found.is_file()
            )
    return entries


def ignored_executable_files(repo: Path, scope: str = "src") -> list[str]:
    """Ignored importable files under the executable scope, sorted.

    Only bytecode copies under a `__pycache__/` segment are excluded: those
    tagged names are never directly importable. A `.py` source inside
    `__pycache__/` (namespace-importable), legacy-path bytecode, extension
    modules, and other importable suffixes are all flagged: any of them
    could shadow tracked code while staying invisible to `git status`.
    """
    found: list[str] = []
    for entry in _iter_ignored(repo, scope):
        suffix = Path(entry).suffix.lower()
        if suffix not in EXECUTABLE_SUFFIXES:
            continue
        if suffix in BYTECODE_SUFFIXES and "__pycache__/" in entry.replace("\\", "/"):
            continue
        found.append(entry)
    return sorted(found)


def suspicious_index_entries(repo: Path, scope: tuple[str, ...] = SNAPSHOT_PATHS) -> list[str]:
    """Tracked files whose index flags hide worktree changes from git status.

    Both status-hiding flags are detected via `git ls-files -v`, whose tag
    letters are: lowercase for assume-unchanged (`h`, or `s` when both flags
    are set) and `S` for skip-worktree. Checking lowercase alone would miss
    skip-worktree. Absent paths in the scope simply produce no output.
    """
    proc = _git(repo, "ls-files", "-v", "--", *scope)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "cannot read index flags"
        raise GitError(detail)
    flagged: list[str] = []
    for line in proc.stdout.splitlines():
        if line and (line[0].islower() or line[0] == "S"):
            flagged.append(line[1:].strip())
    return sorted(flagged)


def check_snapshot(repo: Path, revision: str, paths: tuple[str, ...] = SNAPSHOT_PATHS) -> Snapshot:
    """Establish that the working tree matches the requested revision.

    Raises unless the revision resolves, HEAD equals it, the snapshot scope
    shows no staged, unstaged, or untracked changes, and no ignored
    executable or flag-hidden files lurk under the executable scope.
    """
    oid = resolve_revision(repo, revision)
    head = resolve_revision(repo, "HEAD")
    if head != oid:
        raise GitError(
            f"HEAD is {head} but requested revision is {oid}; "
            "check out the revision before verifying"
        )
    status = relevant_status(repo, paths)
    if status.strip():
        raise GitError(f"uncommitted changes under {list(paths)}:\n{status.strip()}")
    ignored = ignored_executable_files(repo)
    if ignored:
        raise GitError("ignored executable files under src/:\n" + "\n".join(ignored))
    flagged = suspicious_index_entries(repo)
    if flagged:
        raise GitError("files hidden from status via index flags:\n" + "\n".join(flagged))
    return Snapshot(revision=oid, clean=True, status="")


def fingerprint(repo: Path, paths: tuple[str, ...] = SNAPSHOT_PATHS) -> str:
    """Fingerprint the current snapshot for before/after comparison."""
    material = "\n".join(
        [
            resolve_revision(repo, "HEAD"),
            relevant_status(repo, paths),
            "\n".join(ignored_executable_files(repo)),
            "\n".join(suspicious_index_entries(repo)),
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()
