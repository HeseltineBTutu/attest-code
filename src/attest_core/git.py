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
"""Paths whose modifications or untracked files invalidate a snapshot."""

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


def relevant_status(repo: Path, paths: tuple[str, ...] = RELEVANT_PATHS) -> str:
    """Porcelain status (including untracked files) for relevant paths."""
    proc = _git(repo, "status", "--porcelain", "--", *paths)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "cannot read git status"
        raise GitError(detail)
    return proc.stdout


def check_snapshot(repo: Path, revision: str, paths: tuple[str, ...] = RELEVANT_PATHS) -> Snapshot:
    """Establish that the working tree matches the requested revision.

    Raises unless the revision resolves, HEAD equals it, and the relevant
    paths show no staged, unstaged, or untracked changes.
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
    return Snapshot(revision=oid, clean=True, status="")


def fingerprint(repo: Path, paths: tuple[str, ...] = RELEVANT_PATHS) -> str:
    """Fingerprint the current snapshot for before/after comparison."""
    material = f"{resolve_revision(repo, 'HEAD')}\n{relevant_status(repo, paths)}"
    return hashlib.sha256(material.encode()).hexdigest()
