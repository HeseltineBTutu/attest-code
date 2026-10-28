"""Immutable execution snapshot: workers execute verified HEAD bytes.

The live worktree can change between integrity samples, so workers must not
import from it. This module exports the execution closure (the first-party
packages) directly from git objects — never by copying the worktree — into
a per-run directory, then identifies it with a manifest digest covering
file paths, file bytes, the selected invariant, the validated approval,
and the recorded configuration. `git archive` is deliberately not used:
it applies export-subst expansion and honors export-ignore omissions, so
its bytes can differ from both the blobs and the worktree.

The digest establishes content identity relative to itself, never
authenticity. Re-verification detects persistent tampering; a change made
and reverted strictly inside one attempt remains invisible (see
security-model.md).
"""

from __future__ import annotations

import atexit
import dataclasses
import os
import shutil
import subprocess
import tempfile
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from attest_core.evidence import canonical_bytes, sha256_hex
from attest_core.invariants import approval_digest, invariant_content_digest
from attest_core.origin import EXPECTED_PACKAGES
from attest_core.runtime import BOUND_CONFIG_FILES
from attest_spec import ApprovalRecord, Invariant

SNAPSHOT_POLICY = "attest-snapshot-v1"
"""Version identifier for the snapshot scope and manifest format."""

SNAPSHOT_SOURCE_DIR = "src"
"""Worktree directory mirrored into the snapshot for execution."""

ALLOWED_BLOB_MODES = frozenset({"100644", "100755"})
"""Git modes accepted for snapshot files (regular files only)."""

DENIED_SUFFIXES = frozenset({".pyc", ".pyo", ".so", ".pyd"})
"""Importable suffixes that must never enter the snapshot as tracked files."""

_GIT_TIMEOUT_SECONDS = 60


class SnapshotError(Exception):
    """Raised when the execution snapshot cannot be built or verified."""


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """Verified bytes for one verification run; shared by all attempts."""

    root: Path
    digest: str
    files: tuple[tuple[str, str], ...]
    manifest: Mapping[str, Any]


def _git_bytes(repo: Path, *args: str, input_data: bytes | None = None) -> bytes:
    """Run git with byte-exact output; blobs must never cross text decoding."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=repo,
            input=input_data,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SnapshotError("git executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise SnapshotError(f"git command timed out: {exc.cmd}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "git command failed"
        raise SnapshotError(detail)
    return proc.stdout


def _ls_tree(repo: Path, head: str, paths: list[str]) -> list[tuple[str, str, str, str]]:
    """List (mode, type, oid, name) for HEAD entries under the given paths."""
    raw = _git_bytes(repo, "ls-tree", "-r", "-z", head, "--", *paths)
    entries: list[tuple[str, str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            meta, name = record.split(b"\t")
            mode, objtype, oid = meta.decode("ascii").split(" ")
            decoded = name.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SnapshotError(f"cannot parse git tree entry: {record!r}") from exc
        entries.append((mode, objtype, oid, decoded))
    return entries


def _read_blobs(repo: Path, oids: list[str]) -> dict[str, bytes]:
    """Read blob bytes for object ids in one batch; validates sizes/types."""
    unique = list(dict.fromkeys(oids))
    if not unique:
        return {}
    raw = _git_bytes(repo, "cat-file", "--batch", input_data=("\n".join(unique) + "\n").encode())
    blobs: dict[str, bytes] = {}
    cursor = 0
    try:
        for oid in unique:
            end = raw.index(b"\n", cursor)
            header = raw[cursor:end].decode("ascii").split(" ")
            cursor = end + 1
            if len(header) != 3 or header[0] != oid or header[1] != "blob":
                raise SnapshotError(f"unexpected object for {oid}: {' '.join(header)}")
            size = int(header[2])
            chunk = raw[cursor : cursor + size]
            if len(chunk) != size or raw[cursor + size : cursor + size + 1] != b"\n":
                raise SnapshotError(f"truncated object for {oid}")
            blobs[oid] = chunk
            cursor += size + 1
    except (ValueError, UnicodeDecodeError) as exc:
        raise SnapshotError(f"cannot parse git object batch: {exc}") from exc
    return blobs


def _validate_name(name: str) -> None:
    """Reject names that could escape the snapshot directory or confuse joins."""
    if (
        not name
        or "\\" in name
        or name.startswith("/")
        or name in (".", "..")
        or "/../" in f"/{name}/"
        or name.startswith("../")
        or name.endswith("/..")
    ):
        raise SnapshotError(f"unsupported path in snapshot scope: {name!r}")


def _snapshot_src_entries(
    entries: list[tuple[str, str, str, str]],
) -> list[tuple[str, str, str]]:
    """Validate src/ scope entries; return (path, oid, mode) for blobs."""
    scoped = [
        (mode, oid, name)
        for mode, _t, oid, name in entries
        if name == "src" or name.startswith("src/")
    ]
    blobs: list[tuple[str, str, str]] = []
    for mode, oid, name in scoped:
        _validate_name(name)
        if mode == "120000":
            raise SnapshotError(f"symlink in snapshot scope rejected: {name}")
        if mode == "160000":
            raise SnapshotError(f"submodule in snapshot scope rejected: {name}")
        if mode not in ALLOWED_BLOB_MODES:
            raise SnapshotError(f"unsupported entry {mode} in snapshot scope: {name}")
        if Path(name).suffix.lower() in DENIED_SUFFIXES:
            raise SnapshotError(f"importable artifact in snapshot scope rejected: {name}")
        blobs.append((name, oid, mode))
    top = {name.split("/")[1] for name, _, _ in blobs if "/" in name}
    if top != set(EXPECTED_PACKAGES):
        raise SnapshotError(
            f"snapshot src/ scope must be exactly {sorted(EXPECTED_PACKAGES)}: {sorted(top)}"
        )
    for package in EXPECTED_PACKAGES:
        if f"src/{package}/__init__.py" not in {name for name, _, _ in blobs}:
            raise SnapshotError(f"snapshot package is missing __init__.py: {package}")
    return blobs


def _write_snapshot_files(
    root: Path, blobs: dict[str, bytes], wanted: list[tuple[str, str]]
) -> None:
    """Write validated blobs to root-relative paths inside a fresh directory."""
    for name, oid in wanted:
        _validate_name(name)
        target = (root / name).resolve()
        if not target.is_relative_to(root.resolve()):
            raise SnapshotError(f"snapshot path escapes its root: {name!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blobs[oid])


def _lstat_walk(root: Path) -> dict[str, str]:
    """Hash every regular file under root; reject links and special files."""
    found: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise SnapshotError(f"snapshot integrity check failed: link entry {path.name}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SnapshotError(f"snapshot integrity check failed: special file {path.name}")
        rel = path.relative_to(root).as_posix()
        found[rel] = sha256_hex(path.read_bytes())
    return found


def verify_snapshot(snapshot: Snapshot) -> None:
    """Re-verify snapshot bytes against the build-time manifest; fail closed."""
    expected = dict(snapshot.files)
    actual = _lstat_walk(snapshot.root)
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(k for k in expected if k in actual and expected[k] != actual[k])
        detail = ",".join(missing + extra + changed) or "unknown"
        raise SnapshotError(f"snapshot integrity check failed: {detail}")


def _freeze_permissions(root: Path) -> None:
    """Remove file write bits as a speed-bump; integrity never depends on this.

    Directories keep a write bit so exit-time cleanup can unlink children;
    tampering is detected by manifest re-verification, not by modes.
    """
    for path in sorted(root.rglob("*")):
        try:
            if path.is_symlink():
                continue
            os.chmod(path, 0o755 if path.is_dir() else 0o444)
        except OSError:
            continue


def _invariant_source_label(
    repo: Path,
    entries: list[tuple[str, str, str, str]],
    invariant_rel: str,
    invariant_path: Path,
) -> str:
    """Label the invariant bytes as HEAD-committed or worktree-resolved.

    The label is provenance information only; run identity rests on the
    content digest of the loaded invariant object. A live re-read backs the
    label, so an active race can mislabel it but never the digest.
    """
    for mode, objtype, oid, name in entries:
        if name != invariant_rel or objtype != "blob" or mode == "120000":
            continue
        try:
            live = invariant_path.read_bytes()
        except OSError:
            return "worktree"
        return "head" if _read_blobs(repo, [oid])[oid] == live else "worktree"
    return "worktree"


def build_snapshot(
    *,
    repo: Path,
    head: str,
    invariant: Invariant,
    approval: ApprovalRecord,
    invariant_path: Path,
) -> Snapshot:
    """Export the verified execution closure for one run from git objects."""
    root = repo.resolve()
    if not invariant_path.resolve().is_relative_to(root):
        raise SnapshotError(f"invariant file is outside the repository tree: {invariant_path}")
    invariant_rel = invariant_path.resolve().relative_to(root).as_posix()
    spec = ["src", invariant_rel, *BOUND_CONFIG_FILES]
    entries = _ls_tree(repo, head, spec)
    src_blobs = _snapshot_src_entries(entries)
    by_name = {name: (mode, objtype, oid) for mode, objtype, oid, name in entries}
    wanted = [(name, oid) for name, oid, _mode in src_blobs]
    config: dict[str, str] = {}
    config_wanted: list[tuple[str, str]] = []
    for name in BOUND_CONFIG_FILES:
        found = by_name.get(name)
        if found is None:
            config[name] = "absent"
        elif found[0] not in ALLOWED_BLOB_MODES or found[1] != "blob":
            raise SnapshotError(f"unsupported config entry in snapshot scope: {name}")
        else:
            config_wanted.append((name, found[2]))
    blobs = _read_blobs(repo, [oid for _, oid in wanted] + [oid for _, oid in config_wanted])
    for name, oid in config_wanted:
        config[name] = sha256_hex(blobs[oid])
    manifest_files = sorted((name, sha256_hex(blobs[oid])) for name, oid in wanted)
    manifest = {
        "snapshot_policy": SNAPSHOT_POLICY,
        "head": head,
        "files": [{"path": name, "sha256": digest} for name, digest in manifest_files],
        "invariant_path": invariant_rel,
        "invariant_sha256": invariant_content_digest(invariant),
        "invariant_source": _invariant_source_label(repo, entries, invariant_rel, invariant_path),
        "approval_sha256": approval_digest(approval),
        "config": config,
    }
    digest = sha256_hex(canonical_bytes(manifest))
    target = Path(tempfile.mkdtemp(prefix="attest-snapshot-"))
    atexit.register(shutil.rmtree, target, True)
    _write_snapshot_files(target, blobs, wanted)
    snapshot = Snapshot(
        root=target,
        digest=digest,
        files=tuple(manifest_files),
        manifest=types.MappingProxyType(manifest),
    )
    verify_snapshot(snapshot)
    _freeze_permissions(target)
    return snapshot


__all__ = ["Snapshot", "SnapshotError", "SNAPSHOT_POLICY", "build_snapshot", "verify_snapshot"]
