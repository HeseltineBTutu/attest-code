"""Module-origin binding: tie executed code to the attested repository tree.

`attest verify` fingerprints `--repo` but executes whatever Python imports
resolve to (installed packages, editable checkouts, `PYTHONPATH`). This
module closes that gap: it canonicalizes the repository root, checks that
the verifier/demo packages loaded in this process come from the snapshotted
tree, and probes a spawned worker — the same spawn mechanism that runs
attempts — to establish where the worker resolves them.

Anything unresolvable fails closed with OriginError. Path binding plus a
clean tree does not prove exact executed bytes (see security-model.md): it
proves the loaded files live inside the attested snapshot.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import multiprocessing
import sys
from collections.abc import Mapping
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from attest_core.git import RELEVANT_PATHS, GitError, repo_root

EXPECTED_PACKAGES = ("attest_spec", "attest_core", "apps", "examples", "integrations")
"""First-party packages whose origin must be inside the attested tree."""

_PROBE_GRACE_SECONDS = 10


class OriginError(Exception):
    """Raised when executed code cannot be tied to the attested tree."""


@dataclasses.dataclass(frozen=True)
class OriginReport:
    """Provenance of the verifier/demo packages in parent and worker."""

    root: Path
    parent: dict[str, str]
    worker: dict[str, str]


def resolve_repo_root(repo: Path) -> Path:
    """Canonicalize `--repo` to an unambiguous repository root directory."""
    candidate = repo.expanduser().resolve()
    if not candidate.is_dir():
        raise OriginError(f"repository path is not a directory: {repo}")
    try:
        top = repo_root(candidate)
    except GitError as exc:
        raise OriginError(str(exc)) from exc
    if top != candidate:
        raise OriginError(f"not the repository root (top level is {top}): {repo}")
    return candidate


def require_within_root(path: Path, root: Path, label: str) -> Path:
    """Resolve an input path and reject it unless it lives under the root."""
    resolved = path.expanduser().resolve()
    if not resolved.is_relative_to(root):
        raise OriginError(f"{label} is outside the repository tree: {path}")
    return resolved


def _spec_origin(name: str) -> str | None:
    try:
        found = importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return None
    if found is None or found.origin is None:
        return None
    return found.origin


def parent_origins() -> dict[str, str | None]:
    """Report where this process loaded (or would load) each package from."""
    origins: dict[str, str | None] = {}
    for name in EXPECTED_PACKAGES:
        loaded = sys.modules.get(name)
        loaded_file = getattr(loaded, "__file__", None) if loaded is not None else None
        origins[name] = loaded_file if isinstance(loaded_file, str) else _spec_origin(name)
    return origins


def check_origins(origins: Mapping[str, str | None], root: Path, *, actor: str) -> dict[str, str]:
    """Validate resolved origins against the snapshot-enforced tree paths."""
    checked: dict[str, str] = {}
    allowed = [root / rel for rel in RELEVANT_PATHS]
    for name in EXPECTED_PACKAGES:
        origin = origins.get(name)
        if origin is None:
            raise OriginError(f"{actor}: cannot resolve module origin: {name}")
        resolved = Path(origin).expanduser().resolve()
        if not any(resolved.is_relative_to(base) for base in allowed):
            raise OriginError(
                f"{actor}: {name} loaded from outside the repository tree: "
                f"{resolved} (expected under {root})"
            )
        checked[name] = str(resolved)
    return checked


def report_worker_origins() -> dict[str, str | None]:
    """Top-level worker entry: resolve origins without importing module code."""
    return {name: _spec_origin(name) for name in EXPECTED_PACKAGES}


def _probe_main(conn: Connection) -> None:
    try:
        conn.send(("ok", report_worker_origins()))
    except Exception as exc:
        conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()


def _validate_probe_payload(payload: Any) -> dict[str, str | None]:
    if not isinstance(payload, dict):
        raise OriginError("worker origin probe returned malformed data")
    return {
        name: (value if value is None or isinstance(value, str) else str(value))
        for name, value in payload.items()
        if isinstance(name, str)
    }


def probe_worker_origins(timeout_seconds: float) -> dict[str, str | None]:
    """Ask a spawned worker where it resolves the expected packages."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    ctx = multiprocessing.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_probe_main, args=(child_conn,), daemon=True)
    proc.start()
    child_conn.close()
    try:
        if parent_conn.poll(timeout_seconds):
            try:
                kind, payload = parent_conn.recv()
            except EOFError:
                proc.join(_PROBE_GRACE_SECONDS)
                raise OriginError(
                    f"worker origin probe crashed (exit code {proc.exitcode})"
                ) from None
            proc.join(_PROBE_GRACE_SECONDS)
            if kind != "ok":
                raise OriginError(f"worker origin probe failed: {payload}")
            return _validate_probe_payload(payload)
        if proc.is_alive():
            proc.terminate()
            proc.join(_PROBE_GRACE_SECONDS)
            if proc.is_alive():
                proc.kill()
                proc.join(_PROBE_GRACE_SECONDS)
            raise OriginError("worker origin probe timed out")
        proc.join(_PROBE_GRACE_SECONDS)
        raise OriginError(f"worker origin probe crashed (exit code {proc.exitcode})")
    finally:
        parent_conn.close()
        if proc.is_alive():
            proc.kill()
            proc.join(_PROBE_GRACE_SECONDS)


def verify_code_origin(root: Path, timeout_seconds: float) -> OriginReport:
    """Establish parent- and worker-side module origins inside the tree."""
    parent = check_origins(parent_origins(), root, actor="parent process")
    worker = check_origins(probe_worker_origins(timeout_seconds), root, actor="worker process")
    return OriginReport(root=root, parent=parent, worker=worker)


def prepare_worker_sys_path(snapshot_src: Path, live_root: Path) -> None:
    """Point this process's import path at the snapshot for future children.

    Spawn children inherit the parent's `sys.path` wholesale, so strip the
    empty entry and every entry resolving under the live root, then prepend
    the snapshot source directory. Mutates process-global state; the CLI
    invokes verification once per process (see security-model.md).
    """
    live = live_root.resolve()
    kept: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        try:
            if Path(entry).resolve().is_relative_to(live):
                continue
        except OSError:
            continue
        kept.append(entry)
    sys.path[:] = [str(snapshot_src), *kept]
