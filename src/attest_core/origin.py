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

import contextlib
import dataclasses
import importlib.util
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from attest_core.envelope import (
    SandboxEnvelopeError,
    decode_origins_envelope,
    encode_error,
    encode_origins,
    read_result_file,
    write_result_file,
)
from attest_core.git import RELEVANT_PATHS, GitError, repo_root
from attest_core.sandbox import (
    SandboxWorkdir,
    build_worker_environ,
    cleanup_workdir,
    enter_worker_context,
    guarded_spawn,
    prepare_workdir,
    register_cleanup,
    terminate_worker,
)

EXPECTED_PACKAGES = ("attest_spec", "attest_core", "apps", "examples", "integrations")
"""First-party packages whose origin must be inside the attested tree."""

_DEPENDENCY_DIR_NAMES = frozenset({"site-packages", "dist-packages"})
"""Directory names marking third-party dependency locations.

A `sys.path` entry resolving inside one of these directories holds
operator-owned interpreter dependencies, never first-party project code.
Such entries are exempt from live-root stripping so spawned workers keep
their third-party imports (notably with an in-repository `.venv`, whose
`site-packages` resolves under the live root).
"""


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


def _probe_main(paths: SandboxWorkdir) -> None:
    enter_worker_context(paths)
    try:
        write_result_file(paths.result, encode_origins(report_worker_origins()))
    except Exception as exc:
        with contextlib.suppress(OSError):
            write_result_file(paths.result, encode_error(f"{type(exc).__name__}: {exc}"))


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
    paths = prepare_workdir()
    register_cleanup(paths.root)
    try:
        env = build_worker_environ()
        with guarded_spawn(_probe_main, (paths,), environ=env, cwd=paths.root) as proc:
            proc.join(timeout_seconds)
            if proc.is_alive():
                terminate_worker(proc)
                raise OriginError("worker origin probe timed out")
            if proc.exitcode != 0:
                raise OriginError(f"worker origin probe crashed (exit code {proc.exitcode})")
            try:
                return _validate_probe_payload(
                    decode_origins_envelope(read_result_file(paths.result))
                )
            except SandboxEnvelopeError as exc:
                raise OriginError(f"worker origin probe failed: {exc}") from exc
    finally:
        cleanup_workdir(paths.root)


def verify_code_origin(root: Path, timeout_seconds: float) -> OriginReport:
    """Establish parent- and worker-side module origins inside the tree."""
    parent = check_origins(parent_origins(), root, actor="parent process")
    worker = check_origins(probe_worker_origins(timeout_seconds), root, actor="worker process")
    return OriginReport(root=root, parent=parent, worker=worker)


def _is_dependency_search_path(resolved: Path) -> bool:
    """Whether a resolved `sys.path` entry is a dependency directory.

    Detection is structural (a `site-packages`/`dist-packages` path segment)
    rather than prefix-based so it also covers environments injected via
    `PYTHONPATH`. The exemption is safe because the entries it preserves
    come from the operator-owned interpreter environment — contributors
    cannot add `sys.path` entries — and first-party names still cannot
    resolve outside the snapshot: snapshot `src` is prepended first, and
    the origin checks fail closed on any fallback.
    """
    return any(part in _DEPENDENCY_DIR_NAMES for part in resolved.parts)


def prepare_worker_sys_path(snapshot_src: Path, live_root: Path) -> None:
    """Point this process's import path at the snapshot for future children.

    Spawn children inherit the parent's `sys.path` wholesale, so strip the
    empty entry and every entry resolving under the live root, then prepend
    the snapshot source directory. Dependency directories (`site-packages`
    / `dist-packages`, including an in-repository `.venv`) are exempt from
    stripping: without them, spawned workers lose third-party imports.
    Mutates process-global state; the CLI invokes verification once per
    process (see security-model.md).
    """
    live = live_root.resolve()
    kept: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        try:
            resolved = Path(entry).resolve()
        except OSError:
            continue
        if resolved.is_relative_to(live) and not _is_dependency_search_path(resolved):
            continue
        kept.append(entry)
    sys.path[:] = [str(snapshot_src), *kept]
