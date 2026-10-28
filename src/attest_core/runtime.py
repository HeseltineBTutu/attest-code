"""Runtime and environment binding for verification runs.

Execution depends on more than the git tree: the interpreter, import
overrides, and the dependency manifest all shape what actually runs. This
module validates import-affecting environment overrides and collects a
small, deterministic, non-secret runtime record that enters the run
configuration digest. It does not verify installed packages against the
lockfile (see security-model.md).
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import sys
from collections.abc import Mapping
from importlib import metadata as importlib_metadata
from pathlib import Path

DENIED_ENV_VARS = ("PYTHONHOME",)
"""Environment variables that relocate the interpreter; always refused."""

DENIED_ROOT_MODULES = ("sitecustomize.py", "usercustomize.py")
"""Auto-imported startup modules that must not be tied to the repository root.

`site` imports these by name during interpreter startup — before any
verifier check runs — whenever they are importable (notably from the
working directory or `PYTHONPATH`). Files at the root are refused on
presence; a module already imported from the tree trips the loaded-module
check. Traces scrubbed before the check runs are undetectable in-process.
"""

BOUND_CONFIG_FILES = ("pyproject.toml", "uv.lock", ".gitignore", ".gitattributes")
"""Manifest files whose content hash is bound into the configuration digest."""


class RuntimeConfigError(Exception):
    """Raised when the execution environment cannot be trusted or recorded."""


def _entries_within_root(value: str, root: Path) -> str:
    """Validate each PYTHONPATH entry resolves inside the repository root."""
    if not value:
        return ""
    cwd = Path.cwd()
    resolved_entries: list[str] = []
    for entry in value.split(os.pathsep):
        candidate = (cwd / entry if entry else cwd).resolve()
        if not candidate.is_relative_to(root):
            raise RuntimeConfigError(
                f"PYTHONPATH entry escapes the repository tree: {entry or '(empty)'}"
            )
        resolved_entries.append(str(candidate))
    return os.pathsep.join(resolved_entries)


def _loaded_startup_source(root: Path, module: str) -> str | None:
    """Explain why an already-imported startup module is suspect, if it is.

    A `sitecustomize`/`usercustomize` entry in `sys.modules` executed during
    interpreter startup, before any verifier check could run. Refuse it when
    attributable to the attested tree — e.g. a file that ran and deleted
    itself — or when it cannot be attributed elsewhere. A module that ran
    and then scrubbed its import traces is undetectable in-process.
    """
    loaded = sys.modules.get(module)
    if loaded is None:
        return None
    file = getattr(loaded, "__file__", None)
    if not isinstance(file, str) or not file:
        return f"{module} is already imported from an unknown location"
    try:
        inside = Path(file).resolve().is_relative_to(root.resolve())
    except OSError:
        return f"{module} is already imported from an unknown location"
    if inside:
        return f"{module} was already imported from the repository tree"
    return None


def check_root_startup_modules(root: Path) -> None:
    """Refuse auto-imported startup modules tied to the repository tree.

    Call before the first child process is spawned: persistent files and
    symlinks (including dangling ones) at the root or under src/ are
    refused on presence, and an already-imported module attributable to
    the tree trips the loaded-module check. Code that executed before this
    check and scrubbed its traces cannot be detected in-process (see
    security-model.md).
    """
    for parent in (root, root / "src"):
        for name in DENIED_ROOT_MODULES:
            if not os.path.lexists(parent / name):
                continue
            if parent == root:
                raise RuntimeConfigError(
                    f"{name} exists at the repository root; refusing to verify"
                )
            raise RuntimeConfigError(f"src/{name} exists in the source tree; refusing to verify")
    for name in DENIED_ROOT_MODULES:
        reason = _loaded_startup_source(root, name.removesuffix(".py"))
        if reason is not None:
            raise RuntimeConfigError(f"{reason}; refusing to verify")


def check_environment(root: Path, environ: Mapping[str, str] | None = None) -> str:
    """Validate import-affecting overrides; return the normalized PYTHONPATH."""
    env = os.environ if environ is None else environ
    for name in DENIED_ENV_VARS:
        if env.get(name):
            raise RuntimeConfigError(f"{name} is set; refusing to verify")
    check_root_startup_modules(root)
    return _entries_within_root(env.get("PYTHONPATH", ""), root)


def _file_digest(root: Path, name: str) -> str:
    try:
        data = (root / name).read_bytes()
    except FileNotFoundError:
        return "absent"
    except OSError as exc:
        raise RuntimeConfigError(f"cannot read {name}: {exc}") from exc
    return hashlib.sha256(data).hexdigest()


def _installed_versions() -> dict[str, str]:
    """Record installed versions for the runtime dependency closure.

    Requirement names come from the installed distribution metadata, so the
    record describes the environment that actually governs execution. Names
    are used as declared (environment markers are not evaluated); a missing
    distribution records "absent" rather than failing.
    """
    versions = {"deps.attest-code": _installed_version("attest-code")}
    try:
        requires = importlib_metadata.requires("attest-code")
    except importlib_metadata.PackageNotFoundError:
        return versions
    for requirement in requires or []:
        bare = re.split(r"[;<>!=~\s\[]", requirement, maxsplit=1)[0].strip()
        if not bare:
            continue
        name = re.sub(r"[-_.]+", "-", bare).lower()
        versions[f"deps.{name}"] = _installed_version(bare)
    return versions


def _installed_version(distribution: str) -> str:
    try:
        return importlib_metadata.version(distribution)
    except importlib_metadata.PackageNotFoundError:
        return "absent"


def collect_runtime_settings(
    root: Path, environ: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Collect deterministic runtime metadata for the configuration digest."""
    env = os.environ if environ is None else environ
    settings = {
        "python.implementation": platform.python_implementation().lower(),
        "python.version": platform.python_version(),
        "pythonpath": _entries_within_root(env.get("PYTHONPATH", ""), root),
    }
    for name in BOUND_CONFIG_FILES:
        settings[f"{name}.sha256"] = _file_digest(root, name)
    settings.update(_installed_versions())
    return settings
