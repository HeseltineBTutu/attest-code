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
from collections.abc import Mapping
from pathlib import Path

DENIED_ENV_VARS = ("PYTHONHOME",)
"""Environment variables that relocate the interpreter; always refused."""

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


def check_environment(root: Path, environ: Mapping[str, str] | None = None) -> str:
    """Validate import-affecting overrides; return the normalized PYTHONPATH."""
    env = os.environ if environ is None else environ
    for name in DENIED_ENV_VARS:
        if env.get(name):
            raise RuntimeConfigError(f"{name} is set; refusing to verify")
    return _entries_within_root(env.get("PYTHONPATH", ""), root)


def _file_digest(root: Path, name: str) -> str:
    try:
        data = (root / name).read_bytes()
    except FileNotFoundError:
        return "absent"
    except OSError as exc:
        raise RuntimeConfigError(f"cannot read {name}: {exc}") from exc
    return hashlib.sha256(data).hexdigest()


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
    return settings
