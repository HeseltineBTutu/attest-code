"""Benchmark environment capture for performance measurement records.

:func:`collect_environment` records the host, repository, runtime, and
configuration context a benchmark ran under, following policy §5. Host
and repository values come from :mod:`attest_core.bench_env_probes`;
this module validates arguments, assembles the fixed-shape record,
and applies the environment-variable allowlist.

This module is a collector, not an attestation authority: output
describes observed state and proves nothing about authenticity. Every
probed field is either a verified value or an explicit
``{"unavailable": reason}`` marker — never an empty string, zero, or
fabricated default. Environment variables pass an exact-name
allowlist; the full process environment is never serialized, and
proxy userinfo (``user:pass@``) is redacted to ``***@``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from attest_core import bench_env_probes
from attest_core.git import GitError

_PROFILES = ("standard", "contained", "hardened")
"""Execution profiles named by policy §5 (matches the exec-profile mapping)."""

_ENV_ALLOWLIST = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONHASHSEED",
        "PYTHONPYCACHEPREFIX",
        "PATH",
        "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
        "XDG_CACHE_HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
        "NUMBER_OF_PROCESSORS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)
"""Exact environment-variable names collected: imports, paths, caches,
parallelism, and proxies per policy §5. Anything else is never read."""

_PROXY_VARS = frozenset(
    {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}
)
"""Allowlisted variables whose values may embed credentials; redacted."""


def _redact_userinfo(value: str) -> str:
    """Strip proxy credentials, keeping scheme and host (``http://***@host``)."""
    if "@" not in value:
        return value
    scheme, sep, rest = value.partition("://")
    if sep:
        return f"{scheme}{sep}***{rest[rest.rfind('@') :]}"
    return "***" + value[value.rfind("@") :]


def _collect_allowed_env() -> dict[str, str]:
    """Values of set allowlisted variables only (sorted); proxies redacted."""
    collected = {}
    for name in sorted(_ENV_ALLOWLIST):
        value = os.environ.get(name)
        if value is None:
            continue
        if name in _PROXY_VARS:
            value = _redact_userinfo(value)
        collected[name] = value
    return collected


def collect_environment(*, profile: str, command: str) -> dict[str, Any]:
    """Capture the benchmark execution environment as a fixed-shape dict.

    ``profile`` must be a policy §5 execution profile and ``command``
    the exact non-empty benchmark command; both are validated, never
    collected, so invalid arguments raise instead of becoming
    markers. Each probe failure yields a per-field ``{"unavailable":
    reason}`` marker without affecting other fields. Only expected
    per-call failures become markers; programming errors propagate.
    """
    if not isinstance(profile, str):
        raise TypeError(f"profile must be str, got {type(profile).__name__}")
    if profile not in _PROFILES:
        raise ValueError(f"profile must be one of {', '.join(_PROFILES)}, got {profile!r}")
    if not isinstance(command, str):
        raise TypeError(f"command must be str, got {type(command).__name__}")
    if not command:
        raise ValueError("command must be a non-empty string")
    try:
        base = bench_env_probes.resolve_base()
    except GitError as exc:
        base = Path.cwd()
        marker = bench_env_probes.unavailable(str(exc))
        revision: str | dict[str, str] = marker
        worktree: dict[str, str] = marker
    else:
        revision = bench_env_probes.collect_revision(base)
        worktree = bench_env_probes.collect_worktree(base)
    return {
        "profile": profile,
        "command": command,
        "git_revision": revision,
        "worktree": worktree,
        "python": bench_env_probes.collect_python(),
        "uv": bench_env_probes.collect_uv(),
        "os": bench_env_probes.collect_os(),
        "kernel": bench_env_probes.collect_kernel(),
        "cpu_model": bench_env_probes.collect_cpu_model(),
        "memory_total_bytes": bench_env_probes.collect_memory_total_bytes(),
        "pyproject_digest": bench_env_probes.collect_lock_digest(base, "pyproject.toml"),
        "uv_lock_digest": bench_env_probes.collect_lock_digest(base, "uv.lock"),
        "environment": _collect_allowed_env(),
    }
