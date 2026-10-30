"""Execution profiles: named worker-isolation contracts for verification.

Maps ``--exec`` names to :func:`run_bounded` flags, probes only the
capabilities the requested profile needs, and refuses unsupported
requests before any attempt runs. Standard needs no probing;
contained needs namespaces; hardened needs namespaces, quotas, and
seccomp. Refusals raise :class:`ExecProfileError` (the CLI maps every
error to exit 3); refusals never yield a verdict.

Stage 2 makes hardened operational: quotas, containment, and seccomp
all fail closed to infrastructure failure, so a hardened attempt with a
clean (non-INFRA) outcome proves its setup operations all completed.
Enforcement status derives from attempt outcomes, never the request.
Quotas alone get independent post-hoc re-verification (limit files are
re-read at teardown); namespaces and seccomp are confirmed via their
fail-closed setup return codes, not re-checked afterwards.
"""

from __future__ import annotations

import dataclasses
import importlib
from collections.abc import Callable, Sequence
from typing import Any

from attest_spec import AttemptOutcome

STANDARD = "standard"
CONTAINED = "contained"
HARDENED = "hardened"
PROFILES = (STANDARD, CONTAINED, HARDENED)
"""Supported ``--exec`` names; the CLI rejects anything else."""

_FLAGS: dict[str, dict[str, bool]] = {
    STANDARD: {"contained": False, "quotas": False, "seccomp": False},
    CONTAINED: {"contained": True, "quotas": False, "seccomp": False},
    HARDENED: {"contained": True, "quotas": True, "seccomp": True},
}
"""Authoritative profile-to-flag mapping; nothing else may redefine it."""

_NEEDS: dict[str, tuple[str, ...]] = {
    STANDARD: (),
    CONTAINED: ("containment",),
    HARDENED: ("containment", "quotas", "seccomp"),
}
"""Capabilities each profile requires, in probe order."""

ENFORCEMENT_NONE = "none-claimed"
ENFORCEMENT_UNVERIFIED = "requested-unverified"
ENFORCEMENT_VERIFIED = "verified"
"""Standard claims nothing; isolation profiles verify via clean outcomes."""

PRODUCTION_QUOTAS = True
"""Production quota execution is integrated; hardened is operational."""


class ExecProfileError(Exception):
    """A requested execution profile cannot be honored; refuse, never retry."""


def _probe(module: str, attr: str) -> bool:
    """Import a capability detector lazily; missing/broken means unavailable."""
    try:
        detector = getattr(importlib.import_module(f"attest_core.{module}"), attr)
    except Exception:
        return False
    try:
        return bool(detector())
    except Exception:
        return False


_PROBES: dict[str, Callable[[], bool]] = {
    "containment": lambda: _probe("ns_setup", "supports_containment"),
    "quotas": lambda: _probe("scopes", "supports_quotas"),
    "seccomp": lambda: _probe("seccomp", "supports_seccomp"),
}
"""Capability name to lazy detector; detectors never raise or install."""


@dataclasses.dataclass(frozen=True)
class ResolvedProfile:
    """A preflight-passed request: flags to pass plus reportable facts."""

    requested: str
    contained: bool
    quotas: bool
    seccomp: bool
    capabilities: dict[str, bool]
    enforcement: str

    def flags(self) -> dict[str, Any]:
        """Keyword flags for :func:`run_bounded`, from the profile mapping."""
        return {
            "contained": self.contained,
            "quotas": self.quotas,
            "seccomp": self.seccomp,
        }

    def report(self) -> dict[str, Any]:
        """Report-level execution facts; no silent fallback is possible."""
        return {
            "requested": self.requested,
            "selected": self.requested,
            "actual": {
                "contained": self.contained,
                "quotas": self.quotas,
                "seccomp": self.seccomp,
            },
            "capabilities": dict(self.capabilities),
            "enforcement": self.enforcement,
        }


def exec_report(resolved: ResolvedProfile, outcomes: Sequence[AttemptOutcome]) -> dict[str, Any]:
    """Run-level execution facts with enforcement derived from outcomes.

    Every isolation control fails closed to INFRA_FAILURE (quota
    teardown, containment setup, seccomp install), so an isolation
    profile verifies exactly when no attempt reports INFRA_FAILURE.
    "Verified" therefore means every setup/teardown operation completed
    without detected failure — not independent post-hoc proof of each
    mechanism (only quota limits are re-read after the fact).
    Standard claims nothing regardless of outcomes.
    """
    info = resolved.report()
    if resolved.requested == STANDARD:
        return info
    clean = all(outcome is not AttemptOutcome.INFRA_FAILURE for outcome in outcomes)
    info["enforcement"] = ENFORCEMENT_VERIFIED if clean else ENFORCEMENT_UNVERIFIED
    return info


def quota_settings(profile: str) -> dict[str, str]:
    """Stable quota config for the digest; values from QuotaLimits only.

    Hardened binds the effective static values; other profiles bind an
    explicit off marker and claim no enforcement. Host-conditional facts
    (e.g. whether swap exists) stay out: the swap entry names the static
    policy, and runtime observations belong in per-attempt evidence.
    """
    if profile != HARDENED:
        return {"quota.enforced": "off"}
    from attest_core.scopes import QuotaLimits

    limits = QuotaLimits()
    return {
        "quota.enforced": "on",
        "quota.memory_max": str(limits.memory_max),
        "quota.tasks_max": str(limits.tasks_max),
        "quota.cpu_percent": str(limits.cpu_percent),
        "quota.swap": "disabled-where-present",
    }


def preflight_exec_profile(name: str) -> ResolvedProfile:
    """Resolve a profile name or raise :class:`ExecProfileError`.

    Unknown names and missing capabilities are refused before the first
    attempt. Only the requested profile's capabilities are probed, so
    standard never spawns quota scopes and contained never pays for the
    quota probe.
    """
    if name not in _FLAGS:
        raise ExecProfileError(f"unknown execution profile: {name!r}")
    capabilities: dict[str, bool] = {}
    for capability in _NEEDS[name]:
        available = _PROBES[capability]()
        capabilities[capability] = available
        if not available:
            raise ExecProfileError(
                f"execution profile {name!r} needs {capability}, which is unavailable"
            )
    if name == HARDENED and not PRODUCTION_QUOTAS:
        raise ExecProfileError(
            "execution profile 'hardened' needs production quotas (Stage 2: not yet available)"
        )
    flags = _FLAGS[name]
    enforcement = ENFORCEMENT_NONE if name == STANDARD else ENFORCEMENT_UNVERIFIED
    return ResolvedProfile(
        requested=name,
        contained=flags["contained"],
        quotas=flags["quotas"],
        seccomp=flags["seccomp"],
        capabilities=capabilities,
        enforcement=enforcement,
    )
