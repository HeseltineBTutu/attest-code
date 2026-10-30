"""Execution-profile contract: mapping, preflight, digest binding (Stage 1)."""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

import pytest

from apps.verify import _settings
from attest_core import exec_profile as ep
from attest_core import scopes
from attest_core.evidence import canonical_bytes, sha256_hex
from attest_core.exec_profile import ExecProfileError, exec_report, preflight_exec_profile
from attest_spec import AttemptOutcome


def _boom() -> bool:
    raise AssertionError("probe must not run for this profile")


def _digest(profile: str) -> str:
    settings = _settings(
        target="repaired",
        scope=("/admin/users",),
        snapshot="abc",
        snapshot_digest="def",
        timeout_seconds=60.0,
        runtime={},
        profile=profile,
    )
    return sha256_hex(canonical_bytes(settings))


def test_standard_needs_no_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("containment", "quotas", "seccomp"):
        monkeypatch.setitem(ep._PROBES, name, _boom)
    resolved = preflight_exec_profile("standard")
    assert (resolved.contained, resolved.quotas, resolved.seccomp) == (False, False, False)
    assert resolved.capabilities == {}
    assert resolved.enforcement == ep.ENFORCEMENT_NONE


def test_unknown_profile_rejected() -> None:
    with pytest.raises(ExecProfileError, match="unknown execution profile"):
        preflight_exec_profile("fortress")


def test_contained_success_skips_quota_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(ep._PROBES, "containment", lambda: True)
    monkeypatch.setitem(ep._PROBES, "quotas", _boom)
    monkeypatch.setitem(ep._PROBES, "seccomp", _boom)
    resolved = preflight_exec_profile("contained")
    assert (resolved.contained, resolved.quotas, resolved.seccomp) == (True, False, False)
    assert resolved.capabilities == {"containment": True}
    assert resolved.enforcement == ep.ENFORCEMENT_UNVERIFIED


def test_contained_missing_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(ep._PROBES, "containment", lambda: False)
    with pytest.raises(ExecProfileError, match="containment"):
        preflight_exec_profile("contained")


def test_hardened_resolves_all_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("containment", "quotas", "seccomp"):
        monkeypatch.setitem(ep._PROBES, name, lambda: True)
    resolved = preflight_exec_profile("hardened")
    assert (resolved.contained, resolved.quotas, resolved.seccomp) == (True, True, True)
    assert resolved.flags() == {"contained": True, "quotas": True, "seccomp": True}
    assert resolved.capabilities == {"containment": True, "quotas": True, "seccomp": True}


def test_hardened_missing_quotas_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(ep._PROBES, "containment", lambda: True)
    monkeypatch.setitem(ep._PROBES, "quotas", lambda: False)
    monkeypatch.setitem(ep._PROBES, "seccomp", lambda: True)
    with pytest.raises(ExecProfileError, match="quotas"):
        preflight_exec_profile("hardened")


def test_hardened_missing_seccomp_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(ep._PROBES, "containment", lambda: True)
    monkeypatch.setitem(ep._PROBES, "quotas", lambda: True)
    monkeypatch.setitem(ep._PROBES, "seccomp", lambda: False)
    with pytest.raises(ExecProfileError, match="seccomp"):
        preflight_exec_profile("hardened")


def test_flags_match_profile_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("containment", "quotas", "seccomp"):
        monkeypatch.setitem(ep._PROBES, name, lambda: True)
    assert preflight_exec_profile("standard").flags() == {
        "contained": False,
        "quotas": False,
        "seccomp": False,
    }
    assert preflight_exec_profile("contained").flags() == {
        "contained": True,
        "quotas": False,
        "seccomp": False,
    }


def test_report_distinguishes_requested_actual() -> None:
    resolved = preflight_exec_profile("standard")
    report: dict[str, Any] = resolved.report()
    assert report["requested"] == "standard"
    assert report["selected"] == "standard"
    assert report["actual"] == {"contained": False, "quotas": False, "seccomp": False}
    assert report["capabilities"] == {}
    assert report["enforcement"] == ep.ENFORCEMENT_NONE


def test_digest_differs_across_profiles() -> None:
    assert _digest("standard") != _digest("contained")
    assert _digest("contained") != _digest("hardened")


def test_digest_stable_same_profile() -> None:
    assert _digest("contained") == _digest("contained")


def test_quota_settings_hardened_binds_values() -> None:
    settings = ep.quota_settings("hardened")
    assert settings["quota.enforced"] == "on"
    assert settings["quota.memory_max"] == str(scopes.QuotaLimits().memory_max)
    assert settings["quota.tasks_max"] == str(scopes.QuotaLimits().tasks_max)
    assert settings["quota.cpu_percent"] == str(scopes.QuotaLimits().cpu_percent)
    assert settings["quota.swap"] == "disabled-where-present"


def test_quota_settings_off_for_other_profiles() -> None:
    assert ep.quota_settings("standard") == {"quota.enforced": "off"}
    assert ep.quota_settings("contained") == {"quota.enforced": "off"}


def test_quota_value_change_changes_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    before = _digest("hardened")
    monkeypatch.setattr(
        scopes, "QuotaLimits", lambda: SimpleNamespace(memory_max=1, tasks_max=2, cpu_percent=3)
    )
    assert ep.quota_settings("hardened")["quota.memory_max"] == "1"
    assert _digest("hardened") != before


def test_seccomp_unavailable_on_unknown_arch(monkeypatch: pytest.MonkeyPatch) -> None:
    import attest_core.seccomp as seccomp_mod
    from attest_core.ns_setup import RunnerError

    def _raise() -> Any:
        raise RunnerError("nope")

    monkeypatch.setattr(seccomp_mod, "_arch_config", _raise)
    assert seccomp_mod.supports_seccomp() is False


@pytest.mark.skipif(os.uname().machine not in ("x86_64", "aarch64"), reason="seccomp hosts only")
def test_seccomp_available_live() -> None:
    import attest_core.seccomp as seccomp_mod

    assert seccomp_mod.supports_seccomp() is True


def test_exec_report_hardened_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("containment", "quotas", "seccomp"):
        monkeypatch.setitem(ep._PROBES, name, lambda: True)
    resolved = preflight_exec_profile("hardened")
    info = exec_report(resolved, [AttemptOutcome.PASS] * 3)
    assert info["enforcement"] == ep.ENFORCEMENT_VERIFIED


def test_exec_report_hardened_unverified_on_infra(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("containment", "quotas", "seccomp"):
        monkeypatch.setitem(ep._PROBES, name, lambda: True)
    resolved = preflight_exec_profile("hardened")
    mixed = [AttemptOutcome.PASS, AttemptOutcome.INFRA_FAILURE, AttemptOutcome.PASS]
    info = exec_report(resolved, mixed)
    assert info["enforcement"] == ep.ENFORCEMENT_UNVERIFIED


def test_exec_report_standard_claims_nothing() -> None:
    resolved = preflight_exec_profile("standard")
    info = exec_report(resolved, [AttemptOutcome.PASS] * 3)
    assert info["enforcement"] == ep.ENFORCEMENT_NONE


def test_exec_report_contained_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(ep._PROBES, "containment", lambda: True)
    resolved = preflight_exec_profile("contained")
    info = exec_report(resolved, [AttemptOutcome.PASS] * 3)
    assert info["enforcement"] == ep.ENFORCEMENT_VERIFIED
