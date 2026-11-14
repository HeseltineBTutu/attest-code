"""F3 warm-up/measured configuration match (W2)."""

from __future__ import annotations

from typing import Any

from f3_identity_pkg import INVOCATION_1, INVOCATION_2, attempt, env, total
from f3_series_pkg import MARK, camp, invocation, package, triples

from attest_core.f3_series_check import check_package_series

DIGEST = "ab" * 32


def _pair(warm: dict[str, Any], measured: dict[str, Any]) -> Any:
    """One warm-up and one measured invocation with per-side overrides."""
    campaign = camp([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")], warmups=[1])
    first = invocation(INVOCATION_1, sample="warmup", **warm)
    second = invocation(INVOCATION_2, sample="measured", **measured)
    return check_package_series(package(campaign, first, second))


def test_matching_config_clean() -> None:
    assert _pair({}, {}).ok is True


def test_profile_mismatch() -> None:
    report = _pair({"profile": "standard"}, {})
    assert ("INVALID", "W2", "$.campaign.invocations[0]") in triples(report)
    assert "profile" in report.findings[0].reason
    assert INVOCATION_1 in report.findings[0].reason
    assert INVOCATION_2 in report.findings[0].reason


def test_timeout_mismatch() -> None:
    report = _pair({"timeout": "30.000000000"}, {})
    assert ("INVALID", "W2", "$.campaign.invocations[0]") in triples(report)
    assert "timeout_s" in report.findings[0].reason


def test_revision_mismatch() -> None:
    report = _pair({"env_overrides": {"git_revision": "ee" * 20}}, {})
    assert ("INVALID", "W2", "$.campaign.invocations[0]") in triples(report)
    assert "git_revision" in report.findings[0].reason


def test_lock_digest_mismatch() -> None:
    report = _pair({"env_overrides": {"pyproject_digest": "ff" * 32}}, {})
    assert ("INVALID", "W2", "$.campaign.invocations[0]") in triples(report)
    assert "pyproject_digest" in report.findings[0].reason


def test_within_invocation_profile_split() -> None:
    made = [
        attempt(INVOCATION_1, 1, profile="standard"),
        attempt(INVOCATION_1, 2, profile="hardened"),
    ]
    campaign = camp([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")], warmups=[1])
    group1 = (made, total(INVOCATION_1), env(INVOCATION_1))
    group2 = invocation(INVOCATION_2, sample="measured")
    report = check_package_series(package(campaign, group1, group2))
    assert ("INVALID", "W2", "attempt[1]") in triples(report)


def test_marker_against_value_mismatches() -> None:
    report = _pair({"env_overrides": {"git_revision": MARK}}, {})
    assert ("INVALID", "W2", "$.campaign.invocations[0]") in triples(report)


def test_identical_markers_match() -> None:
    report = _pair(
        {"env_overrides": {"git_revision": MARK}},
        {"env_overrides": {"git_revision": MARK}},
    )
    assert report.ok is True


def test_single_class_vacuous() -> None:
    campaign = camp([(INVOCATION_1, "measured"), (INVOCATION_2, "measured")], warmups=[])
    first = invocation(INVOCATION_1, profile="standard")
    second = invocation(INVOCATION_2, profile="hardened")
    report = check_package_series(package(campaign, first, second))
    assert report.ok is True


def test_missing_records_skipped() -> None:
    campaign = camp([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")], warmups=[1])
    report = check_package_series(package(campaign))
    assert report.ok is True


def test_env_profile_ignored() -> None:
    """W2 reads profile from attempt records only (design letter)."""
    report = _pair({"env_overrides": {"profile": "standard"}}, {})
    assert report.ok is True
