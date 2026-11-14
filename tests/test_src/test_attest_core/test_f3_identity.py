"""F3 identity roots: declarations, uniqueness, binding, filename opacity."""

from __future__ import annotations

import inspect
from typing import Any

from f3_identity_pkg import (
    CAMPAIGN_ID,
    INVOCATION_1,
    INVOCATION_2,
    attempt,
    campaign,
    entry,
    env,
    issues,
    total,
    valid_package,
    view,
)

from attest_core.f3_identity import check_identity, check_manifest_binding


def test_valid_package() -> None:
    report = check_identity(valid_package())
    assert report.ok is True
    assert report.severity == "VALID"
    assert report.findings == ()


def test_missing_campaign() -> None:
    made = [attempt(INVOCATION_1, n) for n in (1, 2, 3)]
    report = check_identity(view(None, attempts=made, totals=[total()], envs=[env()]))
    assert report.severity == "INCOMPLETE"
    assert issues(report) == [("INCOMPLETE", "V-B2", "$.campaign")]


def test_duplicate_campaign() -> None:
    report = check_identity(view([campaign(), campaign()]))
    assert report.severity == "INVALID"
    assert issues(report) == [("INVALID", "R-ID2", "campaign[1]")]


def test_duplicate_record_id() -> None:
    first = attempt(INVOCATION_1, 1)
    twin = attempt(INVOCATION_1, 2, record_id=first.record_id)
    report = check_identity(view(campaign(), attempts=[first, twin]))
    assert ("INVALID", "R-ID1", "attempt[1]") in issues(report)
    assert "attempt[0]" in report.findings[0].reason


def test_cross_kind_duplicate_record_id() -> None:
    made = attempt(INVOCATION_1, 1)
    tot = total(INVOCATION_1, record_id=made.record_id)
    report = check_identity(view(campaign(), attempts=[made], totals=[tot]))
    assert ("INVALID", "R-ID1", "total[0]") in issues(report)


def test_duplicate_invocation_declaration() -> None:
    camp = campaign([entry(INVOCATION_1, 1), entry(INVOCATION_1, 2)])
    report = check_identity(view(camp))
    assert report.severity == "INVALID"
    assert ("INVALID", "R-ID2", "$.campaign.invocations[1]") in issues(report)


def test_run_sequence_gap() -> None:
    camp = campaign([entry(INVOCATION_1, 1), entry(INVOCATION_2, 3)])
    report = check_identity(view(camp))
    assert ("INVALID", "R-ID3", "$.campaign.invocations") in issues(report)
    assert "want [1, 2], found [1, 3]" in report.findings[0].reason


def test_run_sequence_duplicate() -> None:
    camp = campaign([entry(INVOCATION_1, 1), entry(INVOCATION_2, 1)])
    report = check_identity(view(camp))
    assert ("INVALID", "R-ID3", "$.campaign.invocations") in issues(report)


def test_entry_target_undeclared() -> None:
    camp = campaign([entry(INVOCATION_1, 1, target="ghost")])
    report = check_identity(view(camp))
    assert ("INVALID", "R-ID9", "$.campaign.invocations[0]") in issues(report)


def test_engine_drift() -> None:
    report = check_identity(view(campaign(protocol_n=5)))
    assert report.severity == "INVALID"
    assert ("INVALID", "V-B8", "$.campaign.protocol.attempts_per_invocation") in issues(report)
    assert "engine drift" in report.findings[0].reason


def test_manifest_binding() -> None:
    made = attempt(INVOCATION_1, 1)
    good = {
        "record_id": made.record_id,
        "kind": "attempt",
        "invocation_id": INVOCATION_1,
    }
    assert check_manifest_binding([(0, good, made)]) == ()
    assert check_manifest_binding([(0, good, None)]) == ()
    bad_id = dict(good, record_id=CAMPAIGN_ID)
    (finding,) = check_manifest_binding([(3, bad_id, made)])
    assert (finding.severity, finding.rule, finding.location) == (
        "INVALID",
        "V-B1",
        "$.records[3]",
    )
    bad_kind = dict(good, kind="environment")
    (finding,) = check_manifest_binding([(0, bad_kind, made)])
    assert finding.rule == "V-B1"
    bad_inv = dict(good, invocation_id=INVOCATION_2)
    (finding,) = check_manifest_binding([(0, bad_inv, made)])
    assert finding.rule == "V-B1"
    (finding,) = check_manifest_binding([(0, ["not", "an", "object"], made)])
    assert (finding.severity, finding.rule) == ("INVALID", "V-B6")


def test_campaign_binding_null_invocation() -> None:
    camp = campaign()
    entry_map: dict[str, Any] = {
        "record_id": camp.record_id,
        "kind": "campaign",
        "invocation_id": None,
    }
    assert check_manifest_binding([(0, entry_map, camp)]) == ()


def test_filenames_cannot_create_identity() -> None:
    """R-ID10: the P3 interface takes no path input, so stems cannot matter."""
    params = set(inspect.signature(check_identity).parameters)
    assert params == {"package"}
    fields = set(view(campaign()).__dataclass_fields__)
    assert not (fields & {"relpath", "path", "filename", "stem"})
    pkg = valid_package()
    assert pkg.attempts[0].target == "repaired"
    assert check_identity(pkg).ok is True
