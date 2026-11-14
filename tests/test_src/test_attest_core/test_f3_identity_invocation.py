"""F3 per-invocation identity: membership, cardinality, attempts, echoes."""

from __future__ import annotations

from typing import Any

from f3_identity_pkg import (
    DIGEST,
    INVOCATION_1,
    INVOCATION_2,
    TRIPLE,
    attempt,
    campaign,
    entry,
    env,
    issues,
    total,
    view,
)

from attest_core.f3_identity import check_identity

WHERE = "$.campaign.invocations[0]"


def _full(*numbers: int) -> tuple[list[Any], Any, Any]:
    made = [attempt(INVOCATION_1, n) for n in numbers]
    return made, total(INVOCATION_1), env(INVOCATION_1)


def test_undeclared_invocation() -> None:
    stray = attempt(INVOCATION_2, 1)
    report = check_identity(view(campaign(), attempts=[stray]))
    assert ("INVALID", "V-B2", "attempt[0]") in issues(report)


def test_campaign_echo_mismatch() -> None:
    made = attempt(INVOCATION_1, 1, campaign_id=INVOCATION_2)
    report = check_identity(view(campaign(), attempts=[made]))
    assert ("INVALID", "V-B2", "attempt[0]") in issues(report)


def test_missing_total_and_env() -> None:
    made = [attempt(INVOCATION_1, n) for n in (1, 2, 3)]
    report = check_identity(view(campaign(), attempts=made))
    assert issues(report) == [
        ("INCOMPLETE", "V-B10", WHERE),
        ("INCOMPLETE", "V-B10", WHERE),
        ("INCOMPLETE", "V-B7", WHERE),
    ]


def test_zero_record_invocation() -> None:
    report = check_identity(view(campaign()))
    assert issues(report) == [("INCOMPLETE", "V-B10", WHERE)]
    assert "no records" in report.findings[0].reason


def test_duplicate_total() -> None:
    made, tot, environment = _full(1, 2, 3)
    report = check_identity(
        view(campaign(), attempts=made, totals=[tot, total()], envs=[environment])
    )
    assert ("INVALID", "V-B10", "total[1]") in issues(report)


def test_duplicate_env() -> None:
    made, tot, environment = _full(1, 2, 3)
    report = check_identity(
        view(campaign(), attempts=made, totals=[tot], envs=[environment, env()])
    )
    assert ("INVALID", "V-B10", "env[1]") in issues(report)


def test_attempt_112() -> None:
    made, tot, environment = _full(1, 1, 2)
    report = check_identity(view(campaign(), attempts=made, totals=[tot], envs=[environment]))
    assert report.severity == "INVALID"
    kinds = issues(report)
    assert ("INVALID", "V-B11", "attempt[1]") in kinds
    assert ("INCOMPLETE", "V-B11", WHERE) in kinds


def test_attempt_124() -> None:
    made, tot, environment = _full(1, 2, 4)
    report = check_identity(view(campaign(), attempts=made, totals=[tot], envs=[environment]))
    assert ("INVALID", "V-B11", WHERE) in issues(report)
    assert "outside declared 1..3" in report.findings[-1].reason


def test_consistent_prefix_is_incomplete() -> None:
    made, tot, environment = _full(1, 2)
    report = check_identity(view(campaign(), attempts=made, totals=[tot], envs=[environment]))
    assert report.severity == "INCOMPLETE"
    assert ("INCOMPLETE", "V-B11", WHERE) in issues(report)
    assert "missing numbers [3]" in str([item.reason for item in report.findings])


def test_gapped_attempts_are_invalid() -> None:
    made, tot, environment = _full(1, 3)
    report = check_identity(view(campaign(), attempts=made, totals=[tot], envs=[environment]))
    assert report.severity == "INVALID"
    assert ("INVALID", "V-B11", WHERE) in issues(report)


def test_target_disagreement() -> None:
    camp = campaign(targets=["repaired", "baseline"])
    first = attempt(INVOCATION_1, 1, target="baseline")
    rest = [attempt(INVOCATION_1, n) for n in (2, 3)]
    report = check_identity(view(camp, attempts=[first, *rest], totals=[total()], envs=[env()]))
    kinds = issues(report)
    assert ("INVALID", "R-ID9", WHERE) in kinds
    assert ("INVALID", "R-ID9", "attempt[0]") in kinds


def test_record_target_undeclared() -> None:
    made = attempt(INVOCATION_1, 1, target="ghost")
    report = check_identity(view(campaign(), attempts=[made]))
    assert ("INVALID", "R-ID9", "attempt[0]") in issues(report)


def test_workload_disagreement() -> None:
    first = attempt(INVOCATION_1, 1, workload_id="other-workload-002")
    rest = [attempt(INVOCATION_1, n) for n in (2, 3)]
    report = check_identity(
        view(campaign(), attempts=[first, *rest], totals=[total()], envs=[env()])
    )
    kinds = issues(report)
    assert ("INVALID", "R-ID11", WHERE) in kinds
    assert ("INVALID", "R-ID11", "attempt[0]") in kinds


def test_workload_entry_mismatch() -> None:
    other = ("Medium", "auth-admin-001", "ff" * 32)
    camp = campaign([entry(INVOCATION_1, 1, triple=other)])
    made, tot, environment = _full(1, 2, 3)
    report = check_identity(view(camp, attempts=made, totals=[tot], envs=[environment]))
    assert ("INVALID", "R-ID11", "attempt[0]") in issues(report)
    assert ("INVALID", "R-ID11", WHERE) not in issues(report)


def test_sample_class_echo() -> None:
    camp = campaign([entry(INVOCATION_1, 1, sample_class="warmup")])
    made, tot, environment = _full(1, 2, 3)
    report = check_identity(view(camp, attempts=made, totals=[tot], envs=[environment]))
    assert ("INVALID", "W1", "attempt[0]") in issues(report)


def test_input_manifest_content_left_to_p4() -> None:
    """A V-B13-violating manifest (unsorted entries) is still P3-VALID."""
    files = [
        {"kind": "file", "relpath": f"inputs/{name}.yaml", "size_bytes": 8, "sha256": DIGEST}
        for name in ("b-second", "a-first")
    ]
    manifest = {"manifest_version": 1, "entries": files}
    triple = (TRIPLE[0], TRIPLE[1], DIGEST)
    camp = campaign([entry(INVOCATION_1, 1, triple=triple, manifest=manifest)])
    made, tot, environment = _full(1, 2, 3)
    report = check_identity(view(camp, attempts=made, totals=[tot], envs=[environment]))
    assert report.ok is True


def test_target_workload_independence() -> None:
    """R-ID9: coinciding target/workload strings are never equated."""
    camp = campaign(
        [entry(INVOCATION_1, 1, target="same", triple=("Medium", "same", DIGEST))],
        targets=["same"],
    )
    made = [attempt(INVOCATION_1, n, target="same", workload_id="same") for n in (1, 2, 3)]
    report = check_identity(
        view(
            camp,
            attempts=made,
            totals=[total(INVOCATION_1, target="same", workload_id="same")],
            envs=[env(INVOCATION_1, target="same", workload_id="same")],
        )
    )
    assert report.ok is True
