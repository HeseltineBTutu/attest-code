"""F3 series decomposition, warm-up declarations, and prefix (W1, W3)."""

from __future__ import annotations

from typing import Any

from f3_identity_pkg import INVOCATION_1, INVOCATION_2, TRIPLE
from f3_series_pkg import INVOCATION_3, camp, invocation, notes, package, triples

from attest_core.f3_identity import PackageRecords
from attest_core.f3_series import compute_series, display_key
from attest_core.f3_series_check import check_package_series

DIGEST2 = "ff" * 32
TRIPLE2 = (TRIPLE[0], TRIPLE[1], DIGEST2)


def _full(inv: str, sample: str, **kwargs: Any) -> tuple[list[Any], Any, Any]:
    return invocation(inv, sample=sample, **kwargs)


def test_valid_series_package() -> None:
    campaign = camp([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")], warmups=[1])
    report = check_package_series(
        package(campaign, _full(INVOCATION_1, "warmup"), _full(INVOCATION_2, "measured"))
    )
    assert report.ok is True
    assert report.severity == "VALID"
    assert len(report.series) == 1
    key = report.series[0].key
    assert key == ("repaired", *TRIPLE, 1)
    assert display_key(key) == "repaired/b1"
    assert [m.relative for m in report.series[0].members] == [1, 2]


def test_split_on_target_change() -> None:
    campaign = camp(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        entry_targets={INVOCATION_2: "baseline"},
        targets=["repaired", "baseline"],
    )
    (first, second) = compute_series(campaign)
    assert (first.ordinal, second.ordinal) == (1, 2)
    assert first.key[0] == "repaired" and second.key[0] == "baseline"


def test_split_on_workload_change() -> None:
    campaign = camp(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        triples={INVOCATION_2: TRIPLE2},
    )
    assert len(compute_series(campaign)) == 2


def test_noncontiguous_target_splits() -> None:
    campaign = camp(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured"), (INVOCATION_3, "measured")],
        entry_targets={INVOCATION_2: "baseline"},
        targets=["repaired", "baseline"],
    )
    series = compute_series(campaign)
    assert [s.ordinal for s in series] == [1, 2, 3]
    assert series[0].key != series[2].key  # Same target, distinct series.


def test_gap_breaks_run() -> None:
    campaign = camp([(INVOCATION_1, "measured"), (INVOCATION_2, "measured")], sequences=[1, 3])
    assert len(compute_series(campaign)) == 2


def test_decomposition_order_independent() -> None:
    fwd = camp([(INVOCATION_1, "measured"), (INVOCATION_2, "measured")])
    back = camp([(INVOCATION_2, "measured"), (INVOCATION_1, "measured")], sequences=[2, 1])

    def partition(campaign):  # type: ignore[no-untyped-def]
        return [
            (s.key, [(m.run_sequence, m.invocation_id) for m in s.members])
            for s in compute_series(campaign)
        ]

    assert partition(fwd) == partition(back)


def test_w1_protocol_mismatch() -> None:
    campaign = camp([(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")], warmups=[1, 2])
    report = check_package_series(package(campaign))
    assert ("INVALID", "W1", "$.campaign.protocol.warmup_invocations") in triples(report)
    campaign2 = camp([(INVOCATION_1, "warmup")], warmups=[])
    report2 = check_package_series(package(campaign2))
    assert ("INVALID", "W1", "$.campaign.invocations[0]") in triples(report2)
    campaign3 = camp([(INVOCATION_1, "measured")], warmups=[9])
    report3 = check_package_series(package(campaign3))
    assert ("INVALID", "W1", "$.campaign.protocol.warmup_invocations") in triples(report3)


def test_w3_prefix_violation() -> None:
    campaign = camp([(INVOCATION_1, "measured"), (INVOCATION_2, "warmup")], warmups=[2])
    report = check_package_series(
        package(campaign, _full(INVOCATION_1, "measured"), _full(INVOCATION_2, "warmup"))
    )
    assert ("INVALID", "W3", "$.campaign.invocations[1]") in triples(report)


def test_w3_empty_and_full_prefix_ok() -> None:
    measured_only = camp([(INVOCATION_1, "measured")], warmups=[])
    assert check_package_series(package(measured_only)).ok is True
    warmup_only = camp([(INVOCATION_1, "warmup")], warmups=[1])
    assert check_package_series(package(warmup_only)).ok is True


def test_w3_prefix_per_series() -> None:
    """A later series restarts its own prefix; no cross-series pooling."""
    campaign = camp(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "warmup"), (INVOCATION_3, "measured")],
        warmups=[2],
        triples={INVOCATION_2: TRIPLE2, INVOCATION_3: TRIPLE2},
    )
    groups = (
        _full(INVOCATION_1, "measured"),
        _full(INVOCATION_2, "warmup", triple=TRIPLE2),
        _full(INVOCATION_3, "measured", triple=TRIPLE2),
    )
    report = check_package_series(package(campaign, *groups))
    assert report.ok is True
    assert len(report.series) == 2
    assert notes(report) == []


def test_no_campaign_empty_report() -> None:
    report = check_package_series(PackageRecords())
    assert (report.series, report.findings, report.diagnostics) == ((), (), ())
    assert report.ok is True
