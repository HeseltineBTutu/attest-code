"""F3 machine-class consistency and diagnostics (W4)."""

from __future__ import annotations

from typing import Any

from f3_identity_pkg import INVOCATION_1, INVOCATION_2
from f3_series_pkg import INVOCATION_3, MARK, camp, invocation, notes, package, triples

from attest_core.f3_machine import machine_class, normalize_cpu
from attest_core.f3_series_check import check_package_series

CPU = "AMD EPYC 7763"
MEM = 17179869184


def _env(inv: str, **overrides: Any) -> Any:
    return invocation(inv, env_overrides=overrides)[2]


def _run(specs: list[tuple[str, str]], warmups: list[int], *envs: Any) -> Any:
    campaign = camp(specs, warmups=warmups)
    groups = []
    for (inv, sample), environment in zip(specs, envs, strict=True):
        made, tot, _ = invocation(inv, sample=sample)
        groups.append((made, tot, environment))
    return check_package_series(package(campaign, *groups))


def test_normalize_and_class() -> None:
    assert normalize_cpu("  AMD   EPYC\t7763  ") == "AMD EPYC 7763"
    assert machine_class(_env(INVOCATION_1)) == (CPU, MEM)
    assert machine_class(_env(INVOCATION_1, cpu_model=MARK)) is None
    assert machine_class(_env(INVOCATION_1, memory_total_bytes=MARK)) is None


def test_same_class_clean() -> None:
    report = _run(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2),
    )
    assert report.ok is True
    assert notes(report) == []


def test_cpu_mismatch_invalid() -> None:
    report = _run(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2, cpu_model="Intel Xeon 8480"),
    )
    assert ("INVALID", "W4", "env[1]") in triples(report)
    assert "cpu_model" in report.findings[0].reason
    assert INVOCATION_1 in report.findings[0].reason


def test_memory_mismatch_invalid() -> None:
    report = _run(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2, memory_total_bytes=8589934592),
    )
    assert ("INVALID", "W4", "env[1]") in triples(report)
    assert "memory_total_bytes" in report.findings[0].reason


def test_whitespace_variants_equal() -> None:
    report = _run(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2, cpu_model="  AMD   EPYC 7763 "),
    )
    assert report.ok is True


def test_unknown_class_diagnostic() -> None:
    report = _run(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2, cpu_model=MARK, memory_total_bytes=MARK),
    )
    assert report.ok is True
    assert report.severity == "VALID"
    assert ("W4", "env[1]") in notes(report)
    assert "cpu_model" in report.diagnostics[0].reason


def test_unknown_plus_known_mismatch() -> None:
    report = _run(
        [
            (INVOCATION_1, "measured"),
            (INVOCATION_2, "measured"),
            (INVOCATION_3, "measured"),
        ],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2, cpu_model="Intel Xeon 8480"),
        _env(INVOCATION_3, cpu_model=MARK),
    )
    kinds = triples(report)
    assert ("INVALID", "W4", "env[1]") in kinds
    assert ("W4", "env[2]") in notes(report)


def test_envelope_notes() -> None:
    limited = {"limited": True, "memory_max_bytes": 4294967296}
    report = _run(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2, cgroup_limits=limited),
    )
    assert report.ok is True
    assert ("W4", "env[1]") in notes(report)
    report2 = _run(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2, cgroup_limits=MARK),
    )
    assert ("W4", "env[1]") in notes(report2)


def test_count_mismatch_note() -> None:
    report = _run(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        [],
        _env(INVOCATION_1),
        _env(INVOCATION_2, logical_processor_count=16),
    )
    assert report.ok is True
    assert ("W4", "env[1]") in notes(report)


def test_missing_and_multiple_envs_skipped() -> None:
    campaign = camp([(INVOCATION_1, "measured"), (INVOCATION_2, "measured")], warmups=[])
    made1, tot1, _ = invocation(INVOCATION_1)
    report = check_package_series(package(campaign, (made1, tot1, _env(INVOCATION_1))))
    assert report.ok is True
    dup = package(campaign, (made1, tot1, _env(INVOCATION_1)))
    assert check_package_series(dup).ok is True


def test_classes_compared_per_series() -> None:
    campaign = camp(
        [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")],
        entry_targets={INVOCATION_2: "baseline"},
        targets=["repaired", "baseline"],
    )
    made1, tot1, _ = invocation(INVOCATION_1)
    made2, tot2, _ = invocation(INVOCATION_2, target="baseline")
    report = check_package_series(
        package(
            campaign,
            (made1, tot1, _env(INVOCATION_1)),
            (made2, tot2, _env(INVOCATION_2, cpu_model="Intel Xeon 8480")),
        )
    )
    assert report.ok is True
