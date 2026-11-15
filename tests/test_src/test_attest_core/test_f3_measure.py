"""F3 measurement classification (M1) and M2 opacity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from f3_identity_pkg import INVOCATION_1, attempt, total

from attest_core.f3_measure import (
    MEASUREMENT_CLEAN,
    MEASUREMENT_INCONCLUSIVE,
    MEASUREMENT_VIOLATION,
    classify_measurement,
    measure_invocation,
)


def _attempts(specs: list[tuple[int, str, bool]]) -> list[Any]:
    return [attempt(INVOCATION_1, n, outcome=o, censored=c) for n, o, c in specs]


def test_clean() -> None:
    made = _attempts([(1, "PASS", False), (2, "PASS", False), (3, "PASS", False)])
    assert classify_measurement(total(INVOCATION_1), made) == MEASUREMENT_CLEAN


def test_violation() -> None:
    made = _attempts([(1, "VIOLATION", False), (2, "VIOLATION", False), (3, "VIOLATION", False)])
    assert classify_measurement(total(INVOCATION_1), made) == MEASUREMENT_VIOLATION


def test_inconclusive_shapes() -> None:
    mixed = _attempts([(1, "PASS", False), (2, "VIOLATION", False), (3, "PASS", False)])
    assert classify_measurement(total(INVOCATION_1), mixed) == MEASUREMENT_INCONCLUSIVE
    infra = _attempts([(1, "PASS", False), (2, "INFRA_FAILURE", False), (3, "PASS", False)])
    assert classify_measurement(total(INVOCATION_1), infra) == MEASUREMENT_INCONCLUSIVE
    timeout = _attempts([(1, "PASS", False), (2, "TIMEOUT", False), (3, "PASS", False)])
    assert classify_measurement(total(INVOCATION_1), timeout) == MEASUREMENT_INCONCLUSIVE
    censored = _attempts([(1, "PASS", True), (2, "PASS", False), (3, "PASS", False)])
    assert classify_measurement(total(INVOCATION_1), censored) == MEASUREMENT_INCONCLUSIVE


def test_incomplete_sets_unclassified() -> None:
    made = _attempts([(1, "PASS", False), (2, "PASS", False)])
    assert classify_measurement(total(INVOCATION_1), made) is None
    full = _attempts([(1, "PASS", False), (2, "PASS", False), (3, "PASS", False)])
    assert classify_measurement(None, full) is None
    assert classify_measurement(total(INVOCATION_1), []) is None
    dup = _attempts([(1, "PASS", False), (1, "PASS", False), (2, "PASS", False)])
    assert classify_measurement(total(INVOCATION_1), dup) is None
    outside = _attempts([(1, "PASS", False), (2, "PASS", False), (4, "PASS", False)])
    assert classify_measurement(total(INVOCATION_1), outside) is None


def test_measure_invocation() -> None:
    made = _attempts([(1, "PASS", False), (2, "PASS", False), (3, "PASS", False)])
    seen = measure_invocation(INVOCATION_1, made, [total(INVOCATION_1)], 1)
    assert (seen.complete, seen.m1) == (True, MEASUREMENT_CLEAN)
    assert measure_invocation(INVOCATION_1, made, [total(INVOCATION_1)], 0).complete is False
    assert measure_invocation(INVOCATION_1, made, [], 1).m1 is None
    short = _attempts([(1, "PASS", False)])
    assert measure_invocation(INVOCATION_1, short, [total(INVOCATION_1)], 1).complete is False


def test_outputs_never_verifier_labels() -> None:
    for label in (MEASUREMENT_CLEAN, MEASUREMENT_VIOLATION, MEASUREMENT_INCONCLUSIVE):
        assert label not in ("PASSED", "FAILED", "INCONCLUSIVE")
        assert label.startswith("MEASUREMENT_")


def test_stored_verdict_never_read() -> None:
    """M2: a FAILED total with PASS attempts still classifies CLEAN."""
    made = _attempts([(1, "PASS", False), (2, "PASS", False), (3, "PASS", False)])
    failed_total = total(INVOCATION_1, verdict="FAILED")
    assert classify_measurement(failed_total, made) == MEASUREMENT_CLEAN


def test_p6_sources_avoid_verdict_authority() -> None:
    """M1/M2 boundary: no verdict reads, no verifier classifier imports."""
    root = Path(__file__).resolve().parents[3] / "src" / "attest_core"
    for name in ("f3_measure.py", "f3_quorum.py", "f3_compare.py", "f3_compare_attrs.py"):
        source = (root / name).read_text()
        assert ".verdict" not in source
        assert "attest_core.verdicts" not in source
        assert "classify_with_reason" not in source
