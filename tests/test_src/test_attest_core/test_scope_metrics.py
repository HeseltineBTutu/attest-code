"""Scope metrics: peak readers, teardown marks, resources parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from attest_core import scope_metrics, scopes
from attest_core.invariants import create_approval
from attest_core.resource_evidence import (
    collect_resources,
    mark_teardown,
    parse_resources,
)
from attest_core.verification import AttemptReport, CheckEvidence, run_verification
from attest_spec import AttemptOutcome, Invariant, Verdict

_NEW = (
    "[resources] oom=1 oom_kill=2 pids_max=3 throttled_usec=4000 "
    "mem_peak=1048576 pids_peak=9 cpu_usec=5000 teardown=empty-verified"
)
_OLD = "[resources] oom=1 oom_kill=2 pids_max=3 throttled_usec=4000"


def _scope_tree(root: Path) -> Path:
    scope = root / "attest-scope-x.scope"
    scope.mkdir()
    (scope / "memory.peak").write_text("1048576\n", encoding="ascii")
    (scope / "pids.peak").write_text("9\n", encoding="ascii")
    (scope / "cpu.stat").write_text("usage_usec 5000\nthrottled_usec 11\n", encoding="ascii")
    return scope


def test_peaks_parse_with_units(tmp_path: Path) -> None:
    peaks = scope_metrics.read_peaks(str(_scope_tree(tmp_path)))
    assert peaks == {"mem_peak": 1048576, "pids_peak": 9, "cpu_usec": 5000}


def test_missing_peak_file_is_scope_error(tmp_path: Path) -> None:
    scope = _scope_tree(tmp_path)
    (scope / "memory.peak").unlink()
    with pytest.raises(scopes.ScopeError):
        scope_metrics.read_peaks(str(scope))


def test_malformed_peak_is_scope_error(tmp_path: Path) -> None:
    scope = _scope_tree(tmp_path)
    (scope / "pids.peak").write_text("many\n", encoding="ascii")
    with pytest.raises(scopes.ScopeError):
        scope_metrics.read_peaks(str(scope))


def test_missing_cpu_field_is_scope_error(tmp_path: Path) -> None:
    scope = _scope_tree(tmp_path)
    (scope / "cpu.stat").write_text("throttled_usec 11\n", encoding="ascii")
    with pytest.raises(scopes.ScopeError):
        scope_metrics.read_peaks(str(scope))


def test_peaks_failure_marks_unavailable_not_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scopes, "find_scope", lambda unit: "/sys/x.scope")
    zeros = {"oom": 0, "oom_kill": 0, "pids_max": 0, "throttled_usec": 0}
    monkeypatch.setattr(scopes, "read_scope_events", lambda path: dict(zeros))

    def _raise(path: str) -> dict[str, int]:
        raise scopes.ScopeError("gone")

    monkeypatch.setattr("attest_core.scope_metrics.read_peaks", _raise)
    marker = collect_resources("u.scope")
    assert marker.startswith("[resources] unavailable(")
    assert "=0" not in marker


def test_teardown_marks_success_and_clipped_failure() -> None:
    assert mark_teardown("[resources] oom=0", None).endswith("teardown=empty-verified")
    marked = mark_teardown("", "x" * 500)
    assert marked.startswith("[resources] teardown=failed(xxx")
    assert len(marked) < 200


def test_parser_round_trips_new_format() -> None:
    assert parse_resources(_NEW) == {
        "oom": 1,
        "oom_kill": 2,
        "pids_max": 3,
        "throttled_usec": 4000,
        "mem_peak": 1048576,
        "pids_peak": 9,
        "cpu_usec": 5000,
        "teardown": "empty-verified",
        "unavailable": None,
    }


def test_parser_treats_absent_as_none_not_zero() -> None:
    parsed = parse_resources(_OLD)
    assert parsed["oom"] == 1
    assert parsed["mem_peak"] is None
    assert parsed["pids_peak"] is None
    assert parsed["cpu_usec"] is None
    assert parsed["teardown"] is None
    assert parsed["unavailable"] is None


def test_parser_rejects_malformed_values() -> None:
    parsed = parse_resources("[resources] oom=many mem_peak=10 teardown=")
    assert parsed["oom"] is None
    assert parsed["mem_peak"] == 10
    assert parsed["teardown"] is None


def test_parser_keeps_unavailable_reason_and_teardown() -> None:
    parsed = parse_resources("[resources] unavailable(some reason here) teardown=failed(x)")
    assert parsed["unavailable"] == "some reason here"
    assert parsed["teardown"] == "failed(x)"
    assert parsed["oom"] is None


def test_parser_ignores_unknown_tokens() -> None:
    parsed = parse_resources("[resources] oom=1 future_metric=99")
    assert parsed["oom"] == 1


def test_parser_keeps_teardown_reason_verbatim() -> None:
    line = "[resources] oom=0 teardown=failed(scope not empty after kill (3 procs))"
    parsed = parse_resources(line)
    assert parsed["teardown"] == "failed(scope not empty after kill (3 procs))"
    assert parsed["oom"] == 0
    lone = parse_resources("[resources] teardown=failed(scope vanished: gone)")
    assert lone["teardown"] == "failed(scope vanished: gone)"


def test_parser_rejects_crafted_unavailable_token() -> None:
    parsed = parse_resources("[resources] oom=1 unavailable=x")
    assert parsed["oom"] == 1
    assert parsed["unavailable"] is None


def _verify_with_resources(resources: list[str]) -> Verdict:
    invariant = Invariant(
        invariant_id="AUTH-ADMIN-001",
        version=1,
        title="stub",
        requirement="stub requirement",
        scope=("/admin/users",),
    )
    calls = 0

    def run_checks() -> AttemptReport:
        nonlocal calls
        check = CheckEvidence("stub-check", "stub-target", True, "stub detail")
        report = AttemptReport(AttemptOutcome.PASS, (check,), "stub PASS")
        report = AttemptReport(report.outcome, report.checks, report.detail, resources[calls])
        calls += 1
        return report

    return run_verification(
        invariant=invariant,
        approval=create_approval(
            invariant, approver="op", approved_at="2026-01-01T00:00:00Z", method="stub"
        ),
        revision="r",
        settings={"k": "v"},
        run_checks=run_checks,
    ).verdict


def test_metrics_never_select_the_verdict() -> None:
    calm = ["[resources] oom=0 oom_kill=0 pids_max=0 throttled_usec=0"] * 3
    alarming = ["[resources] oom=9 oom_kill=9 pids_max=64 throttled_usec=999999"] * 3
    assert _verify_with_resources(calm) == Verdict.PASSED
    assert _verify_with_resources(alarming) == Verdict.PASSED
