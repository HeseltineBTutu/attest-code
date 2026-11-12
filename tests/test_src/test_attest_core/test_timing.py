"""Parent-observed timing: collector units, lifecycle spans, CLI compatibility."""

import io
import json
import re
import sys
import time
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from apps.review import run_review
from apps.verify import run_verify
from attest_core.timing import TimingCollector, TimingError
from attest_core.verification import AttemptReport, run_verification
from attest_spec import ApprovalRecord, AttemptOutcome, Invariant

_KEYS = ["record_type", "attempt", "elapsed_s", "outcome", "censored", "profile", "timeout_s"]
_TIMEOUT_DETAIL = "worker exceeded 2s deadline and was terminated"
_REFUSED_DETAIL = "quota execution unsupported on this host"


@pytest.fixture(autouse=True)
def _restore_sys_path() -> Iterator[None]:
    old = list(sys.path)
    yield
    sys.path[:] = old


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


def _run(
    timer: TimingCollector | None,
    invariant: Invariant,
    approval: ApprovalRecord,
    behavior: str,
) -> Any:
    def _checks() -> AttemptReport:
        if behavior == "raise":
            raise RuntimeError("boom")
        if behavior == "interrupt":
            raise KeyboardInterrupt
        detail = {"pass": "ok", "timeout": _TIMEOUT_DETAIL, "refused": _REFUSED_DETAIL}[behavior]
        outcome = AttemptOutcome.PASS if behavior == "pass" else AttemptOutcome.INFRA_FAILURE
        return AttemptReport(outcome, (), detail)

    return run_verification(
        invariant=invariant,
        approval=approval,
        revision="b" * 40,
        settings={"k": "v"},
        run_checks=_checks,
        timer=timer,
    )


def _verify_staged(staged_repo: Any, timer: TimingCollector | None) -> Any:
    return run_verify(
        invariant_file=staged_repo.invariant,
        approvals_file=staged_repo.approvals,
        invariant_id=None,
        revision="HEAD",
        repo=staged_repo.root,
        target="repaired",
        timeout_seconds=60.0,
        output_format="json",
        timer=timer,
        stdout=io.StringIO(),
    )


def test_spans_and_decimals(monkeypatch: pytest.MonkeyPatch) -> None:
    timer = TimingCollector(profile="hardened", timeout_seconds=2.0)
    ticks = iter([10.0, 10.5, 7.0, 7.0, 9.0, 8.0, 0.0, 99.0])
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    for attempt in (1, 2, 3):
        timer.start_attempt(attempt)
        timer.stop_attempt(attempt, outcome=AttemptOutcome.PASS, detail="ok")
    timer.start_total()
    timer.stop_total()
    records = [json.loads(line) for line in timer.to_jsonl().splitlines()]
    assert [record["elapsed_s"] for record in records[:3]] == [
        "0.500000000",
        "0.000000000",
        "0.000000000",
    ]
    assert all(re.match(r"^\d+\.\d{9}$", record["elapsed_s"]) for record in records)
    assert list(records[0]) == _KEYS
    assert records[3]["record_type"] == "total"
    assert records[3]["elapsed_s"] == "99.000000000"


def test_misuse_raises() -> None:
    timer = TimingCollector(profile="standard", timeout_seconds=1.0)
    with pytest.raises(TimingError):
        timer.stop_attempt(1, outcome=AttemptOutcome.PASS, detail="x")
    timer.start_attempt(1)
    with pytest.raises(TimingError):
        timer.start_attempt(2)
    with pytest.raises(TimingError):
        timer.stop_attempt(2, outcome=AttemptOutcome.PASS, detail="x")
    timer.stop_attempt(1, outcome=AttemptOutcome.PASS, detail="ok")
    timer.start_total()
    with pytest.raises(TimingError):
        timer.start_total()
    timer.stop_total()
    with pytest.raises(TimingError):
        timer.stop_total()


@pytest.mark.parametrize("behavior", ["timeout", "raise", "refused"])
def test_infra_labels(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord, behavior: str
) -> None:
    timer = TimingCollector(profile="standard", timeout_seconds=2.0)
    timer.start_total()
    _run(timer, auth_admin_invariant, auth_admin_approval, behavior)
    timer.stop_total()
    outcome, censored = ("TIMEOUT", True) if behavior == "timeout" else ("INFRA_FAILURE", False)
    records = [json.loads(line) for line in timer.to_jsonl().splitlines()][:3]
    assert all(
        record["outcome"] == outcome and record["censored"] is censored for record in records
    )
    assert set(records[0]) == set(_KEYS)


def test_exception_path_preserves_original(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    timer = TimingCollector(profile="standard", timeout_seconds=2.0)
    timer.start_total()
    with pytest.raises(KeyboardInterrupt):
        _run(timer, auth_admin_invariant, auth_admin_approval, "interrupt")
    with pytest.raises(TimingError):
        timer.to_jsonl()


def test_attempt_timer_failure_keeps_result(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    timer = TimingCollector(profile="standard", timeout_seconds=60.0)
    timer.start_attempt(99)
    report = _run(timer, auth_admin_invariant, auth_admin_approval, "pass")
    assert [attempt.outcome for attempt in report.attempts] == [AttemptOutcome.PASS] * 3


def test_total_timer_boundaries(
    staged_repo: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    monkeypatch.setattr("apps.verify.verify_code_origin", lambda *args, **kwargs: None)
    bad = TimingCollector(profile="standard", timeout_seconds=60.0)
    bad.start_total()
    bad.stop_total()
    assert _verify_staged(staged_repo, bad).value == "PASSED"
    timer = TimingCollector(profile="standard", timeout_seconds=60.0)
    _verify_staged(staged_repo, timer)
    before = timer.to_jsonl()
    timer.write_jsonl(tmp_path / "t.jsonl")
    assert timer.to_jsonl() == before


def test_cli_timing_end_to_end(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    log = tmp_path / "timing.jsonl"
    base = ["verify", str(staged_repo.invariant), "--revision", "HEAD"]
    off = staged_repo.run(*base, "--format", "json")
    assert off.returncode == 0, off.stderr
    assert not log.exists()
    on = staged_repo.run(*base, "--format", "json", "--timing-log", str(log))
    assert on.returncode == 0, on.stderr
    assert on.stdout == off.stdout
    assert json.loads(on.stdout)["schema_version"] == 1
    spans = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [span.get("attempt") for span in spans] == [1, 2, 3, None]
    assert all(span["outcome"] == "PASS" for span in spans[:3])
    total = Decimal(spans[3]["elapsed_s"])
    expect = sum(Decimal(span["elapsed_s"]) for span in spans[:3])
    assert total + Decimal("0.000001") >= expect
    off_text = staged_repo.run(*base)
    on_text = staged_repo.run(*base, "--timing-log", str(tmp_path / "text.jsonl"))
    assert (off_text.returncode, on_text.returncode) == (0, 0)
    assert on_text.stdout == off_text.stdout
    log.write_text("sentinel\n", encoding="utf-8")
    failed = staged_repo.run(*base, "--timing-log", str(log))
    assert failed.returncode == 0, failed.stderr
    assert "timing log failed" in failed.stderr
    assert log.read_text(encoding="utf-8") == "sentinel\n"
