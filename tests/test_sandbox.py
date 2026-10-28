"""S1 sandbox core: worker environment, cwd, JSON IPC, bounds, caches.

Spawn-based tests execute real workers; envelope/validation tests are
pure unit tests over the result-file protocol. No test here claims
OS-enforced isolation — only the documented S1 reductions.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

import pytest

from attest_core.bounds import run_bounded
from attest_core.envelope import (
    MAX_DETAIL_CHARS,
    MAX_RESULT_BYTES,
    SandboxEnvelopeError,
    decode_attempt_report,
    decode_origins_envelope,
    encode_attempt_report,
    encode_error,
    encode_origins,
    read_result_file,
)
from attest_core.sandbox import (
    CAPTURE_TAIL_CHARS,
    SandboxError,
    build_worker_environ,
    guarded_spawn,
)
from attest_core.verification import AttemptReport, CheckEvidence, run_verification
from attest_spec import ApprovalRecord, AttemptOutcome, Invariant

CHECKOUT_ROOT = Path(__file__).resolve().parent.parent

SENSITIVE_VARS = (
    "MODEL_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "DATABASE_URL",
    "PATH",
    "PYTHONPATH",
    "HOME",
)


def _env_probe() -> AttemptReport:
    """Top-level worker: report the environment the worker actually sees."""
    import yaml

    payload = {
        "cwd": os.getcwd(),
        "env_keys": sorted(os.environ),
        "pycache": os.environ.get("PYTHONPYCACHEPREFIX", ""),
        "yaml_file": yaml.__file__,
    }
    return AttemptReport(AttemptOutcome.PASS, (), json.dumps(payload))


def _passing_probe() -> AttemptReport:
    return AttemptReport(
        AttemptOutcome.PASS,
        (CheckEvidence("check-1", "target-1", True, "fine ✓"),),
        "all good",
    )


def _oversized_detail_probe() -> AttemptReport:
    return AttemptReport(AttemptOutcome.PASS, (), "D" * (MAX_DETAIL_CHARS + 1))


def _oversized_report_probe() -> AttemptReport:
    checks = tuple(
        CheckEvidence(f"check-{i}", "target", True, "D" * MAX_DETAIL_CHARS) for i in range(24)
    )
    return AttemptReport(AttemptOutcome.PASS, checks, "bulk")


def _pycache_probe() -> AttemptReport:
    prefix = os.environ.get("PYTHONPYCACHEPREFIX", "")
    found = sorted(str(path) for path in Path(prefix).rglob("*.pyc")) if prefix else []
    payload = {"prefix": prefix, "count": len(found), "sample": found[:3]}
    return AttemptReport(AttemptOutcome.PASS, (), json.dumps(payload))


def _run_probe(monkeypatch: pytest.MonkeyPatch, **secrets: str) -> dict[str, Any]:
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)
    report = run_bounded(_env_probe, 30.0)
    assert report.outcome == AttemptOutcome.PASS
    seen: dict[str, Any] = json.loads(report.detail)
    return seen


def test_sensitive_parent_env_absent_from_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _run_probe(
        monkeypatch,
        MODEL_API_KEY="fake-live-key",
        AWS_SECRET_ACCESS_KEY="fake-aws",
        GITHUB_TOKEN="fake-gh",
        DATABASE_URL="postgres://fake",
    )
    for name in ("MODEL_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DATABASE_URL"):
        assert name not in seen["env_keys"]
    assert "PYTHONPATH" not in seen["env_keys"]
    assert "PATH" not in seen["env_keys"]


def test_required_worker_env_present(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _run_probe(monkeypatch)
    assert seen["pycache"].endswith("pycache")
    assert Path(seen["pycache"]).is_absolute()
    assert seen["yaml_file"].endswith(os.path.join("yaml", "__init__.py"))


def test_worker_cwd_outside_live_repo(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _run_probe(monkeypatch)
    cwd = Path(seen["cwd"]).resolve()
    assert not cwd.is_relative_to(CHECKOUT_ROOT.resolve())
    assert "attest-work-" in seen["cwd"]


def test_parent_env_and_cwd_restored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODEL_API_KEY", "fake-live-key")
    before_env = dict(os.environ)
    before_cwd = os.getcwd()
    run_bounded(_passing_probe, 30.0)
    assert dict(os.environ) == before_env
    assert os.getcwd() == before_cwd


def test_build_worker_environ_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODEL_API_KEY", "fake-live-key")
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", "/tmp/keep-me")
    env = build_worker_environ()
    assert env["PYTHONPYCACHEPREFIX"] == "/tmp/keep-me"
    assert "MODEL_API_KEY" not in env
    assert "PATH" not in env
    env = build_worker_environ({"PYTHONPYCACHEPREFIX": "/tmp/attempt-1"})
    assert env == {"PYTHONPYCACHEPREFIX": "/tmp/attempt-1"}
    with pytest.raises(ValueError, match="allowlisted"):
        build_worker_environ({"MODEL_API_KEY": "nope"})


def test_attempt_report_json_round_trip() -> None:
    report = AttemptReport(
        AttemptOutcome.VIOLATION,
        (
            CheckEvidence("scope-coverage", "/admin/users", False, "mismatch: x"),
            CheckEvidence("admin-allowed", "/admin/users", True, "ok ✓"),
        ),
        "1 sub-check(s) failed",
    )
    assert decode_attempt_report(encode_attempt_report(report)) == report


def test_error_envelope_becomes_infra() -> None:
    report = decode_attempt_report(encode_error("boom"))
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert report.checks == ()
    assert "worker error: boom" in report.detail


def _envelope(**fields: Any) -> str:
    base: dict[str, Any] = {"sandbox_protocol": 1, "status": "ok"}
    base.update(fields)
    return json.dumps(base)


def _report_payload(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"outcome": "PASS", "checks": [], "detail": "fine"}
    base.update(fields)
    return base


def _check_payload(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"check_id": "c", "target": "t", "passed": True, "detail": "d"}
    base.update(fields)
    return base


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        '{"sandbox_protocol": 1, "status": "ok", "report": ',
        "[1, 2]",
        '"just a string"',
        _envelope(status="maybe", report=_report_payload()),
        _envelope(report=_report_payload(), extra="nope"),
        json.dumps({"sandbox_protocol": 2, "status": "ok", "report": _report_payload()}),
        json.dumps({"sandbox_protocol": True, "status": "ok", "report": _report_payload()}),
        json.dumps({"status": "ok", "report": _report_payload()}),
        _envelope(report={"outcome": "PASS", "checks": []}),
        _envelope(report=_report_payload(outcome="MAYBE")),
        _envelope(report=_report_payload(outcome=1)),
        _envelope(report=_report_payload(outcome=["PASS"])),
        _envelope(report=_report_payload(outcome={"nested": True})),
        _envelope(report=_report_payload(checks={})),
        _envelope(report=_report_payload(checks=[_check_payload(passed=1)])),
        _envelope(report=_report_payload(checks=[_check_payload(passed="yes")])),
        _envelope(report=_report_payload(checks=[_check_payload(check_id=7)])),
        _envelope(report=_report_payload(checks=[_check_payload(extra=1)])),
        _envelope(report=_report_payload(detail="D" * (MAX_DETAIL_CHARS + 1))),
        _envelope(
            report=_report_payload(checks=[_check_payload(detail="x" * (MAX_DETAIL_CHARS + 1))])
        ),
        '{"sandbox_protocol": 1, "status": "ok", "report": {"outcome": "PASS",'
        ' "checks": [], "detail": NaN}}',
        '{"sandbox_protocol": 1, "status": "ok", "report": {"outcome": "PASS",'
        ' "checks": [], "detail": Infinity}}',
        json.dumps({"sandbox_protocol": 1, "status": "error"}),
        json.dumps({"sandbox_protocol": 1, "status": "error", "detail": 42}),
    ],
)
def test_malformed_envelopes_rejected(text: str) -> None:
    with pytest.raises(SandboxEnvelopeError):
        decode_attempt_report(text)


def test_oversized_envelope_text_rejected() -> None:
    with pytest.raises(SandboxEnvelopeError, match="exceeds"):
        decode_attempt_report("x" * (MAX_RESULT_BYTES + 1))


def test_read_result_file_bounds(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    with pytest.raises(SandboxEnvelopeError, match="missing"):
        read_result_file(missing)
    big = tmp_path / "big.json"
    big.write_bytes(b"x" * (MAX_RESULT_BYTES + 1))
    with pytest.raises(SandboxEnvelopeError, match="exceeds"):
        read_result_file(big)
    ok = tmp_path / "ok.json"
    ok.write_text(encode_error("fine"), encoding="utf-8")
    assert "fine" in read_result_file(ok)


def test_oversized_detail_fails_closed_in_worker() -> None:
    report = run_bounded(_oversized_detail_probe, 30.0)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "worker result invalid" in report.detail


def test_oversized_report_rejected_worker_side() -> None:
    report = run_bounded(_oversized_report_probe, 30.0)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "worker result exceeds" in report.detail


def test_origins_envelope_round_trip() -> None:
    payload = {"attest_spec": "/snap/src/attest_spec/__init__.py", "apps": None}
    assert decode_origins_envelope(encode_origins(payload)) == payload
    with pytest.raises(SandboxEnvelopeError, match="boom"):
        decode_origins_envelope(encode_error("boom"))
    with pytest.raises(SandboxEnvelopeError, match="protocol"):
        decode_origins_envelope(json.dumps({"sandbox_protocol": 9, "status": "ok", "origins": {}}))


def test_per_attempt_caches_are_distinct_and_cleaned(monkeypatch: pytest.MonkeyPatch) -> None:
    prefixes: list[str] = []
    for _ in range(2):
        report = run_bounded(_pycache_probe, 30.0)
        assert report.outcome == AttemptOutcome.PASS
        seen: dict[str, Any] = json.loads(report.detail)
        prefixes.append(str(seen["prefix"]))
    assert prefixes[0] != prefixes[1]
    for prefix in prefixes:
        assert not Path(prefix).exists()


def test_attempt_cache_receives_bytecode(monkeypatch: pytest.MonkeyPatch) -> None:
    report = run_bounded(_pycache_probe, 60.0)
    assert report.outcome == AttemptOutcome.PASS
    seen: dict[str, Any] = json.loads(report.detail)
    assert seen["count"] >= 1


def test_malformed_worker_output_yields_inconclusive(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    report = run_verification(
        invariant=auth_admin_invariant,
        approval=auth_admin_approval,
        revision="r" * 40,
        settings={"k": "v"},
        run_checks=lambda: run_bounded(_oversized_detail_probe, 30.0),
    )
    assert report.verdict.value == "INCONCLUSIVE"
    assert all(attempt.outcome == AttemptOutcome.INFRA_FAILURE for attempt in report.attempts)


def test_worker_pass_cannot_alone_produce_passed(
    auth_admin_invariant: Invariant, auth_admin_approval: ApprovalRecord
) -> None:
    outcomes = iter([AttemptOutcome.PASS, AttemptOutcome.PASS, AttemptOutcome.VIOLATION])
    report = run_verification(
        invariant=auth_admin_invariant,
        approval=auth_admin_approval,
        revision="r" * 40,
        settings={"k": "v"},
        run_checks=lambda: AttemptReport(next(outcomes), (), "mixed"),
    )
    assert report.verdict.value == "INCONCLUSIVE"


def test_capture_tail_marks_truncation(tmp_path: Path) -> None:
    from attest_core.sandbox import capture_tail

    assert capture_tail(tmp_path / "missing.log") == ""
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    assert capture_tail(empty) == ""
    big = tmp_path / "big.log"
    big.write_text("y" * (CAPTURE_TAIL_CHARS + 500), encoding="utf-8")
    tail = capture_tail(big)
    assert tail.startswith("[output truncated]")
    assert len(tail) < CAPTURE_TAIL_CHARS + 100


def test_deeply_nested_json_fails_closed() -> None:
    nested = "[" * 50000 + "]" * 50000
    assert len(nested.encode("utf-8")) <= MAX_RESULT_BYTES
    with pytest.raises(SandboxEnvelopeError):
        decode_attempt_report(nested)


def test_non_regular_result_files_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "result.json"
    directory.mkdir()
    with pytest.raises(SandboxEnvelopeError, match="regular file"):
        read_result_file(directory)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="platform has no FIFOs")
def test_fifo_result_rejected_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "result.json"
    os.mkfifo(fifo)
    outcome: dict[str, str] = {}

    def attempt() -> None:
        try:
            read_result_file(fifo)
        except SandboxEnvelopeError as exc:
            outcome["error"] = str(exc)

    reader = threading.Thread(target=attempt, daemon=True)
    reader.start()
    reader.join(10.0)
    assert not reader.is_alive()
    assert "regular file" in outcome["error"]


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlinked_result_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text(encode_error("fine"), encoding="utf-8")
    link = tmp_path / "result.json"
    link.symlink_to(real)
    with pytest.raises(SandboxEnvelopeError, match="regular file"):
        read_result_file(link)


def test_capture_tail_marks_non_regular(tmp_path: Path) -> None:
    from attest_core.sandbox import capture_tail

    directory = tmp_path / "d.log"
    directory.mkdir()
    assert capture_tail(directory) == "[output unreadable: not a regular file]"


def test_guarded_spawn_restores_on_chdir_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("S1_SENTINEL_KEEPME", "1")
    before_env = dict(os.environ)
    before_cwd = os.getcwd()
    with (
        pytest.raises(OSError, match="missing"),
        guarded_spawn(_passing_probe, (), environ={}, cwd=tmp_path / "missing"),
    ):
        pass
    assert dict(os.environ) == before_env
    assert os.getcwd() == before_cwd


def test_guarded_spawn_rejects_background_threads(tmp_path: Path) -> None:
    errors: list[BaseException] = []

    def attempt() -> None:
        try:
            with guarded_spawn(_passing_probe, (), environ={}, cwd=tmp_path):
                pass
        except SandboxError as exc:
            errors.append(exc)

    worker = threading.Thread(target=attempt)
    worker.start()
    worker.join(30.0)
    assert not worker.is_alive()
    assert len(errors) == 1
