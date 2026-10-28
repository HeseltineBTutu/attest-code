"""Verify CLI end to end: subprocess runs importing from the staged tree."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from apps.review import run_review
from apps.verify import run_verify
from attest_core.bounds import run_bounded as real_run_bounded
from attest_core.snapshot import Snapshot
from attest_core.snapshot import verify_snapshot as real_verify_snapshot
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome, Verdict


@pytest.fixture(autouse=True)
def _restore_sys_path() -> Iterator[None]:
    old = list(sys.path)
    yield
    sys.path[:] = old


INVARIANT_YAML = """\
- id: AUTH-ADMIN-001
  version: 1
  title: Administrative endpoints require administrator authorization
  requirement: Every endpoint in scope must reject unauthenticated requests.
  scope:
    - /admin/users
    - /admin/settings
"""


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


def _commit(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _verify(staged: Any, *extra: str) -> subprocess.CompletedProcess[str]:
    proc: subprocess.CompletedProcess[str] = staged.run(
        "verify",
        str(staged.invariant),
        "--revision",
        "HEAD",
        "--repo",
        str(staged.root),
        "--approvals",
        str(staged.approvals),
        *extra,
    )
    return proc


def test_repaired_passes_exit_zero(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, "--target", "repaired")
    assert proc.returncode == 0, proc.stderr
    assert "verdict: PASSED" in proc.stdout
    assert re.search(r"revision: [0-9a-f]{40}", proc.stdout)
    assert "config-digest:" in proc.stdout and "attestation:" in proc.stdout
    assert "coverage: established" in proc.stdout


def test_vulnerable_fails_exit_one(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, "--target", "vulnerable")
    assert proc.returncode == 1, proc.stderr
    assert "verdict: FAILED" in proc.stdout


def test_incomplete_repair_fails_exit_one(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, "--target", "incomplete")
    assert proc.returncode == 1, proc.stderr
    assert "verdict: FAILED" in proc.stdout


def test_hanging_is_inconclusive_exit_two(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, "--target", "hanging", "--timeout", "2")
    assert proc.returncode == 2, proc.stderr
    assert "verdict: INCONCLUSIVE" in proc.stdout


def test_crashing_is_inconclusive(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, "--target", "crashing")
    assert proc.returncode == 2, proc.stderr
    assert "verdict: INCONCLUSIVE" in proc.stdout


def test_unapproved_is_refused(staged_repo: Any) -> None:
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "no approval" in proc.stderr


def test_tampered_content_is_refused(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    staged_repo.invariant.write_text(INVARIANT_YAML.replace("reject", "allow"), encoding="utf-8")
    _commit(staged_repo.root, "add", "invariants")
    _commit(staged_repo.root, "commit", "-qm", "tamper")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "does not match" in proc.stderr


def test_dirty_tree_is_refused(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    staged_repo.invariant.write_text(INVARIANT_YAML + "# scratch\n", encoding="utf-8")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "uncommitted" in proc.stderr


def test_head_mismatch_is_refused(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    _commit(staged_repo.root, "commit", "-q", "--allow-empty", "-m", "second")
    proc = staged_repo.run(
        "verify",
        str(staged_repo.invariant),
        "--revision",
        "HEAD~1",
        "--repo",
        str(staged_repo.root),
        "--approvals",
        str(staged_repo.approvals),
    )
    assert proc.returncode == 3
    assert "check out" in proc.stderr


def test_json_output_valid_and_deterministic(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    first = _verify(staged_repo, "--format", "json")
    assert first.returncode == 0, first.stderr
    second = _verify(staged_repo, "--format", "json")
    assert second.returncode == 0, second.stderr
    assert first.stdout == second.stdout
    payload = json.loads(first.stdout)
    assert payload["schema_version"] == 1
    assert payload["verdict"] == "PASSED"
    assert re.fullmatch(r"[0-9a-f]{40}", payload["revision"])
    assert payload["evidence_hashes"]
    assert re.fullmatch(r"[0-9a-f]{64}", payload["attestation_digest"])
    assert payload["scope"]["coverage"] == "established"


def test_inputs_outside_repo_are_refused(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    outside_dir = tmp_path.parent / f"{tmp_path.name}-outside"
    outside_dir.mkdir(parents=True, exist_ok=True)
    outsider = outside_dir / "elsewhere.yaml"
    outsider.write_text(INVARIANT_YAML, encoding="utf-8")
    proc = staged_repo.run(
        "verify",
        str(outsider),
        "--revision",
        "HEAD",
        "--repo",
        str(staged_repo.root),
        "--approvals",
        str(staged_repo.approvals),
    )
    assert proc.returncode == 3
    assert "outside the repository tree" in proc.stderr


def test_mid_run_drift_fails_attempts_inconclusive(
    staged_repo: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drift persisting past an attempt boundary fails closed (real git + workers).

    Two narrow test doubles: origin binding is covered by dedicated F1 e2e
    tests and cannot match a staged root from this process by construction,
    so it is stubbed; the worker call is wrapped (never replaced) to
    interleave genuine worktree dirt. The drift check, git, and workers run.
    """
    _approve(staged_repo.invariant, staged_repo.approvals)
    monkeypatch.setattr("apps.verify.verify_code_origin", lambda *args, **kwargs: None)
    calls = 0

    def dirtying_run_bounded(
        func: Callable[[], AttemptReport],
        timeout_seconds: float,
        snapshot_root: Path | None = None,
    ) -> AttemptReport:
        nonlocal calls
        calls += 1
        (staged_repo.src / "apps" / "demo_api.py").write_text("# drifted\n", encoding="utf-8")
        return real_run_bounded(func, timeout_seconds, snapshot_root=snapshot_root)

    monkeypatch.setattr("apps.verify.run_bounded", dirtying_run_bounded)
    stdout = io.StringIO()
    verdict = run_verify(
        invariant_file=staged_repo.invariant,
        approvals_file=staged_repo.approvals,
        invariant_id=None,
        revision="HEAD",
        repo=staged_repo.root,
        target="repaired",
        timeout_seconds=60.0,
        output_format="json",
        stdout=stdout,
    )
    assert verdict is Verdict.INCONCLUSIVE
    assert calls == 1
    payload = json.loads(stdout.getvalue())
    assert payload["verdict"] == "INCONCLUSIVE"
    assert payload["snapshot_changed"] is True
    outcomes = [attempt["outcome"] for attempt in payload["attempts"]]
    assert outcomes == [AttemptOutcome.INFRA_FAILURE.value] * 3
    details = [attempt["detail"] for attempt in payload["attempts"]]
    assert any("source snapshot changed during verification" in detail for detail in details)


def test_snapshot_tamper_fails_attempts_inconclusive(
    staged_repo: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Snapshot tampering past an attempt boundary fails closed (real guard).

    The re-verification spy delegates to the real check and only records
    the snapshot location; the worker call is wrapped (never replaced) to
    interleave a genuine snapshot mutation. Tamper is a comment line so a
    worker that still ran would pass — the guard is the failure cause.
    """
    _approve(staged_repo.invariant, staged_repo.approvals)
    monkeypatch.setattr("apps.verify.verify_code_origin", lambda *args, **kwargs: None)
    roots: list[Path] = []

    def recording_verify(snapshot: Snapshot) -> None:
        roots.append(snapshot.root)
        real_verify_snapshot(snapshot)

    monkeypatch.setattr("apps.verify.verify_snapshot", recording_verify)
    calls = 0

    def tampering_run_bounded(
        func: Callable[[], AttemptReport],
        timeout_seconds: float,
        snapshot_root: Path | None = None,
    ) -> AttemptReport:
        nonlocal calls
        calls += 1
        if calls == 2:
            target = roots[0] / "src" / "apps" / "demo_api.py"
            target.chmod(0o644)
            target.write_bytes(target.read_bytes() + b"# tampered\n")
        return real_run_bounded(func, timeout_seconds, snapshot_root=snapshot_root)

    monkeypatch.setattr("apps.verify.run_bounded", tampering_run_bounded)
    stdout = io.StringIO()
    verdict = run_verify(
        invariant_file=staged_repo.invariant,
        approvals_file=staged_repo.approvals,
        invariant_id=None,
        revision="HEAD",
        repo=staged_repo.root,
        target="repaired",
        timeout_seconds=60.0,
        output_format="json",
        stdout=stdout,
    )
    assert verdict is Verdict.INCONCLUSIVE
    assert calls == 2
    payload = json.loads(stdout.getvalue())
    outcomes = [attempt["outcome"] for attempt in payload["attempts"]]
    assert outcomes == [
        AttemptOutcome.PASS.value,
        AttemptOutcome.INFRA_FAILURE.value,
        AttemptOutcome.INFRA_FAILURE.value,
    ]
    details = [attempt["detail"] for attempt in payload["attempts"]]
    assert any("snapshot integrity check failed" in detail for detail in details)


def test_worker_path_tamper_caught_by_self_check(
    staged_repo: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Workers redirected off-snapshot refuse to run checks (real spawn).

    Re-inserting the live tree ahead of the snapshot simulates parent-path
    tampering after the pre-attempt probe; each worker's own origin
    self-check must catch it. Workers still spawn (the check is worker-side)
    but execute no verification logic.
    """
    _approve(staged_repo.invariant, staged_repo.approvals)
    monkeypatch.setattr("apps.verify.verify_code_origin", lambda *args, **kwargs: None)
    calls = 0

    def redirecting_run_bounded(
        func: Callable[[], AttemptReport],
        timeout_seconds: float,
        snapshot_root: Path | None = None,
    ) -> AttemptReport:
        nonlocal calls
        calls += 1
        sys.path.insert(0, str(staged_repo.src))
        return real_run_bounded(func, timeout_seconds, snapshot_root=snapshot_root)

    monkeypatch.setattr("apps.verify.run_bounded", redirecting_run_bounded)
    stdout = io.StringIO()
    verdict = run_verify(
        invariant_file=staged_repo.invariant,
        approvals_file=staged_repo.approvals,
        invariant_id=None,
        revision="HEAD",
        repo=staged_repo.root,
        target="repaired",
        timeout_seconds=60.0,
        output_format="json",
        stdout=stdout,
    )
    assert verdict is Verdict.INCONCLUSIVE
    assert calls == 3
    payload = json.loads(stdout.getvalue())
    outcomes = [attempt["outcome"] for attempt in payload["attempts"]]
    assert outcomes == [AttemptOutcome.INFRA_FAILURE.value] * 3
    details = [attempt["detail"] for attempt in payload["attempts"]]
    assert all("worker origin self-check failed" in detail for detail in details)
