"""Verify CLI end to end: subprocess runs importing from the staged tree."""

from __future__ import annotations

import io
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from apps.review import run_review

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
