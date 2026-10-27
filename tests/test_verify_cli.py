"""Verify CLI: exit codes, JSON output, snapshot refusal, determinism."""

from __future__ import annotations

import io
import json
import re
import subprocess
from pathlib import Path

import pytest

from apps.cli import main
from apps.review import run_review
from apps.verify import SNAPSHOT_CHANGED_REASON

INVARIANT_YAML = """\
- id: AUTH-ADMIN-001
  version: 1
  title: Administrative endpoints require administrator authorization
  requirement: Every endpoint in scope must reject unauthenticated requests.
  scope:
    - /admin/users
    - /admin/settings
"""


def _commit(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _setup_repo(git_repo: Path) -> tuple[Path, Path]:
    invariant = git_repo / "invariants" / "auth-admin-001.yaml"
    invariant.parent.mkdir(parents=True, exist_ok=True)
    invariant.write_text(INVARIANT_YAML, encoding="utf-8")
    _commit(git_repo, "add", "invariants")
    _commit(git_repo, "commit", "-qm", "add invariant")
    return invariant, git_repo / "approvals.yaml"


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


def _verify_args(invariant: Path, approvals: Path, repo: Path, *extra: str) -> list[str]:
    return [
        "verify",
        str(invariant),
        "--revision",
        "HEAD",
        "--repo",
        str(repo),
        "--approvals",
        str(approvals),
        *extra,
    ]


def test_repaired_passes_exit_zero(git_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    code = main(_verify_args(invariant, approvals, git_repo, "--target", "repaired"))
    out = capsys.readouterr().out
    assert code == 0
    assert "verdict: PASSED" in out
    assert re.search(r"revision: [0-9a-f]{40}", out)
    assert "config-digest:" in out and "attestation:" in out
    assert "coverage: established" in out


def test_vulnerable_fails_exit_one(git_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    code = main(_verify_args(invariant, approvals, git_repo, "--target", "vulnerable"))
    out = capsys.readouterr().out
    assert code == 1
    assert "verdict: FAILED" in out


def test_hanging_is_inconclusive_exit_two(
    git_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    code = main(
        _verify_args(invariant, approvals, git_repo, "--target", "hanging", "--timeout", "2")
    )
    out = capsys.readouterr().out
    assert code == 2
    assert "verdict: INCONCLUSIVE" in out


def test_crashing_is_inconclusive(git_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    code = main(_verify_args(invariant, approvals, git_repo, "--target", "crashing"))
    assert code == 2


def test_unapproved_is_refused(git_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    invariant, approvals = _setup_repo(git_repo)
    code = main(_verify_args(invariant, approvals, git_repo))
    err = capsys.readouterr().err
    assert code == 3
    assert "no approval" in err


def test_tampered_content_is_refused(git_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    invariant.write_text(INVARIANT_YAML.replace("reject", "allow"), encoding="utf-8")
    _commit(git_repo, "add", "invariants")
    _commit(git_repo, "commit", "-qm", "tamper")
    code = main(_verify_args(invariant, approvals, git_repo))
    err = capsys.readouterr().err
    assert code == 3
    assert "does not match" in err


def test_dirty_tree_is_refused(git_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    invariant.write_text(INVARIANT_YAML + "# scratch\n", encoding="utf-8")
    code = main(_verify_args(invariant, approvals, git_repo))
    err = capsys.readouterr().err
    assert code == 3
    assert "uncommitted" in err


def test_head_mismatch_is_refused(git_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    _commit(git_repo, "commit", "-q", "--allow-empty", "-m", "second")
    code = main(
        [
            "verify",
            str(invariant),
            "--revision",
            "HEAD~1",
            "--repo",
            str(git_repo),
            "--approvals",
            str(approvals),
        ]
    )
    err = capsys.readouterr().err
    assert code == 3
    assert "check out" in err


def test_json_output_valid_and_deterministic(
    git_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    args = _verify_args(invariant, approvals, git_repo, "--format", "json")
    assert main(args) == 0
    first = capsys.readouterr().out
    assert main(args) == 0
    second = capsys.readouterr().out
    assert first == second
    payload = json.loads(first)
    assert payload["schema_version"] == 1
    assert payload["verdict"] == "PASSED"
    assert re.fullmatch(r"[0-9a-f]{40}", payload["revision"])
    assert payload["evidence_hashes"]
    assert re.fullmatch(r"[0-9a-f]{64}", payload["attestation_digest"])
    assert payload["scope"]["coverage"] == "established"


def test_snapshot_change_overrides_to_inconclusive(
    git_repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    invariant, approvals = _setup_repo(git_repo)
    _approve(invariant, approvals)
    calls: list[str] = []

    def fake_fingerprint(repo: Path, paths: tuple[str, ...] = ("src",)) -> str:
        del repo, paths
        calls.append("x")
        return "before" if len(calls) == 1 else "after"

    monkeypatch.setattr("apps.verify.fingerprint", fake_fingerprint)
    code = main(_verify_args(invariant, approvals, git_repo))
    out = capsys.readouterr().out
    assert code == 2
    assert "verdict: INCONCLUSIVE" in out
    assert "snapshot-changed: true" in out
    assert SNAPSHOT_CHANGED_REASON in out
