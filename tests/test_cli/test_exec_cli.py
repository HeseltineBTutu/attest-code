"""Execution-profile CLI: flags, staged runs, pre-attempt refusal (Stage 1)."""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from apps.cli import build_parser
from apps.review import run_review
from apps.verify import run_verify
from attest_core.exec_profile import ExecProfileError
from attest_core.ns_setup import supports_containment
from attest_core.scopes import supports_quotas

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="user+mount+PID+network namespaces unavailable"
)
NEEDS_QUOTAS = pytest.mark.skipif(
    not (supports_containment() and supports_quotas()),
    reason="systemd scope quotas unavailable",
)
NEEDS_NO_QUOTAS = pytest.mark.skipif(
    supports_quotas(), reason="quotas available: refusal path not taken"
)


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


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


def test_parser_defaults_standard() -> None:
    args = build_parser().parse_args(["verify", "inv.yaml", "--revision", "HEAD"])
    assert args.exec == "standard"


@pytest.mark.parametrize("profile", ["standard", "contained", "hardened"])
def test_parser_accepts_profiles(profile: str) -> None:
    args = build_parser().parse_args(
        ["verify", "inv.yaml", "--revision", "HEAD", "--exec", profile]
    )
    assert args.exec == profile


def test_parser_rejects_unknown_profile() -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(
            ["verify", "inv.yaml", "--revision", "HEAD", "--exec", "fortress"]
        )
    assert exc.value.code == 3


def test_run_verify_refuses_unknown_before_repo(tmp_path: Path) -> None:
    with pytest.raises(ExecProfileError, match="unknown execution profile"):
        run_verify(
            invariant_file=tmp_path / "nope.yaml",
            approvals_file=tmp_path / "nope-approvals.yaml",
            invariant_id=None,
            revision="HEAD",
            repo=tmp_path / "no-repo",
            target="repaired",
            timeout_seconds=60.0,
            output_format="text",
            exec_profile="fortress",
        )


@NEEDS_NO_QUOTAS
def test_run_verify_hardened_refused_before_repo(tmp_path: Path) -> None:
    with pytest.raises(ExecProfileError, match="quotas"):
        run_verify(
            invariant_file=tmp_path / "nope.yaml",
            approvals_file=tmp_path / "nope-approvals.yaml",
            invariant_id=None,
            revision="HEAD",
            repo=tmp_path / "no-repo",
            target="repaired",
            timeout_seconds=60.0,
            output_format="text",
            exec_profile="hardened",
        )


def test_default_invocation_unchanged(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo)
    assert proc.returncode == 0, proc.stderr


def test_explicit_standard_reports_profile(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, "--exec", "standard", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["execution"]["requested"] == "standard"
    assert payload["execution"]["enforcement"] == "none-claimed"


@NEEDS_CONTAINMENT
def test_contained_profile_passes(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, "--exec", "contained", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["execution"]["requested"] == "contained"
    assert payload["execution"]["selected"] == "contained"
    assert payload["execution"]["actual"]["quotas"] is False
    assert payload["execution"]["capabilities"] == {"containment": True}
    assert payload["execution"]["enforcement"] == "verified"
    assert all("[resources]" not in attempt["detail"] for attempt in payload["attempts"])


@NEEDS_NO_QUOTAS
def test_hardened_refused_without_capability(staged_repo: Any) -> None:
    proc = _verify(staged_repo, "--exec", "hardened")
    assert proc.returncode == 3
    assert "quotas" in proc.stderr


@NEEDS_QUOTAS
def test_hardened_live_reports_verified_resources(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, "--exec", "hardened", "--format", "json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["execution"]["requested"] == "hardened"
    assert payload["execution"]["actual"] == {
        "contained": True,
        "quotas": True,
        "seccomp": True,
    }
    assert payload["execution"]["enforcement"] == "verified"
    attempts = payload["attempts"]
    assert len(attempts) == 3
    assert all("[resources]" not in attempt["detail"] for attempt in attempts)
    assert all("[resources] oom=" in attempt["resources"] for attempt in attempts)


def test_unknown_exec_rejected(staged_repo: Any) -> None:
    proc = _verify(staged_repo, "--exec", "fortress")
    assert proc.returncode == 3
