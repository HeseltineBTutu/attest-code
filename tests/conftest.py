"""Shared operator fixtures.

Tests act as the human operator deliberately invoking the approval
boundary. Approvals created here are operator input for fixtures, never
model output.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from attest_core.invariants import create_approval, load_definitions
from attest_spec import ApprovalRecord, Invariant

INVARIANTS_FILE = Path(__file__).resolve().parent.parent / "invariants" / "auth-admin-001.yaml"
CHECKOUT_SRC = Path(__file__).resolve().parent.parent / "src"

STAGED_INVARIANT_YAML = """\
- id: AUTH-ADMIN-001
  version: 1
  title: Administrative endpoints require administrator authorization
  requirement: Every endpoint in scope must reject unauthenticated requests.
  scope:
    - /admin/users
    - /admin/settings
"""


@dataclasses.dataclass(frozen=True)
class StagedRepo:
    """A committed git tree carrying a copy of the verifier source."""

    root: Path
    src: Path
    invariant: Path
    approvals: Path

    def run(
        self,
        *args: str,
        env: Mapping[str, str] | None = None,
        timeout: int = 180,
    ) -> subprocess.CompletedProcess[str]:
        """Run the CLI in a fresh interpreter importing from the staged tree."""
        merged = dict(os.environ)
        merged["PYTHONPATH"] = str(self.src)
        if env is not None:
            merged.update(env)
        return subprocess.run(
            [sys.executable, "-c", "from apps.cli import main; raise SystemExit(main())", *args],
            cwd=self.root,
            env=merged,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )


@pytest.fixture
def auth_admin_invariant() -> Invariant:
    definitions = load_definitions(INVARIANTS_FILE)
    assert len(definitions) == 1
    return definitions[0]


@pytest.fixture
def auth_admin_approval(auth_admin_invariant: Invariant) -> ApprovalRecord:
    return create_approval(
        auth_admin_invariant,
        approver="operator",
        approved_at="2026-10-27T00:00:00Z",
        method="test-operator-fixture",
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Fresh temporary git repository with one empty commit."""
    if shutil.which("git") is None:
        pytest.skip("git executable not available")
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "--allow-empty", "-m", "init"],
        check=True,
    )
    return tmp_path


@pytest.fixture
def staged_repo(git_repo: Path) -> StagedRepo:
    """Committed tree with a source copy the CLI subprocess can import."""
    src = git_repo / "src"
    shutil.copytree(CHECKOUT_SRC, src, ignore=shutil.ignore_patterns("__pycache__"))
    invariant = git_repo / "invariants" / "auth-admin-001.yaml"
    invariant.parent.mkdir(parents=True, exist_ok=True)
    invariant.write_text(STAGED_INVARIANT_YAML, encoding="utf-8")
    shutil.copy(Path(__file__).resolve().parent.parent / ".gitignore", git_repo / ".gitignore")
    subprocess.run(
        ["git", "-C", str(git_repo), "add", ".gitignore", "src", "invariants"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(git_repo), "commit", "-qm", "stage tree"],
        check=True,
        capture_output=True,
    )
    return StagedRepo(
        root=git_repo, src=src, invariant=invariant, approvals=git_repo / "approvals.yaml"
    )
