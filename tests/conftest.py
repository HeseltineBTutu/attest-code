"""Shared operator fixtures.

Tests act as the human operator deliberately invoking the approval
boundary. Approvals created here are operator input for fixtures, never
model output.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from attest_core.invariants import create_approval, load_definitions
from attest_spec import ApprovalRecord, Invariant

INVARIANTS_FILE = Path(__file__).resolve().parent.parent / "invariants" / "auth-admin-001.yaml"


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
