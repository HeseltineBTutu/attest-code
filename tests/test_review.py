"""Review flow: explicit confirmation, stale detection, safe storage."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from apps.approvals import (
    find_approval,
    load_approvals,
    save_approvals,
    upsert_approval,
)
from apps.cli import main
from apps.review import ReviewStatus, run_review
from attest_core.invariants import create_approval, is_approval_valid, load_definitions
from attest_spec import Invariant

INVARIANT_YAML = """\
- id: AUTH-ADMIN-001
  version: 1
  title: Administrative endpoints require administrator authorization
  requirement: Every endpoint in scope must reject unauthenticated requests.
  scope:
    - /admin/users
    - /admin/settings
"""


def _write(path: Path, content: str = INVARIANT_YAML) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _review(
    invariant: Path, approvals: Path, answers: str, approver: str = "ada"
) -> tuple[ReviewStatus, str]:
    stdout = io.StringIO()
    status = run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver=approver,
        invariant_id=None,
        stdin=io.StringIO(answers),
        stdout=stdout,
    )
    return status, stdout.getvalue()


def test_approve_after_confirmation(tmp_path: Path) -> None:
    invariant = _write(tmp_path / "inv.yaml")
    approvals = tmp_path / "approvals.yaml"
    status, output = _review(invariant, approvals, "y\n")
    assert status == ReviewStatus.APPROVED
    assert "AUTH-ADMIN-001" in output and "content-digest" in output
    stored = load_approvals(approvals)
    assert len(stored) == 1
    definition = load_definitions(invariant)[0]
    assert is_approval_valid(definition, stored[0])


def test_decline_writes_nothing(tmp_path: Path) -> None:
    approvals = tmp_path / "approvals.yaml"
    status, output = _review(_write(tmp_path / "inv.yaml"), approvals, "n\n")
    assert status == ReviewStatus.DECLINED
    assert "declined" in output
    assert not approvals.exists()


def test_empty_input_declines(tmp_path: Path) -> None:
    status, _ = _review(_write(tmp_path / "inv.yaml"), tmp_path / "a.yaml", "")
    assert status == ReviewStatus.DECLINED


def test_invalid_yaml_is_error(tmp_path: Path) -> None:
    status, output = _review(_write(tmp_path / "inv.yaml", "- id: [\n"), tmp_path / "a.yaml", "y\n")
    assert status == ReviewStatus.ERROR
    assert "invalid invariant" in output


def test_malformed_invariant_is_error(tmp_path: Path) -> None:
    status, _ = _review(
        _write(tmp_path / "inv.yaml", "- id: X\n  version: 1\n"), tmp_path / "a.yaml", "y\n"
    )
    assert status == ReviewStatus.ERROR


def test_already_approved_skips_prompt(tmp_path: Path) -> None:
    invariant = _write(tmp_path / "inv.yaml")
    approvals = tmp_path / "a.yaml"
    assert _review(invariant, approvals, "yes\n")[0] == ReviewStatus.APPROVED
    status, output = _review(invariant, approvals, "")
    assert status == ReviewStatus.ALREADY_APPROVED
    assert "already approved" in output


def test_tampered_content_requires_new_approval(tmp_path: Path) -> None:
    invariant = _write(tmp_path / "inv.yaml")
    approvals = tmp_path / "a.yaml"
    assert _review(invariant, approvals, "y\n")[0] == ReviewStatus.APPROVED
    _write(invariant, INVARIANT_YAML.replace("reject unauthenticated", "allow everyone"))
    status, output = _review(invariant, approvals, "n\n")
    assert status == ReviewStatus.DECLINED
    assert "STALE" in output
    definition = load_definitions(invariant)[0]
    assert not is_approval_valid(definition, load_approvals(approvals)[0])


def test_yaml_approval_claim_is_not_proof(tmp_path: Path) -> None:
    content = INVARIANT_YAML + "  approval:\n    status: approved\n"
    status, output = _review(_write(tmp_path / "inv.yaml", content), tmp_path / "a.yaml", "n\n")
    assert status == ReviewStatus.DECLINED
    assert "previous-approval: none" in output


def test_missing_approver_is_error(tmp_path: Path) -> None:
    status, _ = _review(_write(tmp_path / "inv.yaml"), tmp_path / "a.yaml", "y\n", approver=" ")
    assert status == ReviewStatus.ERROR


def test_corrupt_store_is_error(tmp_path: Path) -> None:
    approvals = tmp_path / "a.yaml"
    approvals.write_text("just: [unbalanced\n", encoding="utf-8")
    status, output = _review(_write(tmp_path / "inv.yaml"), approvals, "y\n")
    assert status == ReviewStatus.ERROR
    assert "approvals" in output


def test_review_via_main(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    invariant = _write(tmp_path / "inv.yaml")
    approvals = tmp_path / "a.yaml"
    monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
    code = main(["review", str(invariant), "--approver", "ada", "--approvals", str(approvals)])
    assert code == 0
    assert approvals.exists()
    capsys.readouterr()


def test_usage_error_exits_three(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["verify", "x.yaml"])
    assert exc.value.code == 3
    capsys.readouterr()


def test_store_roundtrip_and_upsert(tmp_path: Path) -> None:
    definition = Invariant("A", 1, "t", "req", ("/x",))
    first = create_approval(definition, approver="a", approved_at="t1", method="m")
    approvals = tmp_path / "a.yaml"
    save_approvals(approvals, [first])
    assert load_approvals(approvals) == [first]
    second = create_approval(definition, approver="b", approved_at="t2", method="m")
    save_approvals(approvals, upsert_approval(load_approvals(approvals), second))
    assert find_approval(load_approvals(approvals), "A", 1) == second
