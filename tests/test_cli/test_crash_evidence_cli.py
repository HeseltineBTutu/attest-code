"""Crashing CLI evidence: the intended crash is proven, not inferred.

End-to-end companion to the unit-level crash-marker tests: a staged
crashing verification must reach the endpoint (marker in output) and
stay INCONCLUSIVE without ever reporting an invariant violation.
Lives in this file because test_verify_cli.py is line-baselined and
must not grow.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from apps.demo_api import CRASH_MARKER
from apps.review import run_review


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


def test_crashing_proves_endpoint_crash(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = staged_repo.run(
        "verify",
        str(staged_repo.invariant),
        "--revision",
        "HEAD",
        "--repo",
        str(staged_repo.root),
        "--approvals",
        str(staged_repo.approvals),
        "--target",
        "crashing",
    )
    assert proc.returncode == 2, proc.stderr
    assert "verdict: INCONCLUSIVE" in proc.stdout
    assert "FAILED" not in proc.stdout
    assert CRASH_MARKER in proc.stdout
