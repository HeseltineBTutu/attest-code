"""Operator review flow: inspect an invariant and optionally approve it.

Approval requires explicit confirmation naming a human reviewer. A local
confirmation does not cryptographically establish identity; signatures
and strong identity assurance remain out of scope.
"""

from __future__ import annotations

import enum
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from apps.approvals import (
    find_approval,
    load_approvals,
    save_approvals,
    select_invariant,
    upsert_approval,
)
from attest_core.invariants import (
    create_approval,
    invariant_content_digest,
    load_definitions,
)
from attest_spec import Invariant


class ReviewStatus(enum.StrEnum):
    """Outcome of a review invocation, mapped to exit codes by the CLI."""

    APPROVED = "approved"
    ALREADY_APPROVED = "already-approved"
    DECLINED = "declined"
    ERROR = "error"


def _show(invariant: Invariant, digest: str, stdout: TextIO) -> None:
    stdout.write(f"invariant: {invariant.invariant_id} v{invariant.version}\n")
    stdout.write(f"title: {invariant.title}\n")
    stdout.write(f"requirement: {invariant.requirement}\n")
    stdout.write(f"scope: {', '.join(invariant.scope)}\n")
    stdout.write(f"content-digest: {digest}\n")


def run_review(
    *,
    invariant_file: Path,
    approvals_file: Path,
    approver: str,
    invariant_id: str | None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> ReviewStatus:
    """Review one invariant; approve only on explicit confirmation."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if not approver.strip():
        stdout.write("error: --approver must name the human reviewer\n")
        return ReviewStatus.ERROR
    try:
        invariant = select_invariant(load_definitions(invariant_file), invariant_id)
    except Exception as exc:
        stdout.write(f"error: invalid invariant file: {exc}\n")
        return ReviewStatus.ERROR
    digest = invariant_content_digest(invariant)
    _show(invariant, digest, stdout)
    try:
        records = load_approvals(approvals_file)
    except Exception as exc:
        stdout.write(f"error: cannot load approvals: {exc}\n")
        return ReviewStatus.ERROR
    previous = find_approval(records, invariant.invariant_id, invariant.version)
    if previous is None:
        stdout.write("previous-approval: none\n")
    elif previous.content_digest == digest:
        stdout.write(
            f"previous-approval: MATCH by {previous.approver} at {previous.approved_at} "
            f"via {previous.method}\n"
        )
        stdout.write("already approved for this exact content; nothing to do\n")
        return ReviewStatus.ALREADY_APPROVED
    else:
        stdout.write(
            f"previous-approval: STALE by {previous.approver} at {previous.approved_at} "
            "(content changed; new approval required)\n"
        )
    stdout.write(
        f"Approve {invariant.invariant_id} v{invariant.version} "
        f"({digest[:12]}...) as {approver}? [y/N]: "
    )
    stdout.flush()
    answer = stdin.readline().strip().lower()
    if answer not in ("y", "yes"):
        stdout.write("approval declined\n")
        return ReviewStatus.DECLINED
    try:
        approval = create_approval(
            invariant,
            approver=approver,
            approved_at=datetime.now(UTC).isoformat(),
            method="cli-review",
        )
        save_approvals(approvals_file, upsert_approval(records, approval))
    except Exception as exc:
        stdout.write(f"error: cannot record approval: {exc}\n")
        return ReviewStatus.ERROR
    stdout.write(
        f"approved {approval.invariant_id} v{approval.invariant_version} "
        f"by {approval.approver} at {approval.approved_at}\n"
    )
    return ReviewStatus.APPROVED
