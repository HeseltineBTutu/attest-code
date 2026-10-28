"""Authoritative verification flow behind `attest verify`.

The flow refuses unverifiable setups instead of guessing: the invariant
must carry a valid approval for its exact content digest, and the working
tree must match the requested revision with no relevant uncommitted
changes. Checks run in bounded worker subprocesses; a source change
detected after the run overrides any verdict with INCONCLUSIVE.
"""

from __future__ import annotations

import functools
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from apps.approvals import find_approval, load_approvals, select_invariant
from apps.output import render_json, render_text
from attest_core.bounds import run_bounded
from attest_core.evidence import ATTESTATION_SCHEMA_VERSION, Attestation
from attest_core.git import check_snapshot, fingerprint
from attest_core.invariants import is_approval_valid, load_definitions
from attest_core.origin import (
    require_within_root,
    resolve_repo_root,
    verify_code_origin,
)
from attest_core.runtime import check_environment, collect_runtime_settings
from attest_core.verdicts import REQUIRED_ATTEMPTS
from attest_core.verification import AttemptReport, VerificationReport, run_verification
from attest_spec import Invariant, Verdict
from examples.admin_authorization import run_target_attempt, scope_coverage

SNAPSHOT_CHANGED_REASON = "source snapshot changed during verification"


class VerifyError(Exception):
    """Raised when verification cannot authoritatively proceed."""


def apply_snapshot_override(report: VerificationReport, invariant: Invariant) -> VerificationReport:
    """Discard a verdict over mid-run source drift (pure; keeps the evidence)."""
    return VerificationReport(
        verdict=Verdict.INCONCLUSIVE,
        reason=SNAPSHOT_CHANGED_REASON,
        revision=report.revision,
        config_digest=report.config_digest,
        attempts=report.attempts,
        evidence=report.evidence,
        attestation=Attestation(
            schema_version=ATTESTATION_SCHEMA_VERSION,
            verdict=Verdict.INCONCLUSIVE.value,
            invariant_id=invariant.invariant_id,
            invariant_version=invariant.version,
            evidence_hashes=tuple(record.digest() for record in report.evidence),
            statement=SNAPSHOT_CHANGED_REASON,
        ),
    )


def _settings(
    *,
    target: str,
    scope: tuple[str, ...],
    snapshot: str,
    timeout_seconds: float,
    runtime: Mapping[str, str],
) -> dict[str, str]:
    return {
        "checks": "scope-coverage,unauthenticated-rejected,non-admin-denied,admin-allowed",
        "client": "attest-cli",
        "scope": ",".join(sorted(scope)),
        "snapshot": snapshot,
        "target": target,
        "timeout_seconds": f"{timeout_seconds:g}",
        **runtime,
    }


def run_verify(
    *,
    invariant_file: Path,
    approvals_file: Path,
    invariant_id: str | None,
    revision: str,
    repo: Path,
    target: str,
    timeout_seconds: float,
    output_format: str,
    stdout: TextIO | None = None,
) -> Verdict:
    """Verify the demo target; return the authoritative verdict."""
    stdout = sys.stdout if stdout is None else stdout
    if timeout_seconds <= 0:
        raise VerifyError("timeout must be positive")
    if output_format not in ("text", "json"):
        raise VerifyError(f"unknown format: {output_format}")
    root = resolve_repo_root(repo)
    invariant_file = require_within_root(invariant_file, root, "invariant file")
    approvals_file = require_within_root(approvals_file, root, "approvals file")
    invariant = select_invariant(load_definitions(invariant_file), invariant_id)
    stored = load_approvals(approvals_file)
    approval = find_approval(stored, invariant.invariant_id, invariant.version)
    if approval is None:
        raise VerifyError(f"no approval for {invariant.invariant_id} v{invariant.version}")
    if not is_approval_valid(invariant, approval):
        raise VerifyError("stored approval does not match invariant content")
    snapshot = check_snapshot(root, revision)
    verify_code_origin(root, timeout_seconds)
    check_environment(root)
    runtime = collect_runtime_settings(root)
    before = fingerprint(root)
    scope = tuple(invariant.scope)

    def run_checks() -> AttemptReport:
        worker = functools.partial(run_target_attempt, target, scope)
        return run_bounded(worker, timeout_seconds)

    report = run_verification(
        invariant=invariant,
        approval=approval,
        revision=snapshot.revision,
        settings=_settings(
            target=target,
            scope=scope,
            snapshot=snapshot.revision,
            timeout_seconds=timeout_seconds,
            runtime=runtime,
        ),
        run_checks=run_checks,
    )
    snapshot_changed = fingerprint(root) != before
    if snapshot_changed:
        report = apply_snapshot_override(report, invariant)
    coverage = scope_coverage(report.evidence, REQUIRED_ATTEMPTS)
    if output_format == "json":
        render_json(
            report,
            invariant=invariant,
            coverage=coverage,
            snapshot_changed=snapshot_changed,
            stdout=stdout,
        )
    else:
        render_text(
            report,
            invariant=invariant,
            coverage=coverage,
            snapshot_changed=snapshot_changed,
            stdout=stdout,
        )
    return report.verdict
