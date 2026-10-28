"""Authoritative verification flow behind `attest verify`.

The flow refuses unverifiable setups instead of guessing: the invariant
must carry a valid approval for its exact content digest, and the working
tree must match the requested revision with no relevant uncommitted
changes. Checks run in bounded worker subprocesses; a source change
detected after the run overrides any verdict with INCONCLUSIVE.
"""

from __future__ import annotations

import atexit
import functools
import os
import shutil
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from apps.approvals import find_approval, load_approvals, select_invariant
from apps.output import render_json, render_text
from attest_core.bounds import run_bounded
from attest_core.evidence import ATTESTATION_SCHEMA_VERSION, Attestation
from attest_core.git import check_snapshot, fingerprint
from attest_core.invariants import (
    invariant_content_digest,
    is_approval_valid,
    load_definitions,
)
from attest_core.origin import (
    check_origins,
    prepare_worker_sys_path,
    probe_worker_origins,
    require_within_root,
    resolve_repo_root,
    verify_code_origin,
)
from attest_core.runtime import (
    check_environment,
    check_root_startup_modules,
    collect_runtime_settings,
)
from attest_core.snapshot import Snapshot, SnapshotError, build_snapshot, verify_snapshot
from attest_core.verdicts import REQUIRED_ATTEMPTS
from attest_core.verification import AttemptReport, VerificationReport, run_verification
from attest_spec import Invariant, Verdict
from examples.admin_authorization import run_target_attempt, scope_coverage

SNAPSHOT_CHANGED_REASON = "source snapshot changed during verification"


class VerifyError(Exception):
    """Raised when verification cannot authoritatively proceed."""


class SnapshotDriftError(Exception):
    """Raised when the source snapshot drifts during an attempt.

    Handled by the orchestrator's generic per-attempt path as an
    infrastructure failure (evidence preserved), so drift can only yield
    INCONCLUSIVE, never FAILED or PASSED.
    """


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
            content_digest=invariant_content_digest(invariant),
            evidence_hashes=tuple(record.digest() for record in report.evidence),
            statement=SNAPSHOT_CHANGED_REASON,
        ),
    )


def _settings(
    *,
    target: str,
    scope: tuple[str, ...],
    snapshot: str,
    snapshot_digest: str,
    timeout_seconds: float,
    runtime: Mapping[str, str],
) -> dict[str, str]:
    return {
        "checks": "scope-coverage,unauthenticated-rejected,non-admin-denied,admin-allowed",
        "client": "attest-cli",
        "scope": ",".join(sorted(scope)),
        "snapshot": snapshot,
        "snapshot.sha256": snapshot_digest,
        "target": target,
        "timeout_seconds": f"{timeout_seconds:g}",
        **runtime,
    }


def _guard_attempt_snapshot(root: Path, exec_snapshot: Snapshot, before: str) -> None:
    """Fail an attempt when live or snapshot bytes drifted past a boundary."""
    if fingerprint(root) != before:
        raise SnapshotDriftError(SNAPSHOT_CHANGED_REASON)
    try:
        verify_snapshot(exec_snapshot)
    except SnapshotError as exc:
        raise SnapshotDriftError(str(exc)) from exc


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
    # Pre-spawn preflight: refuse hostile startup modules before the first
    # child process (the origin probe) can execute them. Nothing above this
    # line spawns a Python interpreter; keep it that way.
    check_root_startup_modules(root)
    # Isolate worker bytecode caches in a fresh directory: workers must
    # neither read bytecode planted in the tree nor write caches into it.
    # The parent's own imports precede this (see trusted-launch boundary).
    cache_dir = tempfile.mkdtemp(prefix="attest-pycache-")
    os.environ["PYTHONPYCACHEPREFIX"] = cache_dir
    atexit.register(shutil.rmtree, cache_dir, True)
    invariant_file = require_within_root(invariant_file, root, "invariant file")
    approvals_file = require_within_root(approvals_file, root, "approvals file")
    invariant = select_invariant(load_definitions(invariant_file), invariant_id)
    stored = load_approvals(approvals_file)
    approval = find_approval(stored, invariant.invariant_id, invariant.version)
    if approval is None:
        raise VerifyError(f"no approval for {invariant.invariant_id} v{invariant.version}")
    if not is_approval_valid(invariant, approval):
        raise VerifyError("stored approval does not match invariant content")
    source = check_snapshot(root, revision)
    verify_code_origin(root, timeout_seconds)
    check_environment(root)
    runtime = collect_runtime_settings(root)
    exec_snapshot = build_snapshot(
        repo=root,
        head=source.revision,
        invariant=invariant,
        approval=approval,
        invariant_path=invariant_file,
    )
    check_snapshot(root, revision)
    prepare_worker_sys_path(exec_snapshot.root / "src", root)
    check_origins(
        probe_worker_origins(timeout_seconds), exec_snapshot.root, actor="snapshot worker"
    )
    before = fingerprint(root)
    scope = tuple(invariant.scope)

    def run_checks() -> AttemptReport:
        # Per-attempt drift detection against the clean baselines: live dirt
        # or snapshot tampering that persists past any attempt boundary
        # fails that attempt as an infrastructure failure. A change made
        # and reverted strictly inside one attempt remains invisible (see
        # security-model.md).
        _guard_attempt_snapshot(root, exec_snapshot, before)
        worker = functools.partial(run_target_attempt, target, scope)
        report = run_bounded(worker, timeout_seconds, snapshot_root=exec_snapshot.root)
        _guard_attempt_snapshot(root, exec_snapshot, before)
        return report

    report = run_verification(
        invariant=invariant,
        approval=approval,
        revision=source.revision,
        settings=_settings(
            target=target,
            scope=scope,
            snapshot=source.revision,
            snapshot_digest=exec_snapshot.digest,
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
