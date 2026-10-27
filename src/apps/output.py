"""Verification report rendering: human-readable text and versioned JSON.

Both formats print the verdict, invariant identity, recorded revision,
configuration digest, per-attempt outcomes, scope coverage, and evidence
digests. Neither format exposes secrets. JSON uses sorted keys so output
is deterministic where the underlying data is.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from attest_core.invariants import invariant_content_digest
from attest_core.verification import ATTEMPT_SUMMARY_CHECK_ID, VerificationReport
from attest_spec import Invariant

OUTPUT_SCHEMA_VERSION = 1


def _attempt_details(report: VerificationReport) -> dict[int, str]:
    details: dict[int, str] = {}
    for record in report.evidence:
        if record.check_id == ATTEMPT_SUMMARY_CHECK_ID:
            details[record.attempt] = record.detail
    return details


def render_text(
    report: VerificationReport,
    *,
    invariant: Invariant,
    coverage: str,
    snapshot_changed: bool,
    stdout: TextIO | None = None,
) -> None:
    """Render the report as `key: value` lines."""
    stdout = sys.stdout if stdout is None else stdout
    details = _attempt_details(report)
    stdout.write(f"verdict: {report.verdict.value}\n")
    stdout.write(f"invariant: {invariant.invariant_id} v{invariant.version}\n")
    stdout.write(f"content-digest: {invariant_content_digest(invariant)}\n")
    stdout.write(f"revision: {report.revision}\n")
    stdout.write(f"config-digest: {report.config_digest}\n")
    stdout.write(f"scope: {', '.join(sorted(invariant.scope))} (coverage: {coverage})\n")
    stdout.write(f"snapshot-changed: {str(snapshot_changed).lower()}\n")
    stdout.write("attempts:\n")
    for index, attempt in enumerate(report.attempts, start=1):
        detail = details.get(index, "")
        stdout.write(
            f"  {index}: {attempt.outcome.value} evidence={attempt.evidence_hash} {detail}\n"
        )
    stdout.write("evidence:\n")
    for record in report.evidence:
        stdout.write(
            f"  {record.digest()} attempt={record.attempt} "
            f"check={record.check_id} target={record.target} outcome={record.outcome}\n"
        )
    stdout.write(f"attestation: {report.attestation.digest()}\n")
    stdout.write(f"reason: {report.reason}\n")


def render_json(
    report: VerificationReport,
    *,
    invariant: Invariant,
    coverage: str,
    snapshot_changed: bool,
    stdout: TextIO | None = None,
) -> None:
    """Render the report as versioned, deterministic JSON."""
    stdout = sys.stdout if stdout is None else stdout
    details = _attempt_details(report)
    payload: dict[str, Any] = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "command": "verify",
        "verdict": report.verdict.value,
        "reason": report.reason,
        "invariant": {
            "id": invariant.invariant_id,
            "version": invariant.version,
            "content_digest": invariant_content_digest(invariant),
        },
        "revision": report.revision,
        "snapshot_changed": snapshot_changed,
        "config_digest": report.config_digest,
        "scope": {"declared": sorted(invariant.scope), "coverage": coverage},
        "attempts": [
            {
                "index": index,
                "outcome": attempt.outcome.value,
                "evidence_hash": attempt.evidence_hash,
                "detail": details.get(index, ""),
            }
            for index, attempt in enumerate(report.attempts, start=1)
        ],
        "evidence_hashes": [record.digest() for record in report.evidence],
        "attestation_digest": report.attestation.digest(),
    }
    stdout.write(json.dumps(payload, sort_keys=True, indent=2))
    stdout.write("\n")
