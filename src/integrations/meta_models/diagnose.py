"""FAILED-gated diagnosis orchestration.

Glue between a verify JSON report and the model client: confirm the
report is a shape-valid FAILED, build a minimized prompt, validate the
reply, and render it for human review. The report is operator-supplied
JSON; it is validated for shape, not attestation-verified here, and it
influences only the diagnostic prompt — never any verdict or evidence.
This module never verdicts, never writes the repository, and never
applies patches.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from typing import Any

from integrations.meta_models.client import MetaModelsClient
from integrations.meta_models.protocol import (
    ALLOWED_DIFF_PREFIXES,
    MAX_VERDICT_SUMMARY,
    ModelReply,
    build_chat_payload,
    parse_model_reply,
    require_text,
    validate_diff,
)

REPORT_SCHEMA_VERSION = 1
"""Accepted `attest verify --format json` schema (mirrors apps.output)."""

MAX_REASON_CHARS = 2000
MAX_ATTEMPT_DETAIL_CHARS = 1000

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class DiagnosisError(Exception):
    """The diagnosis workflow refused to proceed (fail closed)."""


@dataclasses.dataclass(frozen=True)
class FailedSummary:
    """Minimized, bounded account of one FAILED verification."""

    invariant_id: str
    invariant_version: int
    invariant_digest: str
    revision: str
    reason: str
    failing_details: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Diagnosis:
    """A validated model proposal awaiting human review (never a verdict)."""

    diagnosis: str
    diff: str
    model: str
    invariant_id: str
    invariant_version: int


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def summarize_failed_report(report: Mapping[str, Any]) -> FailedSummary:
    """Accept only a schema-v1 FAILED verify report; refuse anything else.

    INCONCLUSIVE is refused explicitly: it records incomplete evidence,
    not a failure, and must never be relabeled failed or repaired.
    """
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise DiagnosisError(f"unsupported report schema_version {report.get('schema_version')!r}")
    if report.get("command") != "verify":
        raise DiagnosisError(f"unsupported report command {report.get('command')!r}")
    verdict = report.get("verdict")
    if verdict == "INCONCLUSIVE":
        raise DiagnosisError(
            "refusing to diagnose an INCONCLUSIVE result: evidence is incomplete, "
            "so the code is neither failed nor repaired"
        )
    if verdict == "PASSED":
        raise DiagnosisError("refusing to diagnose a PASSED result: nothing to repair")
    if verdict != "FAILED":
        raise DiagnosisError(f"unsupported report verdict {verdict!r}")
    invariant = report.get("invariant")
    if not isinstance(invariant, dict):
        raise DiagnosisError("report has no invariant record")
    invariant_id = invariant.get("id")
    invariant_version = invariant.get("version")
    digest = invariant.get("content_digest")
    if not isinstance(invariant_id, str) or not invariant_id.strip():
        raise DiagnosisError("report invariant id is missing")
    if (
        isinstance(invariant_version, bool)
        or not isinstance(invariant_version, int)
        or invariant_version < 1
    ):
        raise DiagnosisError("report invariant version is missing")
    if not isinstance(digest, str) or not _DIGEST.match(digest):
        raise DiagnosisError("report invariant content_digest is malformed")
    revision = report.get("revision")
    if not isinstance(revision, str) or not revision.strip():
        raise DiagnosisError("report revision is missing")
    reason = report.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise DiagnosisError("report reason is missing")
    attempts = report.get("attempts")
    if not isinstance(attempts, list):
        raise DiagnosisError("report attempts record is malformed")
    failing = tuple(
        _truncate(str(entry.get("detail", "")).strip(), MAX_ATTEMPT_DETAIL_CHARS)
        for entry in attempts
        if isinstance(entry, dict) and entry.get("outcome") == "VIOLATION"
    )
    if not failing:
        raise DiagnosisError("FAILED report records no violations; refusing to proceed")
    return FailedSummary(
        invariant_id=invariant_id.strip(),
        invariant_version=invariant_version,
        invariant_digest=digest,
        revision=revision.strip(),
        reason=_truncate(reason.strip(), MAX_REASON_CHARS),
        failing_details=failing,
    )


def build_verdict_summary(summary: FailedSummary) -> str:
    """Render the minimized summary sent to the model (bounded)."""
    lines = [
        f"verdict: FAILED (revision {summary.revision})",
        f"invariant: {summary.invariant_id} v{summary.invariant_version}",
        f"invariant content digest: {summary.invariant_digest}",
        f"reason: {summary.reason}",
        "failing attempts:",
        *[f"- {detail}" for detail in summary.failing_details],
    ]
    text = "\n".join(lines)
    return require_text(text, name="verdict_summary", maximum=MAX_VERDICT_SUMMARY)


def diagnose(
    client: MetaModelsClient,
    *,
    invariant_id: str,
    invariant_version: int,
    invariant_text: str,
    verdict_summary: str,
    code_excerpt: str,
    allowed_prefixes: tuple[str, ...] = ALLOWED_DIFF_PREFIXES,
) -> Diagnosis:
    """Request one diagnosis and validate the reply.

    Inputs are bounded and the reply's diff is structurally validated
    and scope-confined. The result is a proposal for human review only.
    """
    payload = build_chat_payload(
        model=client.model,
        invariant_id=invariant_id,
        invariant_version=invariant_version,
        invariant_text=invariant_text,
        verdict_summary=verdict_summary,
        code_excerpt=code_excerpt,
    )
    reply: ModelReply = parse_model_reply(client.complete(payload))
    diff = validate_diff(reply.diff, allowed_prefixes=allowed_prefixes)
    return Diagnosis(
        diagnosis=reply.diagnosis,
        diff=diff,
        model=client.model,
        invariant_id=invariant_id.strip(),
        invariant_version=invariant_version,
    )


def render_for_review(diagnosis: Diagnosis) -> str:
    """Render the proposal for a human reviewer.

    The banner states the trust status explicitly: this is an unverified
    model proposal. It becomes a repair only after a human applies it,
    commits a new revision, and Attest Code verifies that revision.
    """
    return (
        "UNVERIFIED MODEL PROPOSAL — NOT A REPAIR\n"
        f"invariant: {diagnosis.invariant_id} v{diagnosis.invariant_version}\n"
        f"model: {diagnosis.model}\n"
        "\ndiagnosis:\n"
        f"{diagnosis.diagnosis}\n"
        "\nproposed diff (review; do not apply blindly):\n"
        f"{diagnosis.diff}"
        "\nNext: a human applies the patch, commits revision R+1, and\n"
        "Attest Code independently verifies R+1 before any repaired claim.\n"
    )
