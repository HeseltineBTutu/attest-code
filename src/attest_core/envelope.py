"""Worker JSON result protocol (S1): bounded envelopes, strict validation.

Replaces pickle IPC for attempt results and origin probes. The worker
writes one JSON file; the parent reads it (bounded, after worker exit)
and validates it against exact schemas. Unknown protocol versions,
shapes, types, non-finite numbers, unknown fields, and oversized
content fail closed. A validated worker outcome is per-attempt input
only — verdicts stay parent-side.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from attest_core.verification import AttemptReport, CheckEvidence
from attest_spec import AttemptOutcome

SANDBOX_PROTOCOL_VERSION = 1
"""Version of the worker JSON result envelope; unknown versions are rejected."""

MAX_RESULT_BYTES = 262144
"""Largest accepted result file; larger results fail the attempt closed."""

MAX_DETAIL_CHARS = 16384
"""Longest accepted evidence detail string; longer details are rejected."""

MAX_ID_CHARS = 1024
"""Longest accepted check/target identifier in a worker report."""
_ERROR_KEYS = frozenset({"sandbox_protocol", "status", "detail"})
_OK_REPORT_KEYS = frozenset({"sandbox_protocol", "status", "report"})
_REPORT_KEYS = frozenset({"outcome", "checks", "detail"})
_CHECK_KEYS = frozenset({"check_id", "target", "passed", "detail"})
_OK_ORIGINS_KEYS = frozenset({"sandbox_protocol", "status", "origins"})
"""Exact envelope key sets; unknown fields are rejected."""


class SandboxEnvelopeError(Exception):
    """A worker result file is missing, oversized, or fails validation."""


def _reject_constant(value: str) -> Any:
    raise SandboxEnvelopeError(f"non-finite JSON constant in worker result: {value}")


def encode_attempt_report(report: AttemptReport) -> str:
    """Serialize an attempt report into the versioned JSON envelope."""
    return json.dumps(
        {
            "sandbox_protocol": SANDBOX_PROTOCOL_VERSION,
            "status": "ok",
            "report": {
                "outcome": report.outcome.value,
                "checks": [
                    {
                        "check_id": check.check_id,
                        "target": check.target,
                        "passed": check.passed,
                        "detail": check.detail,
                    }
                    for check in report.checks
                ],
                "detail": report.detail,
            },
        },
        sort_keys=True,
    )


def encode_error(detail: str) -> str:
    """Serialize a worker-side failure into the versioned JSON envelope."""
    return json.dumps(
        {"sandbox_protocol": SANDBOX_PROTOCOL_VERSION, "status": "error", "detail": detail},
        sort_keys=True,
    )


def encode_origins(origins: Mapping[str, str | None]) -> str:
    """Serialize a worker origin probe into the versioned JSON envelope."""
    return json.dumps(
        {
            "sandbox_protocol": SANDBOX_PROTOCOL_VERSION,
            "status": "ok",
            "origins": dict(origins),
        },
        sort_keys=True,
    )


def _require_text(value: Any, *, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise SandboxEnvelopeError(f"worker result field {name!r} must be a string")
    if len(value) > maximum:
        raise SandboxEnvelopeError(f"worker result field {name!r} exceeds {maximum} characters")
    return value


def _check_keys(payload: Any, expected: frozenset[str], *, name: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SandboxEnvelopeError(f"worker result {name} must be an object")
    keys = frozenset(payload)
    if keys != expected:
        raise SandboxEnvelopeError(f"worker result {name} has unexpected fields")
    return payload


def decode_attempt_report(text: str) -> AttemptReport:
    """Validate a worker result envelope; error envelopes become INFRA reports.

    Unknown protocol versions, shapes, types, or oversized fields fail
    closed. A worker-supplied outcome is per-attempt input only: the
    authoritative verdict is still derived parent-side by the policy.
    """
    if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
        raise SandboxEnvelopeError(f"worker result exceeds {MAX_RESULT_BYTES} bytes")
    try:
        data = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise SandboxEnvelopeError(f"worker result is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SandboxEnvelopeError("worker result must be an object")
    protocol = data.get("sandbox_protocol")
    if protocol != SANDBOX_PROTOCOL_VERSION or isinstance(protocol, bool):
        raise SandboxEnvelopeError("worker result has an unsupported protocol version")
    status = data.get("status")
    if status == "error":
        envelope = _check_keys(data, _ERROR_KEYS, name="error")
        detail = _require_text(envelope["detail"], name="detail", maximum=MAX_DETAIL_CHARS)
        return AttemptReport(AttemptOutcome.INFRA_FAILURE, (), f"worker error: {detail}")
    if status != "ok":
        raise SandboxEnvelopeError("worker result has an unknown status")
    envelope = _check_keys(data, _OK_REPORT_KEYS, name="report")
    report = _check_keys(envelope["report"], _REPORT_KEYS, name="report")
    outcome_value = report["outcome"]
    if not isinstance(outcome_value, str):
        raise SandboxEnvelopeError("worker result outcome must be a string")
    try:
        outcome = AttemptOutcome(outcome_value)
    except ValueError:
        raise SandboxEnvelopeError("worker result has an unknown outcome") from None
    if not isinstance(report["checks"], list):
        raise SandboxEnvelopeError("worker result checks must be a list")
    checks: list[CheckEvidence] = []
    for entry in report["checks"]:
        item = _check_keys(entry, _CHECK_KEYS, name="check")
        if not isinstance(item["passed"], bool):
            raise SandboxEnvelopeError("worker result check passed must be a boolean")
        checks.append(
            CheckEvidence(
                check_id=_require_text(item["check_id"], name="check_id", maximum=MAX_ID_CHARS),
                target=_require_text(item["target"], name="target", maximum=MAX_ID_CHARS),
                passed=item["passed"],
                detail=_require_text(item["detail"], name="detail", maximum=MAX_DETAIL_CHARS),
            )
        )
    detail = _require_text(report["detail"], name="detail", maximum=MAX_DETAIL_CHARS)
    return AttemptReport(outcome, tuple(checks), detail)


def decode_origins_envelope(text: str) -> Any:
    """Validate a probe envelope; returns the raw origins value for checks.

    Error envelopes raise with the worker detail; the caller maps them to
    its own failure type. Payload shape stays with the origin checks.
    """
    if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
        raise SandboxEnvelopeError(f"worker result exceeds {MAX_RESULT_BYTES} bytes")
    try:
        data = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise SandboxEnvelopeError(f"worker result is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SandboxEnvelopeError("worker result must be an object")
    protocol = data.get("sandbox_protocol")
    if protocol != SANDBOX_PROTOCOL_VERSION or isinstance(protocol, bool):
        raise SandboxEnvelopeError("worker result has an unsupported protocol version")
    status = data.get("status")
    if status == "error":
        envelope = _check_keys(data, _ERROR_KEYS, name="error")
        detail = _require_text(envelope["detail"], name="detail", maximum=MAX_DETAIL_CHARS)
        raise SandboxEnvelopeError(detail)
    if status != "ok":
        raise SandboxEnvelopeError("worker result has an unknown status")
    envelope = _check_keys(data, _OK_ORIGINS_KEYS, name="origins")
    return envelope["origins"]


def write_result_file(path: Path, payload: str) -> None:
    """Worker-side result write; oversized payloads fail closed, never truncated."""
    data = payload.encode("utf-8")
    if len(data) > MAX_RESULT_BYTES:
        raise SandboxEnvelopeError(f"worker result exceeds {MAX_RESULT_BYTES} bytes")
    path.write_bytes(data)


def read_result_file(path: Path) -> str:
    """Parent-side bounded result read; the worker must already have exited.

    Only regular files are read (lstat, never following symlinks), and at
    most one byte past the limit is ever buffered. A path swapped after
    this check needs a post-exit writer, which S1 process supervision
    does not provide — see security-model.md.
    """
    try:
        lstat = os.lstat(path)
    except OSError:
        raise SandboxEnvelopeError("worker result file is missing") from None
    if not stat.S_ISREG(lstat.st_mode):
        raise SandboxEnvelopeError("worker result file is not a regular file")
    if lstat.st_size > MAX_RESULT_BYTES:
        raise SandboxEnvelopeError(f"worker result exceeds {MAX_RESULT_BYTES} bytes")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_RESULT_BYTES + 1)
    except OSError as exc:
        raise SandboxEnvelopeError(f"worker result file is unreadable: {exc}") from exc
    if len(data) > MAX_RESULT_BYTES:
        raise SandboxEnvelopeError(f"worker result exceeds {MAX_RESULT_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SandboxEnvelopeError(f"worker result file is unreadable: {exc}") from exc
