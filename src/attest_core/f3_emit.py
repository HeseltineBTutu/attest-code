"""F3 validation report emission: canonical JSON over stdout (§8.2).

Serializes ValidationReport mechanically and writes canonical bytes
plus a trailing newline to a binary stream. Field names come from
the report types by construction (plus the derived severity key),
so emission cannot drift from the implementation. No report
digests: the design defines digests for records, manifests, and
evidence only. NFC normalization is the prescribed mechanism's
specified behavior (§8.2 lossiness analysis).
"""

from __future__ import annotations

import dataclasses
import sys
from typing import Any, BinaryIO

from attest_core.f3_report import ValidationReport
from attest_sdk import canonical


def to_jsonable(report: ValidationReport) -> dict[str, Any]:
    """Project a report to plain JSON-model values (report untouched).

    Tuples spell as lists; None stays null and is never omitted.
    Severity rides along explicitly: it is a derived property that
    dataclass projection would otherwise drop.
    """
    projected = {key: _lists(item) for key, item in dataclasses.asdict(report).items()}
    projected["severity"] = report.severity
    return projected


def _lists(value: Any) -> Any:
    """Recursively spell tuples as lists (canonical has no tuples)."""
    if isinstance(value, dict):
        return {key: _lists(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_lists(item) for item in value]
    return value


def emit_report(report: ValidationReport, stream: BinaryIO | None = None) -> None:
    """Write canonical report bytes plus newline (failures propagate)."""
    target = sys.stdout.buffer if stream is None else stream
    target.write(canonical.canonicalize(to_jsonable(report)) + b"\n")
