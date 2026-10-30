"""Per-attempt resource evidence: scope counters as a separate field.

Collection runs after supervision, before scope teardown, so counters
describe exactly the attempt whose scope is named. The annotation lives
in ``AttemptReport.resources`` (and the attempt-summary evidence
record), never in ``detail``: worker output stays byte-identical while
resource evidence remains attached, bounded, and attested. Missing
scopes and read failures yield explicit ``unavailable(...)`` markers
with clipped reasons — never fabricated zeros. Counters are evidence
only; they never select a verdict.
"""

from __future__ import annotations

import dataclasses

from attest_core import scopes
from attest_core.verification import AttemptReport

_MAX_REASON_CHARS = 80
"""Longest failure reason kept in an unavailable marker."""


def collect_resources(unit: str | None) -> str:
    """Format this attempt's scope counters; ``""`` when no scope ran.

    Empty string keeps non-quota reports identical. Never raises: every
    failure mode becomes an explicit unavailable marker.
    """
    if unit is None:
        return ""
    path = scopes.find_scope(unit)
    if path is None:
        return "[resources] unavailable(scope-gone-before-collection)"
    try:
        events = scopes.read_scope_events(path)
    except scopes.ScopeError as exc:
        reason = str(exc)[:_MAX_REASON_CHARS]
        return f"[resources] unavailable({reason})"
    return (
        f"[resources] oom={events['oom']} oom_kill={events['oom_kill']} "
        f"pids_max={events['pids_max']} throttled_usec={events['throttled_usec']}"
    )


def with_resources(report: AttemptReport, resources: str) -> AttemptReport:
    """Attach parent-collected resource evidence; detail stays untouched."""
    if not resources:
        return report
    return dataclasses.replace(report, resources=resources)
