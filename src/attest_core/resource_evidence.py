"""Per-attempt resource evidence: scope counters as a separate field.

Collection runs after supervision, before scope teardown, so counters
describe exactly the attempt whose scope is named. The annotation lives
in ``AttemptReport.resources`` (and the attempt-summary evidence
record), never in ``detail``: worker output stays byte-identical while
resource evidence remains attached, bounded, and attested. Missing
scopes and read failures yield explicit ``unavailable(...)`` markers
with clipped reasons — never fabricated zeros. Counters are evidence
only; they never select a verdict.

The wire shape is one line: ``[resources] k=v ...`` with event
counters, peak metrics (see :mod:`attest_core.scope_metrics`), and a
teardown token appended after the scope stops. :func:`parse_resources`
reads the line back for cross-attempt comparison; tokens absent from
older records parse as None, never zero.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from attest_core import scope_metrics, scopes
from attest_core.verification import AttemptReport

_MAX_REASON_CHARS = 80
"""Longest failure reason kept in an unavailable marker."""

_METRIC_KEYS = (
    "oom",
    "oom_kill",
    "pids_max",
    "throttled_usec",
    "mem_peak",
    "pids_peak",
    "cpu_usec",
)
"""Integer metric tokens in wire order; teardown parses separately."""


def collect_resources(unit: str | None) -> str:
    """Format this attempt's scope counters; ``""`` when no scope ran.

    Events and peaks are read from the same live scope before
    teardown; any failure becomes an explicit unavailable marker.
    Empty string keeps non-quota reports identical. Never raises.
    """
    if unit is None:
        return ""
    path = scopes.find_scope(unit)
    if path is None:
        return "[resources] unavailable(scope-gone-before-collection)"
    try:
        events = scopes.read_scope_events(path)
        peaks = scope_metrics.read_peaks(path)
    except scopes.ScopeError as exc:
        reason = str(exc)[:_MAX_REASON_CHARS]
        return f"[resources] unavailable({reason})"
    tokens = [f"{key}={events[key]}" for key in _METRIC_KEYS[:4]]
    tokens += [f"{key}={peaks[key]}" for key in _METRIC_KEYS[4:]]
    return "[resources] " + " ".join(tokens)


def mark_teardown(resources: str, error: str | None) -> str:
    """Append the scope-teardown outcome; never raises, never empty-handed.

    ``None`` means the scope stopped and verified empty; a message
    names the failure (clipped). Applied exactly once per quota
    attempt, after the scope stops.
    """
    if error is None:
        token = "teardown=empty-verified"
    else:
        token = f"teardown=failed({error[:_MAX_REASON_CHARS]})"
    if not resources:
        return f"[resources] {token}"
    return f"{resources} {token}"


def parse_resources(text: str) -> dict[str, Any]:
    """Parse a resources line back into metrics for comparison.

    Every known metric key is present; absent or malformed values
    are None (missing data is not zero). ``teardown`` is terminal
    by construction, so everything after its marker is kept
    verbatim, spaces included; ``unavailable`` carries the marker
    reason or None. Unknown tokens are ignored so old and new
    records mix.
    """
    parsed: dict[str, Any] = dict.fromkeys(_METRIC_KEYS)
    parsed["teardown"] = None
    parsed["unavailable"] = None
    body = text[len("[resources]") :].strip() if text.startswith("[resources]") else text
    if body.startswith("unavailable("):
        rest = body[len("unavailable(") :]
        cut = rest.find(" teardown=")
        reason = rest if cut < 0 else rest[:cut]
        parsed["unavailable"] = reason[:-1] if reason.endswith(")") else reason
        body = "" if cut < 0 else rest[cut:].strip()
    if body.startswith("teardown="):
        parsed["teardown"] = body[len("teardown=") :] or None
        body = ""
    else:
        head, sep, tail = body.partition(" teardown=")
        if sep:
            parsed["teardown"] = tail or None
            body = head
    for token in body.split():
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        if key in _METRIC_KEYS:
            try:
                parsed[key] = int(value)
            except ValueError:
                parsed[key] = None
    return parsed


def with_resources(report: AttemptReport, resources: str) -> AttemptReport:
    """Attach parent-collected resource evidence; detail stays untouched."""
    if not resources:
        return report
    return dataclasses.replace(report, resources=resources)
