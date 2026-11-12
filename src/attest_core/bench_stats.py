"""Benchmark-run statistical aggregation over parent-observed timing.

Pure functions: parse timing sidecar JSONL into observations, then
summarize successful samples with exact decimal arithmetic. Successful
means a completed, uncensored execution (``PASS`` or ``VIOLATION``) —
a measurement-validity rule, never a verdict claim. Failed, censored,
and malformed inputs stay counted and retained; nothing is silently
discarded. Summaries are separate artifacts: raw observations are
never modified. Deterministic output: fixed key order, canonical
decimals, sorted counts.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation, localcontext
from typing import Any

_KNOWN_OUTCOMES = frozenset({"PASS", "VIOLATION", "INFRA_FAILURE", "TIMEOUT"})

_SUCCESSFUL_OUTCOMES = frozenset({"PASS", "VIOLATION"})

_TWELVE_PLACES = Decimal("0.000000000001")


class BenchStatsError(Exception):
    """Integrity or argument error: duplicates, bad quorum, invalid values."""


@dataclass(frozen=True)
class Observation:
    """One timed repetition: identity, exact duration, outcome, censor flag."""

    repetition: int
    elapsed_s: Decimal
    outcome: str
    censored: bool

    def __post_init__(self) -> None:
        if isinstance(self.repetition, bool) or not isinstance(self.repetition, int):
            raise BenchStatsError("repetition must be an int")
        if not isinstance(self.elapsed_s, Decimal):
            raise BenchStatsError("elapsed_s must be a Decimal")
        if not self.elapsed_s.is_finite():
            raise BenchStatsError("elapsed_s must be finite")
        if self.elapsed_s.is_signed() and self.elapsed_s.is_zero():
            raise BenchStatsError("elapsed_s must not be negative zero")
        if self.elapsed_s < 0:
            raise BenchStatsError("elapsed_s must not be negative")
        if not isinstance(self.outcome, str) or self.outcome not in _KNOWN_OUTCOMES:
            raise BenchStatsError(f"unknown outcome: {self.outcome!r}")
        if not isinstance(self.censored, bool):
            raise BenchStatsError("censored must be a bool")


def _canonical(value: Decimal) -> str:
    """Half-even to 12 places with trailing zeros stripped, never negative zero."""
    with localcontext() as context:
        context.prec = 50
        rounded = value.quantize(_TWELVE_PLACES, rounding=ROUND_HALF_EVEN).normalize()
    rounded = abs(rounded) if rounded.is_zero() else rounded
    return format(rounded, "f")


def _problem(line_no: int, raw: str, reason: str) -> dict[str, Any]:
    return {"line": line_no, "raw": raw, "reason": reason}


def _parse_attempt(record: dict[str, Any]) -> Observation | str:
    """Build an observation from one attempt record, or return the reason.

    Value validation delegates to Observation (``invalid:`` reasons).
    """
    try:
        attempt = record["attempt"]
        raw_elapsed = record["elapsed_s"]
        outcome = record["outcome"]
        censored = record["censored"]
    except KeyError as exc:
        return f"missing-field:{exc.args[0]}"
    if not isinstance(raw_elapsed, str):
        return "invalid-type:elapsed_s"
    try:
        elapsed = Decimal(raw_elapsed)
        return Observation(
            repetition=attempt, elapsed_s=elapsed, outcome=outcome, censored=censored
        )
    except InvalidOperation:
        return "invalid-decimal:elapsed_s"
    except BenchStatsError as exc:
        return f"invalid:{exc}"


def parse_timing_jsonl(text: str) -> tuple[list[Observation], list[dict[str, Any]]]:
    """Parse attempt records; every other line is retained with its reason.

    Total records are not repetitions: they are retained under a
    ``skipped:`` reason rather than dropped. Duplicate repetition ids
    reject the whole set with :class:`BenchStatsError`.
    """
    observations: list[Observation] = []
    unparsed: list[dict[str, Any]] = []
    seen: set[int] = set()
    for line_no, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            unparsed.append(_problem(line_no, raw, "blank-line"))
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            unparsed.append(_problem(line_no, raw, f"invalid-json:{exc.msg}"))
            continue
        if not isinstance(record, dict):
            unparsed.append(_problem(line_no, raw, "not-an-object"))
            continue
        kind = record.get("record_type")
        if kind != "attempt":
            if kind == "total":
                reason = "skipped:record-type-total"
            elif "record_type" not in record:
                reason = "missing-field:record_type"
            elif not isinstance(kind, str):
                reason = "invalid-type:record_type"
            else:
                reason = f"unknown-record-type:{kind[:40]}"
            unparsed.append(_problem(line_no, raw, reason))
            continue
        parsed = _parse_attempt(record)
        if isinstance(parsed, str):
            unparsed.append(_problem(line_no, raw, parsed))
            continue
        if parsed.repetition in seen:
            raise BenchStatsError(f"duplicate repetition: {parsed.repetition}")
        seen.add(parsed.repetition)
        observations.append(parsed)
    return observations, unparsed


def summarize(
    observations: Sequence[Observation],
    *,
    required_successful: int,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize successful samples; pure, deterministic, nothing discarded.

    ``complete`` is quorum only, never acceptance. ``context`` echoes
    verbatim; ``unparsed`` stays empty (callers attach parse problems).
    """
    if isinstance(required_successful, bool) or not isinstance(required_successful, int):
        raise BenchStatsError("required_successful must be an int")
    if required_successful < 1:
        raise BenchStatsError("required_successful must be positive")
    if context is not None and not isinstance(context, Mapping):
        raise BenchStatsError("context must be a mapping or None")
    items = list(observations)
    seen: set[int] = set()
    for observation in items:
        if not isinstance(observation, Observation):
            raise BenchStatsError("observations must be Observation instances")
        if observation.repetition in seen:
            raise BenchStatsError(f"duplicate repetition: {observation.repetition}")
        seen.add(observation.repetition)
    successful = sorted(
        o.elapsed_s for o in items if o.outcome in _SUCCESSFUL_OUTCOMES and not o.censored
    )
    counts = dict(sorted(Counter(o.outcome for o in items).items()))
    n_successful = len(successful)
    if n_successful:
        low, high = successful[0], successful[-1]
        with localcontext() as computation:
            computation.prec = 50
            if n_successful % 2:
                median = successful[n_successful // 2]
            else:
                pair = successful[n_successful // 2 - 1 : n_successful // 2 + 1]
                median = (pair[0] + pair[1]) / 2
            spread = high - low
        stats: dict[str, Any] = {
            "min_s": _canonical(low),
            "median_s": _canonical(median),
            "max_s": _canonical(high),
            "range_s": _canonical(spread),
        }
    else:
        stats = {"min_s": None, "median_s": None, "max_s": None, "range_s": None}
    return {
        "n_total": len(items),
        "n_successful": n_successful,
        "outcome_counts": counts,
        **stats,
        "required_successful": required_successful,
        "complete": n_successful >= required_successful,
        "context": dict(context) if context is not None else {},
        "unparsed": [],
    }
