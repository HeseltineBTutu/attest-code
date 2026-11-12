"""Repetition composition over timing sidecars from multiple invocations.

Pure helpers: parse each caller-ordered JSONL text independently,
renumber observations sequentially in declared order, keep a
provenance ledger mapping every repetition back to its source
position and original attempt number, and compose summaries with
all parser problems attached. Sequential integers are deterministic
aggregation bookkeeping, never inferred invocation identity and
never a claim of statistical independence. Warm-up invocations are
excluded as whole sources by the caller; nothing here infers them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from attest_core.bench_stats import (
    BenchStatsError,
    Observation,
    parse_timing_jsonl,
    summarize,
)


def load_repetitions(
    timing_texts: Sequence[str],
) -> tuple[list[Observation], list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse ordered sidecar texts into observations, problems, and provenance.

    ``timing_texts`` is an explicitly ordered sequence; its 1-based
    position is each source's declared identity. Every parser problem
    is retained with its ``source_position``, original line number,
    raw input, and reason. Within-source duplicate attempts raise
    :class:`BenchStatsError` without silent recovery.
    """
    if isinstance(timing_texts, (str, bytes)) or not isinstance(timing_texts, Sequence):
        raise BenchStatsError("timing_texts must be a sequence of strings")
    observations: list[Observation] = []
    unparsed: list[dict[str, Any]] = []
    provenance: list[dict[str, Any]] = []
    repetition = 0
    for position, text in enumerate(timing_texts, start=1):
        if not isinstance(text, str):
            raise BenchStatsError(f"source {position}: expected str, got {type(text).__name__}")
        parsed, problems = parse_timing_jsonl(text)
        for problem in problems:
            unparsed.append({"source_position": position, **problem})
        for observation in parsed:
            repetition += 1
            observations.append(
                Observation(
                    repetition=repetition,
                    elapsed_s=observation.elapsed_s,
                    outcome=observation.outcome,
                    censored=observation.censored,
                )
            )
            provenance.append(
                {
                    "repetition": repetition,
                    "source_position": position,
                    "attempt": observation.repetition,
                }
            )
    return observations, unparsed, provenance


def build_summary(
    timing_texts: Sequence[str],
    *,
    required_successful: int,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose parsed observations into a summary with problems attached.

    Single public composition entry point: loads repetitions, runs
    the unchanged statistical summary, attaches every source-tagged
    parser problem under ``unparsed`` and the provenance ledger under
    ``provenance``. Caller inputs are never mutated.
    """
    observations, unparsed, provenance = load_repetitions(timing_texts)
    summary = summarize(observations, required_successful=required_successful, context=context)
    summary["unparsed"] = unparsed
    summary["provenance"] = provenance
    return summary
