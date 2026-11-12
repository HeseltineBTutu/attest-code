"""Parent-observed elapsed-time spans for verification benchmarking.

:class:`TimingCollector` records how long each verification attempt
and the overall ``run_verify`` operation take, using
:func:`time.monotonic` like the existing supervision and scope code.
Spans serialize to a JSON Lines sidecar that stays separate from
authoritative evidence: timing is observational, never a verdict
input, and timer failures must never change a verification result.

Deliberate limitations: parent-observed attempt durations include
process spawn, supervision, teardown, and result handling — they
cannot isolate actual worker function execution, so no
worker-execution metric exists here. Worker self-reported timing
would be untrusted worker output, not evidence. Timeout spans are
flagged ``censored`` because a deadline cut-off is a lower bound on
completion time, not a completed sample; see ``TIMEOUT_DETAIL_PREFIX``.
"""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path

from attest_spec import AttemptOutcome

TIMEOUT_DETAIL_PREFIX = "worker exceeded "
"""Parent-constructed timeout detail prefix (see ``bounds.run_bounded``).

Matched only on infrastructure-failure spans to label censored
timeout samples. Pinned by regression test: if the constructing
message in ``bounds.py`` changes shape, timeout labeling fails
loudly instead of silently mislabeling samples. A worker-crafted
error envelope could mimic the prefix; the label stays
observational and never feeds verdict logic.
"""

_TIMEOUT_OUTCOME = "TIMEOUT"
"""Observational timeout label; verdict-wise an infrastructure failure."""

_FRACTION_DIGITS = 9
"""Fixed decimal places for second quantities in sidecar records."""


class TimingError(Exception):
    """Collector misuse: double start, stop without start, or span mismatch."""


def _decimal_seconds(value: float) -> str:
    """Format seconds as a fixed-point decimal string, never NaN/inf/negative."""
    if value == float("inf") or not (value >= 0.0):
        value = 0.0
    return f"{value:.{_FRACTION_DIGITS}f}"


class TimingCollector:
    """Accumulates attempt and total spans for one verification run.

    The collector is single-shot and single-threaded like its
    callers: attempts open and close in order, the total opens once
    around the run, and misuse raises :class:`TimingError` instead of
    corrupting records. ``profile`` and ``timeout_seconds`` are
    observational context recorded verbatim, never decisions.
    """

    def __init__(self, *, profile: str, timeout_seconds: float) -> None:
        self._profile = profile
        self._timeout_s = _decimal_seconds(timeout_seconds)
        self._attempts: list[dict[str, object]] = []
        self._open_attempt: tuple[int, float] | None = None
        self._total_start: float | None = None
        self._total_elapsed: str | None = None

    def start_attempt(self, attempt: int) -> None:
        """Open the span for one attempt; attempts must not overlap."""
        if self._open_attempt is not None:
            raise TimingError("attempt span already open")
        self._open_attempt = (attempt, time.monotonic())

    def try_start_attempt(self, attempt: int) -> None:
        """Best-effort span open for instrumentation; misuse is dropped, never raised."""
        with contextlib.suppress(TimingError):
            self.start_attempt(attempt)

    def stop_attempt(self, attempt: int, *, outcome: AttemptOutcome, detail: str) -> None:
        """Close the open span, labeling timeouts as censored samples."""
        opened = self._open_attempt
        if opened is None:
            raise TimingError("no open attempt span")
        if opened[0] != attempt:
            raise TimingError("attempt number mismatch")
        self._open_attempt = None
        elapsed = _decimal_seconds(time.monotonic() - opened[1])
        if outcome is AttemptOutcome.INFRA_FAILURE and detail.startswith(TIMEOUT_DETAIL_PREFIX):
            label, censored = _TIMEOUT_OUTCOME, True
        else:
            label, censored = outcome.value, False
        self._attempts.append(
            {
                "record_type": "attempt",
                "attempt": attempt,
                "elapsed_s": elapsed,
                "outcome": label,
                "censored": censored,
                "profile": self._profile,
                "timeout_s": self._timeout_s,
            }
        )

    def try_stop_attempt(self, attempt: int, *, outcome: AttemptOutcome, detail: str) -> None:
        """Best-effort span close for instrumentation; misuse is dropped, never raised."""
        with contextlib.suppress(TimingError):
            self.stop_attempt(attempt, outcome=outcome, detail=detail)

    def start_total(self) -> None:
        """Open the whole-run span exactly once."""
        if self._total_start is not None:
            raise TimingError("total span already started")
        self._total_start = time.monotonic()

    def stop_total(self) -> None:
        """Close the whole-run span exactly once."""
        if self._total_start is None or self._total_elapsed is not None:
            raise TimingError("total span not started or already stopped")
        self._total_elapsed = _decimal_seconds(time.monotonic() - self._total_start)

    def try_start_total(self) -> None:
        """Best-effort total open for instrumentation; misuse is dropped, never raised."""
        with contextlib.suppress(TimingError):
            self.start_total()

    def try_stop_total(self) -> None:
        """Best-effort total close for instrumentation; misuse is dropped, never raised."""
        with contextlib.suppress(TimingError):
            self.stop_total()

    def to_jsonl(self) -> str:
        """Serialize attempt records plus the total record as JSON Lines."""
        if self._total_elapsed is None:
            raise TimingError("total span incomplete")
        lines = [json.dumps(record) for record in self._attempts]
        lines.append(
            json.dumps(
                {
                    "record_type": "total",
                    "elapsed_s": self._total_elapsed,
                    "profile": self._profile,
                }
            )
        )
        return "\n".join(lines) + "\n"

    def write_jsonl(self, path: Path) -> None:
        """Write the sidecar, refusing to overwrite an existing destination.

        Raises :class:`TimingError` for incomplete spans and
        :class:`OSError` (including :class:`FileExistsError`) for
        filesystem failures; the caller reports these without
        affecting verification.
        """
        payload = self.to_jsonl()
        with open(path, "x", encoding="utf-8") as handle:
            handle.write(payload)
