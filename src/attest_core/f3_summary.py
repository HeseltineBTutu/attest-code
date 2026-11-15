"""F3 per-series summary computation (§7.5, §10.4).

Builds one attempt-level descriptive summary over a single W3
series' bound observations: dimension refusal, series-membership
refusal, homogeneity refusal, measured/warmup partition, and
exact-decimal statistics. Set-internal membership (§10.4) is the
composer's own rule; record↔declaration agreement (R-ID9/R-ID11)
stays P3's domain. Never reads stored verifier verdicts (M2)
and never emits quorum fields (I9). Every emitted record passes
`validate_summary`, so malformed caller inputs (record_id,
campaign_id, context) fail as §7.5 schema violations.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from typing import Any

from attest_core.f3_errors import F3Error
from attest_core.f3_records import AttemptRecord
from attest_core.f3_records_summary import SummaryRecord, validate_summary
from attest_core.f3_series import display_key

STATISTIC_ATTEMPT = "attempt"
SERIES_METRIC = "latency"
_SUCCESSFUL_OUTCOMES = frozenset({"PASS", "VIOLATION"})
_TWELVE_PLACES = Decimal("0.000000000001")


@dataclasses.dataclass(frozen=True)
class ComposedSummary:
    """A composed series summary, or the explicit reason it is absent."""

    summary: SummaryRecord | None
    absent_reason: str | None

    def __post_init__(self) -> None:
        if (self.summary is None) == (self.absent_reason is None):
            raise ValueError("exactly one of summary/absent_reason must be set")


def mint_record_id() -> str:
    """Mint a fresh UUIDv4 summary record id (§5.1 composer minting)."""
    return str(uuid.uuid4())


def _canonical(value: Decimal) -> str:
    """Half-even to 12 places, trailing zeros stripped, never negative zero.

    Byte-identical to the bench_stats canonical decimals (parity is
    pinned by test); the 12-place cap never binds 9-place inputs
    whose even-count medians terminate within 10 places.
    """
    with localcontext() as context:
        context.prec = 50
        rendered = value.quantize(_TWELVE_PLACES, rounding=ROUND_HALF_EVEN).normalize()
    rendered = abs(rendered) if rendered.is_zero() else rendered
    return format(rendered, "f")


def compose_summary(
    records: Sequence[AttemptRecord],
    *,
    series_key: tuple[str, str, str, str, int],
    member_invocations: frozenset[str],
    campaign_id: str,
    record_id: str,
    statistic: str = STATISTIC_ATTEMPT,
    context: Mapping[str, str] | None = None,
) -> ComposedSummary:
    """Compose one series summary over its bound attempt records.

    `series_key` carries series membership (target plus workload
    triple plus ordinal); `member_invocations` is the series'
    invocation set. Warmup observations are excluded from every
    statistic and retained by id (§6.3, I2). Statistics cover the
    measured set: counts over all measured observations, latency
    extremes over successful ones only (§10.3).
    """
    if statistic != STATISTIC_ATTEMPT:
        raise F3Error(
            rule="COMPOSE",
            section="10.4",
            location="$.statistic",
            reason=(
                f"unsupported statistic {statistic!r}: v1 defines 'attempt' only "
                "(the invocation namespace is reserved, §11.3)"
            ),
        )
    for record in records:
        if not isinstance(record, AttemptRecord):
            raise F3Error(
                rule="COMPOSE",
                section="10.4",
                location="$",
                reason=(
                    "mixed-dimension observation set: "
                    f"{type(record).__name__} is not an attempt record"
                ),
            )
    stray = sorted(
        {item.record_id for item in records if item.invocation_id not in member_invocations}
    )
    if stray:
        raise F3Error(
            rule="COMPOSE",
            section="10.4",
            location="$",
            reason=(
                "observation set spans invocations outside series "
                f"{display_key(series_key)}: {', '.join(stray)}"
            ),
        )
    identity = series_key[:4]
    offenders = sorted(
        item.record_id
        for item in records
        if (item.target, item.workload_class, item.workload_id, item.input_digest) != identity
    )
    if offenders:
        raise F3Error(
            rule="COMPOSE",
            section="10.4",
            location="$",
            reason=(
                "mixed-target/mixed-workload observation set for series "
                f"{display_key(series_key)}: {', '.join(offenders)}"
            ),
        )
    measured = [item for item in records if item.sample_class == "measured"]
    observed = sorted(measured, key=lambda item: item.record_id)
    excluded = sorted(item.record_id for item in records if item.sample_class == "warmup")
    if not observed:
        return ComposedSummary(
            summary=None,
            absent_reason=(
                f"series {display_key(series_key)} has no measured observations "
                f"({len(excluded)} warmup records excluded, 0 measured)"
            ),
        )
    successful = sorted(
        Decimal(item.elapsed_s)
        for item in observed
        if not item.censored and item.outcome in _SUCCESSFUL_OUTCOMES
    )
    if not successful:
        return ComposedSummary(
            summary=None,
            absent_reason=(
                f"series {display_key(series_key)} has {len(observed)} measured "
                "observations but 0 successful: no descriptive statistics defined"
            ),
        )
    with localcontext() as context_:
        context_.prec = 50
        if len(successful) % 2:
            median = successful[len(successful) // 2]
        else:
            pair = successful[len(successful) // 2 - 1 : len(successful) // 2 + 1]
            median = (pair[0] + pair[1]) / 2
        spread = successful[-1] - successful[0]
    target, klass, wid, digest, _ordinal = series_key
    payload: dict[str, Any] = {
        "record_id": record_id,
        "record_version": 1,
        "record_kind": "summary",
        "campaign_id": campaign_id,
        "invocation_id": None,
        "emitted_by": "composer",
        "target": target,
        "workload_class": klass,
        "workload_id": wid,
        "input_digest": digest,
        "series": f"{display_key(series_key)}/{SERIES_METRIC}",
        "statistic": STATISTIC_ATTEMPT,
        "observation_ids": [item.record_id for item in observed],
        "excluded_warmups": excluded,
        "n_total": len(observed),
        "n_successful": len(successful),
        "outcome_counts": dict(sorted(Counter(item.outcome for item in observed).items())),
        "min_s": _canonical(successful[0]),
        "median_s": _canonical(median),
        "max_s": _canonical(successful[-1]),
        "range_s": _canonical(spread),
        "context": dict(context) if context is not None else {},
    }
    return ComposedSummary(summary=validate_summary(payload), absent_reason=None)
