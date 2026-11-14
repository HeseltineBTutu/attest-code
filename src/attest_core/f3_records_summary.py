"""F3 summary records: strict structural validation (§7.5).

Validates shapes only: series grammar, id-list UUIDs, counts,
statistics, and context mapping. Partition and recomputation
checks belong to later phases.
"""

from __future__ import annotations

import dataclasses
import functools
from typing import Any

from attest_core import f3_fields as ff
from attest_core import f3_schema as sc

_SUMMARY_KEYS = frozenset(
    {
        "record_id",
        "record_version",
        "record_kind",
        "campaign_id",
        "invocation_id",
        "emitted_by",
        "target",
        "workload_class",
        "workload_id",
        "input_digest",
        "series",
        "statistic",
        "observation_ids",
        "excluded_warmups",
        "n_total",
        "n_successful",
        "outcome_counts",
        "min_s",
        "median_s",
        "max_s",
        "range_s",
        "context",
    }
)


def _id_list(value: Any, section: str, location: str) -> list[str]:
    """A list of UUIDv4 record ids (partition checked later)."""
    if not isinstance(value, list):
        sc.fail(section, location, "must be a JSON list of UUIDs")
    return [ff.uuid4(item, section, f"{location}[{i}]") for i, item in enumerate(value)]


def _context(value: Any, section: str, location: str) -> dict[str, str]:
    """Provenance mapping: non-blank names to strings."""
    obj = sc.check_object(value, section, location)
    out: dict[str, str] = {}
    for key in obj:
        if not isinstance(key, str) or not key.strip():
            sc.fail(section, location, "context names must be non-blank strings")
        item = obj[key]
        if not isinstance(item, str):
            sc.fail(section, f"{location}.{key}", "context values must be strings")
        out[key] = item
    return out


@dataclasses.dataclass(frozen=True)
class SummaryRecord:
    """One validated summary record (§7.5)."""

    record_id: str
    record_version: int
    record_kind: str
    campaign_id: str
    invocation_id: None
    emitted_by: str
    target: str
    workload_class: str
    workload_id: str
    input_digest: str
    series: str
    statistic: str
    observation_ids: list[str]
    excluded_warmups: list[str]
    n_total: int
    n_successful: int
    outcome_counts: dict[str, int]
    min_s: str
    median_s: str
    max_s: str
    range_s: str
    context: dict[str, str]


def validate_summary(value: Any, section: str = "7.5", location: str = "$") -> SummaryRecord:
    """Validate a summary record object (§7.5)."""

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _SUMMARY_KEYS, section, location)
    kind = functools.partial(sc.enum, allowed=frozenset({"summary"}), name="record_kind")
    stat = functools.partial(sc.enum, allowed=frozenset({"attempt"}), name="statistic")
    return SummaryRecord(
        record_id=one("record_id", ff.uuid4),
        record_version=one("record_version", ff.record_version),
        record_kind=one("record_kind", kind),
        campaign_id=one("campaign_id", ff.uuid4),
        invocation_id=one("invocation_id", ff.null_invocation),
        emitted_by=one("emitted_by", ff.emitter),
        target=one("target", ff.target),
        workload_class=one("workload_class", ff.workload_class),
        workload_id=one("workload_id", ff.workload_id),
        input_digest=one("input_digest", ff.digest64),
        series=one("series", ff.series),
        statistic=one("statistic", stat),
        observation_ids=one("observation_ids", _id_list),
        excluded_warmups=one("excluded_warmups", _id_list),
        n_total=one("n_total", sc.nonnegative_int),
        n_successful=one("n_successful", sc.nonnegative_int),
        outcome_counts=one("outcome_counts", ff.outcome_counts),
        min_s=one("min_s", ff.summary_decimal),
        median_s=one("median_s", ff.summary_decimal),
        max_s=one("max_s", ff.summary_decimal),
        range_s=one("range_s", ff.summary_decimal),
        context=one("context", _context),
    )
