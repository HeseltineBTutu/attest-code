"""F3 attempt and invocation_total records (§7.1, §7.2)."""

from __future__ import annotations

import dataclasses
import functools
from typing import Any

from attest_core import f3_fields as ff
from attest_core import f3_schema as sc

_ATTEMPT_KEYS = frozenset(
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
        "attempt",
        "sample_class",
        "elapsed_s",
        "outcome",
        "censored",
        "profile",
        "timeout_s",
        "pid",
    }
)
_TOTAL_KEYS = frozenset(
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
        "sample_class",
        "elapsed_s",
        "profile",
        "verdict",
        "attempts_completed",
        "attempts_total",
        "attempt_outcomes",
    }
)
_ATTEMPT_KIND: sc.Check = functools.partial(
    sc.enum, allowed=frozenset({"attempt"}), name="record_kind"
)
_TOTAL_KIND: sc.Check = functools.partial(
    sc.enum, allowed=frozenset({"invocation_total"}), name="record_kind"
)


@dataclasses.dataclass(frozen=True)
class AttemptRecord:
    """One validated attempt execution record (§7.1)."""

    record_id: str
    record_version: int
    record_kind: str
    campaign_id: str
    invocation_id: str
    emitted_by: str
    target: str
    workload_class: str
    workload_id: str
    input_digest: str
    attempt: int
    sample_class: str
    elapsed_s: str
    outcome: str
    censored: bool
    profile: str
    timeout_s: str
    pid: int


def validate_attempt(value: Any, section: str = "7.1", location: str = "$") -> AttemptRecord:
    """Validate an attempt record object (§7.1)."""

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _ATTEMPT_KEYS, section, location)
    return AttemptRecord(
        record_id=one("record_id", ff.uuid4),
        record_version=one("record_version", ff.record_version),
        record_kind=one("record_kind", _ATTEMPT_KIND),
        campaign_id=one("campaign_id", ff.uuid4),
        invocation_id=one("invocation_id", ff.uuid4),
        emitted_by=one("emitted_by", ff.emitter),
        target=one("target", ff.target),
        workload_class=one("workload_class", ff.workload_class),
        workload_id=one("workload_id", ff.workload_id),
        input_digest=one("input_digest", ff.digest64),
        attempt=one("attempt", sc.positive_int),
        sample_class=one("sample_class", ff.sample_class),
        elapsed_s=one("elapsed_s", ff.decimal9),
        outcome=one("outcome", ff.outcome),
        censored=one("censored", sc.strict_bool),
        profile=one("profile", ff.profile),
        timeout_s=one("timeout_s", ff.decimal9),
        pid=one("pid", sc.positive_int),
    )


@dataclasses.dataclass(frozen=True)
class TotalRecord:
    """One validated invocation_total record (§7.2)."""

    record_id: str
    record_version: int
    record_kind: str
    campaign_id: str
    invocation_id: str
    emitted_by: str
    target: str
    workload_class: str
    workload_id: str
    input_digest: str
    sample_class: str
    elapsed_s: str
    profile: str
    verdict: str
    attempts_completed: int
    attempts_total: int
    attempt_outcomes: dict[str, int]


def validate_total(value: Any, section: str = "7.2", location: str = "$") -> TotalRecord:
    """Validate an invocation_total record object (§7.2)."""

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _TOTAL_KEYS, section, location)
    return TotalRecord(
        record_id=one("record_id", ff.uuid4),
        record_version=one("record_version", ff.record_version),
        record_kind=one("record_kind", _TOTAL_KIND),
        campaign_id=one("campaign_id", ff.uuid4),
        invocation_id=one("invocation_id", ff.uuid4),
        emitted_by=one("emitted_by", ff.emitter),
        target=one("target", ff.target),
        workload_class=one("workload_class", ff.workload_class),
        workload_id=one("workload_id", ff.workload_id),
        input_digest=one("input_digest", ff.digest64),
        sample_class=one("sample_class", ff.sample_class),
        elapsed_s=one("elapsed_s", ff.decimal9),
        profile=one("profile", ff.profile),
        verdict=one("verdict", ff.verdict),
        attempts_completed=one("attempts_completed", sc.nonnegative_int),
        attempts_total=one("attempts_total", sc.nonnegative_int),
        attempt_outcomes=one("attempt_outcomes", ff.outcome_counts),
    )
