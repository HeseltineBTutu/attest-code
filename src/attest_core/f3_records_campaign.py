"""F3 campaign records: strict structural validation (§7.4)."""

from __future__ import annotations

import dataclasses
import functools
from typing import Any

from attest_core import f3_fields as ff
from attest_core import f3_schema as sc
from attest_core import f3_workload as wl

_CAMPAIGN_KEYS = frozenset(
    {
        "record_id",
        "record_version",
        "record_kind",
        "campaign_id",
        "invocation_id",
        "emitted_by",
        "observed_start_wallclock",
        "protocol",
        "invocations",
    }
)
_PROTOCOL_KEYS = frozenset(
    {
        "benchmark_category",
        "required_successful",
        "attempts_per_invocation",
        "warmup_invocations",
        "targets",
        "profile",
    }
)
_ENTRY_KEYS = frozenset({"run_sequence", "invocation_id", "sample_class", "target", "workload"})


def _nonempty_str(value: Any, section: str, location: str) -> str:
    """Non-empty string (no format rule specified)."""
    if not isinstance(value, str) or not value:
        sc.fail(section, location, "must be a non-empty string")
    return value


def _int_list(value: Any, section: str, location: str, what: str) -> list[int]:
    """A list of positive integers without duplicates."""
    if not isinstance(value, list):
        sc.fail(section, location, f"must be a list of positive integers ({what})")
    out = [sc.positive_int(item, section, f"{location}[{i}]") for i, item in enumerate(value)]
    if len(set(out)) != len(out):
        sc.fail(section, location, f"duplicate entries rejected ({what})")
    return out


def _targets(value: Any, section: str, location: str) -> list[str]:
    """Non-empty unique list of target-shaped strings."""
    if not isinstance(value, list) or not value:
        sc.fail(section, location, "must be a non-empty JSON list")
    out = [ff.target(item, section, f"{location}[{i}]") for i, item in enumerate(value)]
    if len(set(out)) != len(out):
        sc.fail(section, location, "duplicate targets rejected")
    return out


def _protocol(value: Any, section: str, location: str) -> dict[str, Any]:
    """Campaign protocol declaration (shape only)."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _PROTOCOL_KEYS, section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    warmups = functools.partial(_int_list, what="warmup_invocations")
    return {
        "benchmark_category": one("benchmark_category", ff.category),
        "required_successful": one("required_successful", sc.positive_int),
        "attempts_per_invocation": one("attempts_per_invocation", sc.positive_int),
        "warmup_invocations": one("warmup_invocations", warmups),
        "targets": one("targets", _targets),
        "profile": one("profile", ff.profile),
    }


def _invocation_entry(value: Any, section: str, location: str) -> dict[str, Any]:
    """One declared invocation entry (shape only)."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _ENTRY_KEYS, section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    return {
        "run_sequence": one("run_sequence", sc.positive_int),
        "invocation_id": one("invocation_id", ff.uuid4),
        "sample_class": one("sample_class", ff.sample_class),
        "target": one("target", ff.target),
        "workload": one("workload", wl.validate_workload),
    }


@dataclasses.dataclass(frozen=True)
class CampaignRecord:
    """One validated campaign record (§7.4)."""

    record_id: str
    record_version: int
    record_kind: str
    campaign_id: str
    invocation_id: None
    emitted_by: str
    observed_start_wallclock: str
    protocol: dict[str, Any]
    invocations: list[dict[str, Any]]


def validate_campaign(value: Any, section: str = "7.4", location: str = "$") -> CampaignRecord:
    """Validate a campaign record object (§7.4)."""

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _CAMPAIGN_KEYS, section, location)
    kind = functools.partial(sc.enum, allowed=frozenset({"campaign"}), name="record_kind")
    raw_entries = one("invocations", _nonempty_invocations)
    invocations = [
        _invocation_entry(item, section, f"{location}.invocations[{index}]")
        for index, item in enumerate(raw_entries)
    ]
    return CampaignRecord(
        record_id=one("record_id", ff.uuid4),
        record_version=one("record_version", ff.record_version),
        record_kind=one("record_kind", kind),
        campaign_id=one("campaign_id", ff.uuid4),
        invocation_id=one("invocation_id", ff.null_invocation),
        emitted_by=one("emitted_by", ff.emitter),
        observed_start_wallclock=one("observed_start_wallclock", _nonempty_str),
        protocol=one("protocol", _protocol),
        invocations=invocations,
    )


def _nonempty_invocations(value: Any, section: str, location: str) -> list[Any]:
    """A campaign declares at least one invocation."""
    if not isinstance(value, list) or not value:
        sc.fail(section, location, "must be a non-empty JSON list")
    return value
