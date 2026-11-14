"""F3 campaign records: strict structural validation (§7.4)."""

from __future__ import annotations

from typing import Any

import pytest
from f3_fixtures import UUID_A, UUID_C, assert_fails, valid_campaign

from attest_core.f3_records_campaign import validate_campaign

WL_TRIPLE = {"workload_class": "Medium", "workload_id": "w", "input_digest": "ab" * 32}
FILE_ENTRY = {"kind": "file", "relpath": "inputs/x", "size_bytes": 3, "sha256": "cd" * 32}


def _workload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        **WL_TRIPLE,
        "input_manifest": {"manifest_version": 1, "entries": [dict(FILE_ENTRY)]},
    }
    base.update(overrides)
    return base


def _entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "run_sequence": 1,
        "invocation_id": UUID_C,
        "sample_class": "warmup",
        "target": "repaired",
        "workload": _workload(),
    }
    base.update(overrides)
    return base


def test_campaign_valid() -> None:
    record = validate_campaign(valid_campaign())
    assert record.record_kind == "campaign"
    assert record.invocation_id is None
    assert len(record.invocations) == 1
    assert record.protocol["required_successful"] == 5


def test_campaign_missing_and_unknown() -> None:
    payload = valid_campaign()
    del payload["protocol"]
    assert_fails(
        validate_campaign,
        payload,
        rule="V-B6",
        section="7.4",
        location="$.protocol",
        reason="missing",
    )
    assert_fails(
        validate_campaign,
        {**valid_campaign(), "zzz": 1},
        rule="V-B6",
        section="7.4",
        location="$",
        reason="'zzz'",
    )


def test_campaign_envelope() -> None:
    assert_fails(
        validate_campaign,
        valid_campaign(invocation_id=UUID_A),
        rule="V-B6",
        section="7.4",
        location="$.invocation_id",
        reason="null",
    )
    assert_fails(
        validate_campaign,
        valid_campaign(observed_start_wallclock=""),
        rule="V-B6",
        section="7.4",
        location="$.observed_start_wallclock",
    )
    assert_fails(
        validate_campaign,
        valid_campaign(emitted_by="worker"),
        rule="V-B6",
        section="7.4",
        location="$.emitted_by",
    )
    assert validate_campaign(valid_campaign(emitted_by="parent")).emitted_by == "parent"


def _protocol_case(**overrides: Any) -> dict[str, Any]:
    payload = valid_campaign()
    payload["protocol"] = {**payload["protocol"], **overrides}
    return payload


@pytest.mark.parametrize(
    ("key", "value", "location"),
    [
        ("benchmark_category", "End To End", "$.protocol.benchmark_category"),
        ("benchmark_category", "", "$.protocol.benchmark_category"),
        ("benchmark_category", 7, "$.protocol.benchmark_category"),
        ("required_successful", 0, "$.protocol.required_successful"),
        ("required_successful", True, "$.protocol.required_successful"),
        ("attempts_per_invocation", -3, "$.protocol.attempts_per_invocation"),
        ("warmup_invocations", [1, 1], "$.protocol.warmup_invocations"),
        ("warmup_invocations", [0], "$.protocol.warmup_invocations[0]"),
        ("warmup_invocations", {"a": 1}, "$.protocol.warmup_invocations"),
        ("targets", [], "$.protocol.targets"),
        ("targets", ["a", "a"], "$.protocol.targets"),
        ("targets", ["Bad!"], "$.protocol.targets[0]"),
        ("profile", "turbo", "$.protocol.profile"),
    ],
)
def test_campaign_protocol_rejects(key: str, value: Any, location: str) -> None:
    assert_fails(
        validate_campaign,
        _protocol_case(**{key: value}),
        rule="V-B6",
        section="7.4",
        location=location,
    )


def test_campaign_protocol_accepts() -> None:
    payload = _protocol_case(warmup_invocations=[], targets=["a", "b-repaired_2"])
    assert validate_campaign(payload).protocol["warmup_invocations"] == []


def _entry_case(**overrides: Any) -> dict[str, Any]:
    payload = valid_campaign()
    payload["invocations"] = [_entry(**overrides)]
    return payload


@pytest.mark.parametrize(
    ("key", "value", "location"),
    [
        ("run_sequence", 0, "$.invocations[0].run_sequence"),
        ("run_sequence", True, "$.invocations[0].run_sequence"),
        ("invocation_id", None, "$.invocations[0].invocation_id"),
        ("invocation_id", "zzz", "$.invocations[0].invocation_id"),
        ("sample_class", "lukewarm", "$.invocations[0].sample_class"),
        ("target", "Bad Target", "$.invocations[0].target"),
    ],
)
def test_campaign_entry_rejects(key: str, value: Any, location: str) -> None:
    assert_fails(
        validate_campaign,
        _entry_case(**{key: value}),
        rule="V-B6",
        section="7.4",
        location=location,
    )


def test_campaign_entry_workload_rejects() -> None:
    bad_triple = {
        **WL_TRIPLE,
        "workload_class": "medium",
        "input_manifest": _workload()["input_manifest"],
    }
    assert_fails(
        validate_campaign,
        _entry_case(workload=bad_triple),
        rule="V-B6",
        section="7.4",
        location="$.invocations[0].workload.workload_class",
    )
    assert_fails(
        validate_campaign,
        _entry_case(workload={"workload_class": "Medium"}),
        rule="V-B6",
        section="7.4",
        location="$.invocations[0].workload.workload_id",
        reason="missing",
    )
    assert_fails(
        validate_campaign,
        _entry_case(workload={**_workload(), "zzz": 1}),
        rule="V-B6",
        section="7.4",
        location="$.invocations[0].workload",
        reason="'zzz'",
    )


def test_campaign_invocations_nonempty() -> None:
    assert_fails(
        validate_campaign,
        valid_campaign(invocations=[]),
        rule="V-B6",
        section="7.4",
        location="$.invocations",
    )
