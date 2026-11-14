"""F3 schema primitives: strict field validators and error shape."""

from __future__ import annotations

from typing import Any

import pytest
from f3_fixtures import SHA40, UUID_A, assert_fails

from attest_core import f3_fields as ff
from attest_core import f3_schema as sc

SEC = "7.1"
LOC = "$.field"


@pytest.mark.parametrize("value", [UUID_A, "550e8400-e29b-41d4-a716-446655440000"])
def test_uuid4_accepts_valid(value: str) -> None:
    assert ff.uuid4(value, SEC, LOC) == value


@pytest.mark.parametrize(
    "value",
    [
        "not-a-uuid",
        "11111111-1111-1111-8111-111111111111",
        "11111111-1111-4111-7111-111111111111",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "11111111-1111-4111-8111-11111111111",
        "",
        123,
        None,
        True,
    ],
)
def test_uuid4_rejects(value: Any) -> None:
    assert_fails(lambda v: ff.uuid4(v, SEC, LOC), value, rule="V-B6", section=SEC, location=LOC)


def test_null_invocation() -> None:
    ff.null_invocation(None, SEC, LOC)
    assert_fails(
        lambda v: ff.null_invocation(v, SEC, LOC),
        UUID_A,
        rule="V-B6",
        section=SEC,
        location=LOC,
        reason="null",
    )


@pytest.mark.parametrize("value", [1])
def test_record_version_accepts(value: int) -> None:
    assert ff.record_version(value, SEC, LOC) == 1


@pytest.mark.parametrize("value", [0, 2, -1])
def test_record_version_rejects_unsupported(value: Any) -> None:
    assert_fails(
        lambda v: ff.record_version(v, SEC, LOC),
        value,
        rule="V-B6",
        section=SEC,
        location=LOC,
        reason="unsupported record_version",
    )


@pytest.mark.parametrize("value", ["1", 1.0, True, None])
def test_record_version_rejects_malformed(value: Any) -> None:
    assert_fails(
        lambda v: ff.record_version(v, SEC, LOC),
        value,
        rule="V-B6",
        section=SEC,
        location=LOC,
        reason="must be a JSON integer",
    )


@pytest.mark.parametrize("value", ["3.770075605", "0.000000000", "60.000000000", "123.000000001"])
def test_decimal9_accepts(value: str) -> None:
    assert ff.decimal9(value, SEC, LOC) == value


@pytest.mark.parametrize(
    "value",
    ["3.77", "3.7700756055", "03.770075605", "-1.000000000", "3", 3.77, "", "3.77007560a"],
)
def test_decimal9_rejects(value: Any) -> None:
    assert_fails(lambda v: ff.decimal9(v, SEC, LOC), value, rule="V-B6", section=SEC, location=LOC)


@pytest.mark.parametrize(
    "value", ["5", "0", "10.25", "0.5", "3.703622808", "123456789.123456789012"]
)
def test_summary_decimal_accepts(value: str) -> None:
    assert ff.summary_decimal(value, SEC, LOC) == value


@pytest.mark.parametrize("value", ["5.0", "00.5", "-1", "1e3", "5.", 5, None, "5.0000000000001"])
def test_summary_decimal_rejects(value: Any) -> None:
    assert_fails(
        lambda v: ff.summary_decimal(v, SEC, LOC),
        value,
        rule="V-B6",
        section=SEC,
        location=LOC,
    )


def test_patterns_and_bounds() -> None:
    assert ff.target("a" * 63, SEC, LOC) == "a" * 63
    assert ff.target("a" * 64, SEC, LOC) == "a" * 64
    assert ff.workload_id("b" * 128, SEC, LOC) == "b" * 128
    assert ff.digest64("ab" * 32, SEC, LOC) == "ab" * 32
    assert ff.series("repaired/b12/latency", SEC, LOC) == "repaired/b12/latency"
    assert ff.detail("x" * 200, SEC, LOC) == "x" * 200
    assert ff.category("z" * 32, SEC, LOC) == "z" * 32
    assert ff.git_sha(SHA40, SEC, LOC) == SHA40
    assert ff.ascii_text("", SEC, LOC) == ""
    bad = [
        (ff.target, "a" * 65),
        (ff.target, "Repaired"),
        (ff.workload_id, "c" * 129),
        (ff.workload_id, "has space"),
        (ff.digest64, "ab" * 31),
        (ff.digest64, "AB" * 32),
        (ff.series, "repaired/b0/latency"),
        (ff.series, "repaired/b01/latency"),
        (ff.series, "repaired/latency"),
        (ff.series, "a/b1/c/d"),
        (ff.category, "End-To-End"),
        (ff.category, ""),
        (ff.category, "z" * 33),
        (ff.detail, "x" * 201),
        (ff.detail, ":colon:"),
        (ff.detail, ""),
        (ff.git_sha, "cd" * 19),
        (ff.git_sha, "CD" * 20),
        (ff.ascii_text, "héllo"),
        (ff.ascii_text, 5),
    ]
    def check(func: Any, value: Any) -> None:
        assert_fails(lambda v: func(v, SEC, LOC), value, rule="V-B6", section=SEC, location=LOC)

    for func, value in bad:
        check(func, value)


def test_enums() -> None:
    assert ff.workload_class("Adversarial", SEC, LOC) == "Adversarial"
    bad = [
        (ff.workload_class, "medium"),
        (ff.sample_class, "WARMUP"),
        (ff.outcome, "pass"),
        (ff.profile, "turbo"),
        (ff.emitter, "worker"),
        (ff.verdict, "passed"),
        (ff.interference_category, "aliens"),
        (ff.workload_class, None),
    ]
    def check(func: Any, value: Any) -> None:
        assert_fails(lambda v: func(v, SEC, LOC), value, rule="V-B6", section=SEC, location=LOC)

    for func, value in bad:
        check(func, value)


def test_bool_int_traps() -> None:
    assert sc.strict_bool(True, SEC, LOC) is True
    assert sc.strict_int(3, SEC, LOC) == 3
    assert sc.positive_int(1, SEC, LOC) == 1
    assert sc.nonnegative_int(0, SEC, LOC) == 0
    assert sc.positive_int(2**60, SEC, LOC) == 2**60
    bad = [
        (sc.strict_bool, 1),
        (sc.strict_bool, 0),
        (sc.strict_int, True),
        (sc.strict_int, 1.0),
        (sc.positive_int, 0),
        (sc.positive_int, -2),
        (sc.nonnegative_int, -1),
        (sc.nonnegative_int, False),
    ]

    def check(func: Any, value: Any) -> None:
        assert_fails(lambda v: func(v, SEC, LOC), value, rule="V-B6", section=SEC, location=LOC)

    for func, value in bad:
        check(func, value)
