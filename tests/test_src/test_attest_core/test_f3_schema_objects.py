"""F3 schema object helpers: strings, markers, and structural checks."""

from __future__ import annotations

import functools
from typing import Any

from f3_fixtures import assert_fails

from attest_core import f3_schema as sc

SEC = "7.1"
LOC = "$.field"
ASCII4 = functools.partial(sc.ascii_bounded, max_len=4)


def test_strings_and_markers() -> None:
    assert sc.nonblank_str("x", SEC, LOC) == "x"
    assert sc.ascii_bounded("y" * 128, SEC, LOC, 128) == "y" * 128
    assert sc.unavailable_marker({"unavailable": "why"}, SEC, LOC) == {"unavailable": "why"}
    bad = [
        (sc.nonblank_str, ""),
        (sc.nonblank_str, "   "),
        (sc.nonblank_str, 7),
        (ASCII4, "toolongvalue"),
        (ASCII4, "héllo"),
        (sc.unavailable_marker, {"unavailable": ""}),
        (sc.unavailable_marker, {"unavailable": "x", "extra": 1}),
        (sc.unavailable_marker, {"reason": "x"}),
        (sc.unavailable_marker, "x"),
    ]
    def check(func: Any, value: Any) -> None:
        assert_fails(lambda v: func(v, SEC, LOC), value, rule="V-B6", section=SEC, location=LOC)

    for func, value in bad:
        check(func, value)


def test_object_helpers() -> None:
    assert sc.check_object({"a": 1}, SEC, LOC) == {"a": 1}
    assert_fails(
        lambda v: sc.check_object(v, SEC, LOC), [1], rule="V-B6", section=SEC, location=LOC
    )
    assert_fails(
        lambda v: sc.field({"a": 1}, "b", SEC, LOC, sc.strict_int),
        None,
        rule="V-B6",
        section=SEC,
        location="$.field.b",
        reason="missing required field",
    )
    assert_fails(
        lambda v: sc.reject_unknown({"a": 1, "zzz": 2}, frozenset({"a"}), SEC, LOC),
        None,
        rule="V-B6",
        section=SEC,
        location=LOC,
        reason="'zzz'",
    )
    assert sc.value_or_marker(sc.positive_int)({"unavailable": "r"}, SEC, LOC) == {
        "unavailable": "r"
    }
    assert sc.value_or_marker(sc.positive_int)(4, SEC, LOC) == 4
    assert_fails(
        lambda v: sc.value_or_marker(sc.positive_int)(v, SEC, LOC),
        -1,
        rule="V-B6",
        section=SEC,
        location=LOC,
    )
