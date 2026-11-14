"""F3 schema machinery: generic strict validators.

Fail-closed primitives shared by all record-kind validators. Each
returns the validated value or raises F3SchemaError citing rule
V-B6 with the schema section and field path. No I/O.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any, NoReturn, TypeVar

from attest_core.f3_errors import F3SchemaError

RULE = "V-B6"
T = TypeVar("T")
Check = Callable[[Any, str, str], Any]


def fail(section: str, location: str, reason: str) -> NoReturn:
    """Raise a schema violation with full design traceability."""
    raise F3SchemaError(rule=RULE, section=section, location=location, reason=reason)


def pattern(value: Any, section: str, location: str, compiled: re.Pattern[str], what: str) -> str:
    """String fully matching a compiled pattern (config binds last)."""
    if not isinstance(value, str) or compiled.fullmatch(value) is None:
        fail(section, location, f"must match {what}")
    return value


def enum(value: Any, section: str, loc: str, allowed: frozenset[str], name: str) -> str:
    """Exact vocabulary membership (config binds last; no coercion)."""
    if not isinstance(value, str) or value not in allowed:
        fail(section, loc, f"must be one of {name}: {sorted(allowed)}")
    return value


def strict_bool(value: Any, section: str, location: str) -> bool:
    """Exact bool (never an int masquerading as one)."""
    if type(value) is not bool:
        fail(section, location, "must be a JSON boolean")
    return value


def strict_int(value: Any, section: str, location: str) -> int:
    """Exact int (bools rejected even though bool subclasses int)."""
    if type(value) is not int:
        fail(section, location, "must be a JSON integer")
    return value


def positive_int(value: Any, section: str, location: str) -> int:
    """Integer >= 1."""
    number = strict_int(value, section, location)
    if number < 1:
        fail(section, location, "must be >= 1")
    return number


def nonnegative_int(value: Any, section: str, location: str) -> int:
    """Integer >= 0."""
    number = strict_int(value, section, location)
    if number < 0:
        fail(section, location, "must be >= 0")
    return number


def nonblank_str(value: Any, section: str, location: str) -> str:
    """String with non-whitespace content (mirrors collector idiom)."""
    if not isinstance(value, str) or not value.strip():
        fail(section, location, "must be a non-blank string")
    return value


def ascii_bounded(value: Any, section: str, location: str, max_len: int) -> str:
    """Non-blank ASCII string within a length bound."""
    text = nonblank_str(value, section, location)
    if not text.isascii() or len(text) > max_len:
        fail(section, location, f"must be ASCII of length 1..{max_len}")
    return text


def unavailable_marker(value: Any, section: str, location: str) -> dict[str, str]:
    """Exactly {"unavailable": <non-empty reason>} and nothing else."""
    if not isinstance(value, dict) or set(value) != {"unavailable"}:
        fail(section, location, 'must be exactly {"unavailable": reason}')
    reason = value["unavailable"]
    if not isinstance(reason, str) or not reason:
        fail(section, location, "marker reason must be a non-empty string")
    return {"unavailable": reason}


def check_object(value: Any, section: str, location: str) -> dict[str, Any]:
    """Require a JSON object."""
    if not isinstance(value, dict):
        fail(section, location, "must be a JSON object")
    return value


def reject_unknown(
    obj: Mapping[str, Any], allowed: frozenset[str], section: str, location: str
) -> None:
    """Reject unknown fields (V-B6 strict per-version validation)."""
    unknown = sorted(repr(key) for key in set(obj) - allowed)
    if unknown:
        fail(section, location, f"unknown fields rejected: [{', '.join(unknown)}]")


def field(
    obj: Mapping[str, Any],
    key: str,
    section: str,
    location: str,
    func: Callable[[Any, str, str], T],
) -> T:
    """Require a key and validate its value, extending the field path."""
    path = f"{location}.{key}"
    if key not in obj:
        fail(section, path, "missing required field")
    return func(obj[key], section, path)


def value_or_marker(
    func: Callable[[Any, str, str], T],
) -> Callable[[Any, str, str], T | dict[str, str]]:
    """Wrap a value check to also accept an unavailable marker."""

    def check(value: Any, section: str, location: str) -> T | dict[str, str]:
        if isinstance(value, dict) and set(value) == {"unavailable"}:
            return unavailable_marker(value, section, location)
        return func(value, section, location)

    return check
