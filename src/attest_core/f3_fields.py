"""F3 named field checks: design vocabularies and patterns.

One pre-bound check per constrained F3 field, composing the
generic machinery in f3_schema. Pure.
"""

from __future__ import annotations

import functools
import re
from typing import Any

from attest_core import f3_schema as sc

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
TARGET_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
WORKLOAD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
DIGEST64_RE = re.compile(r"[0-9a-f]{64}")
DECIMAL9_RE = re.compile(r"(0|[1-9][0-9]*)\.[0-9]{9}")
SUMMARY_DECIMAL_RE = re.compile(r"(0|[1-9][0-9]*)(\.[0-9]{0,11}[1-9])?")
SERIES_RE = re.compile(r"([a-z0-9][a-z0-9_-]{0,63})/b([1-9][0-9]*)/([A-Za-z0-9_.-]{1,64})")
CATEGORY_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
DETAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.,-]{0,199}")
ASCII_RE = re.compile(r"[\x00-\x7F]*")

RECORD_KINDS = frozenset({"attempt", "invocation_total", "environment", "campaign", "summary"})
WORKLOAD_CLASSES = frozenset({"Small", "Medium", "Large", "Adversarial"})
SAMPLE_CLASSES = frozenset({"warmup", "measured"})
OUTCOMES = frozenset({"PASS", "VIOLATION", "INFRA_FAILURE", "TIMEOUT"})
PROFILES = frozenset({"standard", "contained", "hardened"})
EMITTERS = frozenset({"parent", "orchestrator", "composer"})
VERDICTS = frozenset({"PASSED", "FAILED", "INCONCLUSIVE"})
INTERFERENCE_CATEGORIES = frozenset(
    {
        "concurrent-load",
        "shared-host",
        "frequency-scaling",
        "thermal-throttling",
        "power-throttling",
        "other",
    }
)


def uuid4(value: object, section: str, location: str) -> str:
    """Lowercase UUIDv4: shape plus version-4 and variant bits."""
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        sc.fail(section, location, "must match UUID shape [0-9a-f-]{36}")
    if value[14] != "4":
        sc.fail(section, location, "must be UUID version 4")
    if value[19] not in "89ab":
        sc.fail(section, location, "must carry RFC variant bits")
    return value


def null_invocation(value: object, section: str, location: str) -> None:
    """Campaign/summary records scope above one invocation: null required."""
    if value is not None:
        sc.fail(section, location, "campaign/summary records must carry null invocation_id")
    return None


def record_version(value: object, section: str, location: str) -> int:
    """Exact schema version 1 (bools rejected as non-integers)."""
    number = sc.strict_int(value, section, location)
    if number != 1:
        sc.fail(section, location, "unsupported record_version: exactly 1 required")
    return number


decimal9: sc.Check = functools.partial(sc.pattern, compiled=DECIMAL9_RE, what="9-place decimal")
summary_decimal: sc.Check = functools.partial(
    sc.pattern, compiled=SUMMARY_DECIMAL_RE, what="summary decimal"
)
target: sc.Check = functools.partial(sc.pattern, compiled=TARGET_RE, what="target shape")
workload_id: sc.Check = functools.partial(
    sc.pattern, compiled=WORKLOAD_ID_RE, what="workload_id shape"
)
digest64: sc.Check = functools.partial(sc.pattern, compiled=DIGEST64_RE, what="SHA-256 hex")
git_sha: sc.Check = functools.partial(sc.pattern, compiled=GIT_SHA_RE, what="40-hex commit id")
series: sc.Check = functools.partial(sc.pattern, compiled=SERIES_RE, what="series grammar")
category: sc.Check = functools.partial(sc.pattern, compiled=CATEGORY_RE, what="category shape")
detail: sc.Check = functools.partial(sc.pattern, compiled=DETAIL_RE, what="detail shape")
ascii_text: sc.Check = functools.partial(sc.pattern, compiled=ASCII_RE, what="ASCII text")
workload_class: sc.Check = functools.partial(
    sc.enum, allowed=WORKLOAD_CLASSES, name="workload_class"
)
sample_class: sc.Check = functools.partial(sc.enum, allowed=SAMPLE_CLASSES, name="sample_class")
outcome: sc.Check = functools.partial(sc.enum, allowed=OUTCOMES, name="outcome")
profile: sc.Check = functools.partial(sc.enum, allowed=PROFILES, name="profile")
emitter: sc.Check = functools.partial(sc.enum, allowed=EMITTERS, name="emitted_by")
verdict: sc.Check = functools.partial(sc.enum, allowed=VERDICTS, name="verdict")
interference_category: sc.Check = functools.partial(
    sc.enum, allowed=INTERFERENCE_CATEGORIES, name="category"
)
record_kind: sc.Check = functools.partial(sc.enum, allowed=RECORD_KINDS, name="record_kind")


def outcome_counts(value: Any, section: str, location: str) -> dict[str, int]:
    """Outcome label to non-negative count map."""
    obj = sc.check_object(value, section, location)
    counts: dict[str, int] = {}
    for key in obj:
        if key not in OUTCOMES:
            sc.fail(section, location, f"unknown outcome label: {key!r}")
        counts[key] = sc.nonnegative_int(obj[key], section, f"{location}.{key}")
    return counts
