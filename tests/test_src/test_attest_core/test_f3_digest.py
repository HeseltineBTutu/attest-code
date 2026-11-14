"""F3 digest projection, pins, and verification behavior (§8.2)."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from f3_fixtures import assert_fails, valid_attempt, valid_campaign, valid_total

from attest_core.f3_digest import (
    CANONICAL_NAME,
    CANONICAL_VERSION,
    PROJECTION_NAME,
    PROJECTION_VERSION,
    DigestCheck,
    project,
    record_digest,
    require_canonicalizer,
    require_projection,
    verify_record_digest,
)


def test_constants_pin_v1() -> None:
    assert (PROJECTION_NAME, PROJECTION_VERSION) == ("f3-digest-projection", 1)
    assert (CANONICAL_NAME, CANONICAL_VERSION) == ("attest-canonical-json", 1)


def test_project_drops_nothing_for_records() -> None:
    record = valid_attempt()
    projected = project("attempt", record)
    assert projected == record
    assert projected is not record


def test_project_drops_campaign_wallclock_only() -> None:
    record = valid_campaign()
    projected = project("campaign", record)
    assert "observed_start_wallclock" not in projected
    assert sorted(projected) == sorted(set(record) - {"observed_start_wallclock"})
    assert projected["protocol"] == record["protocol"]


def test_project_manifest_drops_observed_only() -> None:
    manifest = {
        "campaign_id": "c",
        "records": [{"record_id": "r"}],
        "evidence": [{"invocation_id": "i"}],
        "observed_start": "t0",
        "observed_end": "t1",
    }
    projected = project("manifest", manifest)
    assert "observed_start" not in projected
    assert "observed_end" not in projected
    assert projected["evidence"] == [{"invocation_id": "i"}]
    assert "observed_start" in manifest


def test_project_never_silently_drops_unknown_fields() -> None:
    payload = {**valid_attempt(), "smuggled": 1}
    assert_fails(
        lambda v: project("attempt", v),
        payload,
        rule="V-B6",
        section="7.1",
        location="$",
        reason="unknown fields",
    )


def test_project_rejects_non_dict_and_bad_kind() -> None:
    assert_fails(lambda v: project("attempt", v), [1], rule="V-B6", section="7.1", location="$")
    assert_fails(
        lambda v: project("nope", v),
        {},
        rule="V-B6",
        section="8.2",
        location="$",
        reason="unknown kind",
    )
    assert_fails(lambda v: project("manifest", v), 7, rule="V-B6", section="8.2", location="$")


def test_digest_kind_must_match_record() -> None:
    total = valid_total()
    assert_fails(
        lambda v: record_digest("attempt", v),
        total,
        rule="V-B6",
        section="7.1",
        location="$",
        reason="unknown fields",
    )
    relabeled = valid_attempt(record_kind="invocation_total")
    assert_fails(
        lambda v: record_digest("attempt", v),
        relabeled,
        rule="V-B6",
        section="7.1",
        location="$.record_kind",
    )


def test_digest_is_deterministic_and_input_kept() -> None:
    record = valid_attempt()
    before = copy.deepcopy(record)
    first = record_digest("attempt", record)
    assert record_digest("attempt", record) == first
    assert record == before
    assert len(first) == 64


def test_digest_refuses_over_limit_integers() -> None:
    """Shape-valid huge ints fail closed at canonicalization (P0/P1 seam)."""
    record = valid_attempt(pid=2**60)
    assert_fails(
        lambda v: record_digest("attempt", v),
        record,
        rule="V-B6",
        section="8.2",
        location="$",
        reason="integer-out-of-range",
    )


def test_verify_paths() -> None:
    record = valid_attempt()
    digest = record_digest("attempt", record)
    good = verify_record_digest("attempt", record, digest)
    assert good == DigestCheck(ok=True, reason="match")
    bad = verify_record_digest("attempt", record, "00" * 32)
    assert bad.ok is False
    assert digest in bad.reason and "00" * 8 in bad.reason
    broken = verify_record_digest("attempt", {"record_kind": "attempt"}, digest)
    assert broken.ok is False
    assert "unverifiable record" in broken.reason
    assert "missing required field" in broken.reason
    assert verify_record_digest("attempt", record, None).ok is False


def test_require_pins_accept_exact() -> None:
    require_projection({"name": "f3-digest-projection", "version": 1})
    require_canonicalizer({"name": "attest-canonical-json", "version": 1})


@pytest.mark.parametrize(
    ("func", "pin", "location", "reason"),
    [
        ("projection", {"name": "f3-digest-projection", "version": 2}, "$.version", "unsupported"),
        ("projection", {"name": "other", "version": 1}, "$.name", "unsupported"),
        (
            "projection",
            {"name": "f3-digest-projection", "version": True},
            "$.version",
            "unsupported",
        ),
        ("projection", {"name": "f3-digest-projection"}, "$.version", "unsupported"),
        ("projection", {"name": "f3-digest-projection", "version": 1, "x": 0}, "$", "unknown"),
        ("projection", [], "$", "must be a JSON object"),
        (
            "canonicalizer",
            {"name": "attest-canonical-json", "version": 0},
            "$.version",
            "unsupported",
        ),
        ("canonicalizer", {"name": "stdlib-json", "version": 1}, "$.name", "unsupported"),
        ("canonicalizer", "v1", "$", "must be a JSON object"),
    ],
)
def test_require_pins_refuse(func: str, pin: Any, location: str, reason: str) -> None:
    check = require_projection if func == "projection" else require_canonicalizer
    assert_fails(check, pin, rule="V-B6", section="8.2", location=location, reason=reason)
