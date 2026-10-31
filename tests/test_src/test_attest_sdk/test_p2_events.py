"""P2 unit tests: event parsing, hashing, and schema rules."""

from __future__ import annotations

from typing import Any

import pytest

from attest_sdk import canonical
from attest_sdk.errors import AmbiguousHistoryError
from attest_sdk.events import parse_approval_event, parse_lifecycle_event

DIGEST = "686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8"
GENESIS_PREV = None


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    inner = {key: item for key, item in payload.items() if key != "event_id"}
    payload["event_id"] = canonical.digest_of(inner)
    return payload


def _approve(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "seq": 0,
        "prev": GENESIS_PREV,
        "invariant_id": "X",
        "invariant_version": 1,
        "invariant_digest": DIGEST,
        "event_type": "APPROVE",
        "approver": "A",
        "method": "cli-review",
        "timestamp": "2026-10-31T00:00:00+00:00",
    }
    base.update(over)
    return _seal(base)


def _activate(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "seq": 0,
        "prev": GENESIS_PREV,
        "invariant_id": "X",
        "invariant_version": 1,
        "event_type": "ACTIVATE",
        "actor": "A",
        "timestamp": "2026-10-31T00:00:00+00:00",
    }
    base.update(over)
    return _seal(base)


def test_valid_approval_with_optionals() -> None:
    event = parse_approval_event(
        _approve(
            approver_id="mailto:a@example.test",
            reason="r",
            supersedes="0" * 64,
            seq=3,
            prev="1" * 64,
        )
    )
    assert event.seq == 3
    assert event.prev == "1" * 64
    assert event.approver_id == "mailto:a@example.test"
    assert event.supersedes == "0" * 64


def test_valid_lifecycle_with_successor() -> None:
    event = parse_lifecycle_event(
        _activate(event_type="SUPERSEDE", successor_version=2, reason="r")
    )
    assert event.successor_version == 2


def test_x_method_preserved() -> None:
    assert parse_approval_event(_approve(method="x-lab.trial")).method == "x-lab.trial"


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda v: [1, 2], "malformed-event"),
        (lambda v: {**v, "event_type": "FOO"}, "malformed-event"),
        (lambda v: {k: i for k, i in v.items() if k != "event_type"}, "malformed-event"),
        (lambda v: {**v, "event_type": "ACTIVATE"}, "misplaced-event"),
        (lambda v: {**v, "bogus": 1}, "malformed-event"),
        (lambda v: {**v, "seq": "0"}, "malformed-event"),
        (lambda v: {**v, "seq": True}, "malformed-event"),
        (lambda v: {**v, "prev": 5}, "malformed-event"),
        (lambda v: {**v, "prev": "xyz"}, "malformed-event"),
        (lambda v: {k: i for k, i in v.items() if k != "event_id"}, "malformed-event"),
        (lambda v: {**v, "invariant_id": 7}, "malformed-event"),
        (lambda v: {**v, "invariant_version": "1"}, "malformed-event"),
        (lambda v: {**v, "invariant_digest": "0" * 63}, "malformed-event"),
        (lambda v: {**v, "invariant_digest": "G" * 64}, "malformed-event"),
        (lambda v: {**v, "approver": None}, "malformed-event"),
        (lambda v: {**v, "method": "CLI"}, "malformed-event"),
        (lambda v: {**v, "method": ""}, "malformed-event"),
        (lambda v: {**v, "method": "a" * 65}, "malformed-event"),
        (lambda v: {**v, "timestamp": 0}, "malformed-event"),
        (lambda v: {**v, "reason": 0}, "malformed-event"),
        (lambda v: {**v, "approver_id": 0}, "malformed-event"),
        (lambda v: {**v, "supersedes": 0}, "malformed-event"),
        (lambda v: {**v, "approver": "Mallory"}, "event-hash-mismatch"),
    ],
)
def test_approval_refusals(mutate: Any, reason: str) -> None:
    with pytest.raises(AmbiguousHistoryError) as err:
        parse_approval_event(mutate(_approve()))
    assert err.value.reason_class == reason


def test_method_length_boundary() -> None:
    parse_approval_event(_approve(method="a" * 64))
    parse_approval_event(_approve(method="a.b-c9"))


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda v: {**v, "event_type": "APPROVE"}, "misplaced-event"),
        (lambda v: {**v, "event_type": "NOTE"}, "misplaced-event"),
        (lambda v: {**v, "event_type": "FOO"}, "malformed-event"),
        (lambda v: {**v, "invariant_digest": DIGEST}, "malformed-event"),
        (lambda v: {**v, "method": "cli-review"}, "malformed-event"),
        (lambda v: {**v, "actor": 9}, "malformed-event"),
        (lambda v: {**v, "event_type": "SUPERSEDE"}, "malformed-event"),
        (lambda v: {**v, "event_type": "SUPERSEDE", "successor_version": 0}, "malformed-event"),
        (lambda v: {**v, "event_type": "SUPERSEDE", "successor_version": True}, "malformed-event"),
        (lambda v: {**v, "event_type": "SUPERSEDE", "successor_version": "2"}, "malformed-event"),
        (lambda v: {**v, "successor_version": 2}, "malformed-event"),
        (lambda v: {**v, "successor_version": None}, "malformed-event"),
        (lambda v: {**v, "actor": "Mallory"}, "event-hash-mismatch"),
    ],
)
def test_lifecycle_refusals(mutate: Any, reason: str) -> None:
    with pytest.raises(AmbiguousHistoryError) as err:
        parse_lifecycle_event(mutate(_activate()))
    assert err.value.reason_class == reason
