"""P2 unit tests: chain linkage validation and ordering."""

from __future__ import annotations

from typing import Any

import pytest

from attest_sdk import canonical, chains
from attest_sdk.errors import AmbiguousHistoryError
from attest_sdk.events import parse_approval_event, parse_lifecycle_event

DIGEST = "686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8"


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    inner = {key: item for key, item in payload.items() if key != "event_id"}
    payload["event_id"] = canonical.digest_of(inner)
    return payload


def _approve(seq: int, prev: str | None, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "seq": seq,
        "prev": prev,
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


def _chain() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    genesis = _approve(0, None)
    note = _approve(1, genesis["event_id"], event_type="NOTE")
    tip = _approve(2, note["event_id"])
    return genesis, note, tip


def _parse_all(raw: list[dict[str, Any]]) -> list[Any]:
    return [parse_approval_event(item) for item in raw]


def test_empty_and_singleton() -> None:
    assert chains.order_chain([], invariant_id="X", version=1) == ()
    (genesis, _, _) = _chain()
    (only,) = chains.order_chain(_parse_all([genesis]), invariant_id="X", version=1)
    assert only.seq == 0


def test_orders_regardless_of_input_order() -> None:
    genesis, note, tip = _chain()
    ordered = chains.order_chain(_parse_all([tip, genesis, note]), invariant_id="X", version=1)
    assert [event.seq for event in ordered] == [0, 1, 2]


def test_lifecycle_events_order() -> None:
    first = _seal(
        {
            "seq": 0,
            "prev": None,
            "invariant_id": "X",
            "invariant_version": 1,
            "event_type": "ACTIVATE",
            "actor": "A",
            "timestamp": "2026-10-31T00:00:00+00:00",
        }
    )
    second = _seal(
        {
            "seq": 1,
            "prev": first["event_id"],
            "invariant_id": "X",
            "invariant_version": 1,
            "event_type": "DEPRECATE",
            "actor": "A",
            "timestamp": "2026-10-31T00:00:00+00:00",
        }
    )
    ordered = chains.order_chain(
        [parse_lifecycle_event(second), parse_lifecycle_event(first)],
        invariant_id="X",
        version=1,
    )
    assert [event.seq for event in ordered] == [0, 1]


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        (lambda g, n, t: [g, {**n, "invariant_id": "Y"}], "directory-mismatch"),
        (lambda g, n, t: [g, {**n, "invariant_version": 2}], "directory-mismatch"),
        (lambda g, n, t: [{**g, "prev": "0" * 64}], "inconsistent-sequence"),
        (lambda g, n, t: [g, {**n, "prev": None}], "inconsistent-sequence"),
        (lambda g, n, t: [g, {**n, "prev": "0" * 64}], "missing-predecessor"),
        (lambda g, n, t: [g, _approve(2, g["event_id"], approver="B")], "sequence-gap"),
        (lambda g, n, t: [g, n, _approve(1, g["event_id"], approver="B")], "fork"),
        (lambda g, n, t: [g, _approve(0, None, approver="B")], "competing-tips"),
    ],
)
def test_linkage_refusals(build: Any, reason: str) -> None:
    genesis, note, tip = _chain()
    raw = build(genesis, note, tip)
    resealed = [_seal({k: v for k, v in item.items() if k != "event_id"}) for item in raw]
    with pytest.raises(AmbiguousHistoryError) as err:
        chains.order_chain(_parse_all(resealed), invariant_id="X", version=1)
    assert err.value.reason_class == reason
