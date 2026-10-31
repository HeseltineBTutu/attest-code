"""Chain linkage validation shared by approval and lifecycle histories."""

from __future__ import annotations

from typing import Any, overload

from attest_sdk.errors import AmbiguousHistoryError
from attest_sdk.events import ApprovalEvent, LifecycleEvent


def _fail(message: str, reason: str) -> AmbiguousHistoryError:
    return AmbiguousHistoryError(message, reason_class=reason)


@overload
def order_chain(
    events: list[ApprovalEvent], *, invariant_id: str, version: int
) -> tuple[ApprovalEvent, ...]: ...


@overload
def order_chain(
    events: list[LifecycleEvent], *, invariant_id: str, version: int
) -> tuple[LifecycleEvent, ...]: ...


def order_chain(events: list[Any], *, invariant_id: str, version: int) -> tuple[Any, ...]:
    """Validate transplant/linkage rules; return oldest-first order.

    Sequence arithmetic makes cycles unrepresentable (a loop would
    require seq == seq + n); the seen-set still guards the walk so
    a logic error fails closed instead of hanging.
    """
    if not events:
        return ()
    for event in events:
        if event.invariant_id != invariant_id or event.invariant_version != version:
            raise _fail("event does not match its directory", "directory-mismatch")
        if (event.prev is None) != (event.seq == 0):
            raise _fail("prev/seq inconsistency", "inconsistent-sequence")
    by_id = {event.event_id: event for event in events}
    children: dict[str, list[Any]] = {}
    for event in events:
        if event.prev is None:
            continue
        parent = by_id.get(event.prev)
        if parent is None:
            raise _fail("predecessor missing", "missing-predecessor")
        if parent.seq + 1 != event.seq:
            raise _fail("sequence gap", "sequence-gap")
        children.setdefault(event.prev, []).append(event)
    for kids in children.values():
        if len(kids) > 1:
            raise _fail("event has multiple successors", "fork")
    geneses = [event for event in events if event.seq == 0]
    if len(geneses) != 1:
        raise _fail("history has no single genesis", "competing-tips")
    ordered: list[Any] = []
    seen: set[str] = set()
    current: Any | None = geneses[0]
    while current is not None:
        if current.event_id in seen:
            raise _fail("cycle in history", "cycle-detected")
        seen.add(current.event_id)
        ordered.append(current)
        kids = children.get(current.event_id, [])
        current = kids[0] if kids else None
    if len(ordered) != len(events):
        raise _fail("disconnected history", "competing-tips")
    return tuple(ordered)
