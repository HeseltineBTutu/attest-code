"""F3 manifest-to-record label binding (V-B1).

Each manifest entry's claimed (record_id, kind, invocation_id)
must equal the resolved record's. Content equality is P2's
digest domain and is not repeated here.
"""

from __future__ import annotations

from typing import Any

from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records import AttemptRecord, TotalRecord
from attest_core.f3_records_campaign import CampaignRecord
from attest_core.f3_records_env import EnvRecord
from attest_core.f3_records_summary import SummaryRecord

Bound = AttemptRecord | TotalRecord | EnvRecord | CampaignRecord | SummaryRecord


def check_manifest_binding(
    pairs: list[tuple[int, Any, Bound | None]],
) -> tuple[Finding, ...]:
    """V-B1: manifest labels must match the record each entry resolved to."""
    out: list[Finding] = []
    for index, entry, record in pairs:
        if record is None:
            continue  # Unresolved entries are P2's findings, not relitigated.
        location = f"$.records[{index}]"
        if not isinstance(entry, dict):
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B6",
                    location=location,
                    reason="manifest entry must be an object",
                )
            )
            continue
        claimed = {
            "record_id": entry.get("record_id"),
            "kind": entry.get("kind"),
            "invocation_id": entry.get("invocation_id"),
        }
        actual = {
            "record_id": record.record_id,
            "kind": record.record_kind,
            "invocation_id": record.invocation_id,
        }
        for key in ("record_id", "kind", "invocation_id"):
            if claimed[key] != actual[key]:
                out.append(
                    Finding(
                        severity="INVALID",
                        rule="V-B1",
                        location=location,
                        reason=(
                            f"manifest entry {key} {claimed[key]!r} "
                            f"!= resolved record {actual[key]!r}"
                        ),
                    )
                )
    return tuple(out)
