"""F3 campaign declaration self-consistency (V-B8 engine leg, R-ID2, R-ID3, R-ID9).

The campaign record is the expected-set root: the engine pin,
declaration uniqueness, run_sequence density, and declared
target membership are checked before any record is grouped.
"""

from __future__ import annotations

from attest_core import f3_identity_totals as chain
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records_campaign import CampaignRecord


def check_declarations(campaign: CampaignRecord) -> list[Finding]:
    """Self-consistency of one campaign declaration."""
    out: list[Finding] = []
    engine = chain.check_engine(int(campaign.protocol["attempts_per_invocation"]))
    if engine is not None:
        out.append(engine)
    seen: dict[str, int] = {}
    for index, entry in enumerate(campaign.invocations):
        key = str(entry["invocation_id"])
        if key in seen:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="R-ID2",
                    location=f"$.campaign.invocations[{index}]",
                    reason=(
                        f"duplicate invocation_id {key!r} "
                        f"(also at $.campaign.invocations[{seen[key]}])"
                    ),
                )
            )
        else:
            seen[key] = index
        if entry["target"] not in campaign.protocol["targets"]:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="R-ID9",
                    location=f"$.campaign.invocations[{index}]",
                    reason=(f"declared target {entry['target']!r} not in protocol.targets"),
                )
            )
    want = set(range(1, len(campaign.invocations) + 1))
    found = {int(item["run_sequence"]) for item in campaign.invocations}
    if found != want:
        out.append(
            Finding(
                severity="INVALID",
                rule="R-ID3",
                location="$.campaign.invocations",
                reason=(
                    "run_sequence must be dense 1..N over declared invocations: "
                    f"want {sorted(want)}, found {sorted(found)}"
                ),
            )
        )
    return out
