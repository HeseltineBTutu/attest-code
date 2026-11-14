"""Typed-record package builders for P3 identity tests (deterministic)."""

from __future__ import annotations

import itertools
from typing import Any

from attest_core.f3_identity import IdentityReport, PackageRecords
from attest_core.f3_records import AttemptRecord, TotalRecord, validate_attempt, validate_total
from attest_core.f3_records_campaign import CampaignRecord, validate_campaign
from attest_core.f3_records_env import EnvRecord, validate_environment
from tests.f3_fixtures import (
    DIGEST,
    UUID_A,
    UUID_C,
    valid_attempt,
    valid_campaign,
    valid_env,
    valid_total,
)

CAMPAIGN_ID = UUID_A
INVOCATION_1 = UUID_C
INVOCATION_2 = "66666666-6666-4666-8666-666666666666"
TRIPLE = ("Medium", "auth-admin-001", DIGEST)

_counter = itertools.count(1)


def _rid() -> str:
    """Fresh valid UUIDv4 record id (version/variant bits set)."""
    return f"aaaaaaaa-aaaa-4aaa-8aaa-{next(_counter):012x}"


def _manifest(entries: Any = ()) -> dict[str, Any]:
    return {"manifest_version": 1, "entries": list(entries)}


def attempt(invocation: str = INVOCATION_1, number: int = 1, **overrides: Any) -> AttemptRecord:
    """One validated attempt record with coherent default echoes."""
    base: dict[str, Any] = {
        "record_id": _rid(),
        "campaign_id": CAMPAIGN_ID,
        "invocation_id": invocation,
        "attempt": number,
    }
    base.update(overrides)
    return validate_attempt(valid_attempt(**base))


def total(invocation: str = INVOCATION_1, **overrides: Any) -> TotalRecord:
    """One validated total record with coherent default echoes."""
    base: dict[str, Any] = {
        "record_id": _rid(),
        "campaign_id": CAMPAIGN_ID,
        "invocation_id": invocation,
    }
    base.update(overrides)
    return validate_total(valid_total(**base))


def env(invocation: str = INVOCATION_1, **overrides: Any) -> EnvRecord:
    """One validated environment record with coherent default echoes."""
    base: dict[str, Any] = {
        "record_id": _rid(),
        "campaign_id": CAMPAIGN_ID,
        "invocation_id": invocation,
    }
    base.update(overrides)
    return validate_environment(valid_env(**base))


def entry(
    invocation: str,
    sequence: int,
    *,
    sample_class: str = "measured",
    target: str = "repaired",
    triple: tuple[str, str, str] = TRIPLE,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One campaign invocation entry with a P0-valid workload declaration."""
    klass, wid, digest = triple
    return {
        "run_sequence": sequence,
        "invocation_id": invocation,
        "sample_class": sample_class,
        "target": target,
        "workload": {
            "workload_class": klass,
            "workload_id": wid,
            "input_digest": digest,
            "input_manifest": manifest if manifest is not None else _manifest(),
        },
    }


def campaign(
    entries: list[dict[str, Any]] | None = None,
    *,
    targets: list[str] | None = None,
    protocol_n: int = 3,
) -> CampaignRecord:
    """One validated campaign record declaring the given entries."""
    if entries is None:
        entries = [entry(INVOCATION_1, 1)]
    protocol = {
        "benchmark_category": "end-to-end",
        "required_successful": 5,
        "attempts_per_invocation": protocol_n,
        "warmup_invocations": [],
        "targets": targets if targets is not None else ["repaired"],
        "profile": "hardened",
    }
    return validate_campaign(
        valid_campaign(
            record_id=_rid(),
            campaign_id=CAMPAIGN_ID,
            protocol=protocol,
            invocations=entries,
        )
    )


def view(
    camp: CampaignRecord | list[CampaignRecord] | None = "auto",
    attempts: list[AttemptRecord] | None = None,
    totals: list[TotalRecord] | None = None,
    envs: list[EnvRecord] | None = None,
) -> PackageRecords:
    """Assemble a PackageRecords view (`"auto"` builds the default campaign)."""
    if camp == "auto":
        camp = campaign()
    campaigns = () if camp is None else (camp if isinstance(camp, list) else (camp,))
    return PackageRecords(
        campaigns=tuple(campaigns),
        attempts=tuple(attempts or ()),
        totals=tuple(totals or ()),
        envs=tuple(envs or ()),
    )


def valid_package() -> PackageRecords:
    """One complete coherent invocation: 3 attempts, total, environment."""
    made = [attempt(INVOCATION_1, n) for n in (1, 2, 3)]
    return view(campaign(), attempts=made, totals=[total(INVOCATION_1)], envs=[env(INVOCATION_1)])


def issues(report: IdentityReport) -> list[tuple[str, str, str]]:
    """Findings as (severity, rule, location) triples for exact assertions."""
    return [(item.severity, item.rule, item.location) for item in report.findings]
