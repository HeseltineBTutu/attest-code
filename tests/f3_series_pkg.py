"""Builders for P5 series tests (multi-invocation coherent packages)."""

from __future__ import annotations

import itertools
from typing import Any

from f3_fixtures import valid_campaign
from f3_identity_pkg import CAMPAIGN_ID, TRIPLE, attempt, env, total, view

from attest_core.f3_identity import PackageRecords
from attest_core.f3_records_campaign import CampaignRecord, validate_campaign

INVOCATION_3 = "77777777-7777-4777-8777-777777777777"
MARK = {"unavailable": "probe-failed"}

_counter = itertools.count(1000)


def _rid() -> str:
    """Fresh valid UUIDv4 record id."""
    return f"bbbbbbbb-bbbb-4bbb-8bbb-{next(_counter):012x}"


def invocation(
    inv: str,
    *,
    sample: str = "measured",
    target: str = "repaired",
    triple: tuple[str, str, str] = TRIPLE,
    profile: str = "hardened",
    timeout: str = "60.000000000",
    attempts: int = 3,
    env_overrides: dict[str, Any] | None = None,
    attempt_numbers: tuple[int, ...] | None = None,
) -> tuple[list, Any, Any]:
    """Coherent (attempts, total, env) for one invocation."""
    klass, wid, digest = triple
    numbers = attempt_numbers if attempt_numbers is not None else tuple(range(1, attempts + 1))
    made = [
        attempt(
            inv,
            n,
            target=target,
            workload_class=klass,
            workload_id=wid,
            input_digest=digest,
            sample_class=sample,
            profile=profile,
            timeout_s=timeout,
        )
        for n in numbers
    ]
    tot = total(
        inv,
        target=target,
        workload_class=klass,
        workload_id=wid,
        input_digest=digest,
        sample_class=sample,
        profile=profile,
        attempts_completed=len(numbers),
        attempts_total=3,
        attempt_outcomes={"PASS": len(numbers)},
    )
    env_kw: dict[str, Any] = {"profile": profile}
    env_kw.update(env_overrides or {})
    environment = env(
        inv,
        target=target,
        workload_class=klass,
        workload_id=wid,
        input_digest=digest,
        sample_class=sample,
        **env_kw,
    )
    return made, tot, environment


def camp(
    specs: list[tuple[str, str]],
    *,
    warmups: list[int] | None = None,
    targets: list[str] | None = None,
    triples: dict[str, tuple[str, str, str]] | None = None,
    sequences: list[int] | None = None,
    entry_targets: dict[str, str] | None = None,
) -> CampaignRecord:
    """A campaign declaring the given (invocation, sample_class) entries."""
    triples = triples or {}
    entry_targets = entry_targets or {}
    entries = []
    for position, (inv, sample) in enumerate(specs):
        seq = sequences[position] if sequences else position + 1
        triple = triples.get(inv, TRIPLE)
        klass, wid, digest = triple
        entries.append(
            {
                "run_sequence": seq,
                "invocation_id": inv,
                "sample_class": sample,
                "target": entry_targets.get(inv, "repaired"),
                "workload": {
                    "workload_class": klass,
                    "workload_id": wid,
                    "input_digest": digest,
                    "input_manifest": {"manifest_version": 1, "entries": []},
                },
            }
        )
    protocol = {
        "benchmark_category": "end-to-end",
        "required_successful": 5,
        "attempts_per_invocation": 3,
        "warmup_invocations": warmups if warmups is not None else [],
        "targets": targets if targets is not None else ["repaired"],
        "profile": "hardened",
    }
    return validate_campaign(
        valid_campaign(
            record_id=_rid(), campaign_id=CAMPAIGN_ID, protocol=protocol, invocations=entries
        )
    )


def package(campaign: CampaignRecord, *groups: tuple[list, Any, Any]) -> PackageRecords:
    """Assemble a view from per-invocation record groups."""
    made: list = []
    totals: list = []
    envs: list = []
    for group_attempts, group_total, group_env in groups:
        made.extend(group_attempts)
        totals.append(group_total)
        envs.append(group_env)
    return view(campaign, attempts=made, totals=totals, envs=envs)


def triples(report: Any) -> list[tuple[str, str, str]]:
    """Findings as (severity, rule, location) triples."""
    return [(item.severity, item.rule, item.location) for item in report.findings]


def notes(report: Any) -> list[tuple[str, str]]:
    """Diagnostics as (rule, location) pairs."""
    return [(item.rule, item.location) for item in report.diagnostics]
