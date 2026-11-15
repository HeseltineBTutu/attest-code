"""Orchestration builders for P7 composition tests (real P3/P5/P6 outputs)."""

from __future__ import annotations

from typing import Any

from f3_series_pkg import camp, invocation, package

from attest_core.f3_compare_attrs import derive_attributes
from attest_core.f3_compose import compose_package
from attest_core.f3_identity import check_identity
from attest_core.f3_measure import measure_invocation
from attest_core.f3_quorum import evaluate_quorum
from attest_core.f3_series_check import check_package_series

RID_ONE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
RID_TWO = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"


def single(envs: list[Any]) -> Any:
    """The single environment record, else None (P3 owns other counts)."""
    return envs[0] if len(envs) == 1 else None


def pieces(
    view: Any,
    evidence: set[str],
    record_ids: dict[Any, str],
    required: int,
    findings: tuple[Any, ...] = (),
) -> dict[str, Any]:
    """Real P3/P5/P6 outputs over a view, as compose_package kwargs."""
    identity = check_identity(view)
    report = check_package_series(view)
    attempts: dict[str, list[Any]] = {}
    totals: dict[str, list[Any]] = {}
    envs: dict[str, list[Any]] = {}
    for record in view.attempts:
        attempts.setdefault(record.invocation_id, []).append(record)
    for record in view.totals:
        totals.setdefault(record.invocation_id, []).append(record)
    for record in view.envs:
        envs.setdefault(record.invocation_id, []).append(record)
    members = [m.invocation_id for s in report.series for m in s.members]
    by_inv = {
        inv: measure_invocation(
            inv, attempts.get(inv, []), totals.get(inv, []), len(envs.get(inv, []))
        )
        for inv in members
    }
    quorums = {
        s.key: evaluate_quorum(
            series=s, measurements=by_inv, evidence_ok=evidence, required_successful=required
        )
        for s in report.series
    }
    attributes = {
        inv: derive_attributes(inv, attempts.get(inv, []), single(envs.get(inv, [])))
        for inv in members
    }
    return {
        "package": view,
        "identity": identity,
        "workload_findings": findings,
        "series_report": report,
        "measurements": by_inv,
        "quorums": quorums,
        "attributes": attributes,
        "record_ids": record_ids,
    }


def orchestrate(view: Any, evidence: set[str], record_ids: dict[Any, str], required: int) -> Any:
    """Compose a view end to end with real upstream reports."""
    return compose_package(**pieces(view, evidence, record_ids, required))


def setup(specs: list[Any]) -> Any:
    """A campaign plus coherent record groups for (invocation, sample) specs."""
    warmups = [i + 1 for i, (_, sample) in enumerate(specs) if sample == "warmup"]
    campaign = camp(specs, warmups=warmups)
    groups = [invocation(inv, sample=sample) for inv, sample in specs]
    return campaign, package(campaign, *groups)
