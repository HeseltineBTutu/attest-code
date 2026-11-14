"""F3 P5 package entry point: series validation over typed records.

Decomposes the campaign into series (W3), checks warm-up
declarations (W1) and prefixes (W3), then machine class (W4)
and configuration (W2) per series. P3 identity runs first in
P8; without exactly one campaign record there is no declared
set to decompose, so P5 reports nothing (P3 owns that case).
"""

from __future__ import annotations

from typing import TypeVar

from attest_core import f3_config as config
from attest_core import f3_machine as machine
from attest_core import f3_series as series
from attest_core.f3_identity import PackageRecords
from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records import AttemptRecord
from attest_core.f3_records_env import EnvRecord
from attest_core.f3_series import Diagnostic, SeriesReport


def check_package_series(package: PackageRecords) -> SeriesReport:
    """Validate every series of a single-campaign package."""
    if len(package.campaigns) != 1:
        return SeriesReport(series=(), findings=(), diagnostics=())
    campaign = package.campaigns[0]
    decomposed = series.compute_series(campaign)
    attempts = [(f"attempt[{i}]", record) for i, record in enumerate(package.attempts)]
    envs = [(f"env[{i}]", record) for i, record in enumerate(package.envs)]
    grouped_a = _group(attempts)
    grouped_e = _group(envs)
    findings: list[Finding] = list(series.check_warmup_declarations(campaign))
    diagnostics: list[Diagnostic] = []
    for item in decomposed:
        findings.extend(series.check_prefix(item))
        item_findings, item_notes = machine.check_series_class(item, grouped_e)
        findings.extend(item_findings)
        diagnostics.extend(item_notes)
        findings.extend(config.check_series_config(item, grouped_a, grouped_e))
    return SeriesReport(series=decomposed, findings=tuple(findings), diagnostics=tuple(diagnostics))


_R = TypeVar("_R", AttemptRecord, EnvRecord)


def _group(labeled: list[tuple[str, _R]]) -> dict[str, list[tuple[str, _R]]]:
    """Group labeled records by invocation (P3-consistent labels)."""
    out: dict[str, list[tuple[str, _R]]] = {}
    for label, record in labeled:
        out.setdefault(record.invocation_id, []).append((label, record))
    return out
