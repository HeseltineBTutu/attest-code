"""F3 manifest top-level shape validation (V-B6)."""

from __future__ import annotations

from typing import Any

from attest_core import f3_fields as ff
from attest_core import f3_manifest_entries as entries
from attest_core import f3_schema as sc
from attest_core.f3_digest import require_canonicalizer, require_projection
from attest_core.f3_errors import F3Error

_TOP_KEYS = frozenset(
    {
        "campaign_id",
        "canonicalization",
        "digest_projection",
        "records",
        "evidence",
        "warmup_invocations",
    }
)


def shape_manifest(manifest: dict[str, Any]) -> tuple[list[entries.Finding], bool]:
    """Collect top-level shape findings; report whether pins passed."""
    findings: list[entries.Finding] = []
    unknown = sorted(k for k in manifest if k not in _TOP_KEYS and not k.startswith("observed_"))
    if unknown:
        findings.append(
            entries.Finding(
                severity="INVALID",
                rule="V-B6",
                location="$",
                reason=f"unknown manifest fields rejected: {unknown}",
            )
        )
    try:
        ff.uuid4(manifest.get("campaign_id"), "8.3", "$.campaign_id")
    except F3Error as exc:
        findings.append(entries.finding_for(exc))
    pins_ok = True
    for key, require in (
        ("canonicalization", require_canonicalizer),
        ("digest_projection", require_projection),
    ):
        if key not in manifest:
            findings.append(
                entries.Finding(
                    severity="INVALID",
                    rule="V-B6",
                    location=f"$.{key}",
                    reason="missing required field",
                )
            )
            pins_ok = False
        else:
            try:
                require(manifest[key], "8.3", f"$.{key}")
            except F3Error as exc:
                findings.append(entries.finding_for(exc))
                pins_ok = False
    warmups = manifest.get("warmup_invocations")
    if not isinstance(warmups, list):
        findings.append(
            entries.Finding(
                severity="INVALID",
                rule="V-B6",
                location="$.warmup_invocations",
                reason="must be a JSON list",
            )
        )
    else:
        for index, item in enumerate(warmups):
            try:
                sc.positive_int(item, "8.3", f"$.warmup_invocations[{index}]")
            except F3Error as exc:
                findings.append(entries.finding_for(exc))
                break
    for key in ("records", "evidence"):
        if not isinstance(manifest.get(key), list):
            findings.append(
                entries.Finding(
                    severity="INVALID",
                    rule="V-B6",
                    location=f"$.{key}",
                    reason="must be a JSON list",
                )
            )
    return findings, pins_ok
