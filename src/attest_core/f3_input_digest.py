"""F3 input-manifest digest verification and workload composition (V-B13(b)(d)).

The digest covers the canonical bytes of the input_manifest
object with the frozen attest-canonical-json and NO F3
projection. A match establishes declared-manifest identity
(plus staged-byte identity once files verify) — never that
the benchmark process consumed those bytes (§18: no
consumption proof exists in F3 scope, and none is claimed).
"""

from __future__ import annotations

from typing import Any

from attest_core import f3_input_files as staged
from attest_core import f3_input_manifest as values
from attest_core.f3_digest import require_canonicalizer
from attest_core.f3_errors import F3Error
from attest_core.f3_manifest_entries import Finding, finding_for
from attest_sdk import canonical
from attest_sdk.errors import AttestError


def manifest_digest(manifest: dict[str, Any]) -> str:
    """SHA-256 hex over the canonical bytes of an input_manifest object."""
    try:
        return canonical.digest_of(manifest)
    except AttestError as exc:
        raise F3Error(
            rule="V-B13",
            section="8.3",
            location="$.input_manifest",
            reason=f"canonicalizer refused input manifest (fail closed): {exc}",
        ) from exc


def verify_workload_digest(
    workload: Any, location: str = "$", canonical_pin: Any = None
) -> tuple[Finding, ...]:
    """Compare the declared input_digest against the recomputed manifest digest."""
    if not isinstance(workload, dict):
        return (
            Finding(
                severity="INVALID",
                rule="V-B6",
                location=location,
                reason="workload must be an object",
            ),
        )
    if canonical_pin is not None:
        try:
            require_canonicalizer(canonical_pin, "8.2", "$.canonicalization")
        except F3Error as exc:
            return (finding_for(exc),)
    manifest = workload.get("input_manifest")
    if not isinstance(manifest, dict):
        return (
            Finding(
                severity="INVALID",
                rule="V-B6",
                location=f"{location}.input_manifest",
                reason="input_manifest must be an object",
            ),
        )
    try:
        computed = manifest_digest(manifest)
    except F3Error as exc:
        return (finding_for(exc),)
    declared = workload.get("input_digest")
    if computed != declared:
        return (
            Finding(
                severity="INVALID",
                rule="V-B13",
                location=f"{location}.input_digest",
                reason=(f"input_digest mismatch: computed {computed} != declared {declared!r}"),
            ),
        )
    return ()


def verify_workload(
    workload: Any,
    *,
    root_fd: int,
    root: str,
    location: str = "$",
    canonical_pin: Any = None,
) -> tuple[Finding, ...]:
    """Full per-entry workload verification: value, digest, then staged files.

    A refused manifest version stops all processing of that
    manifest (unknown contract, fail closed). `location` is the
    workload's own location (e.g. `$.campaign.invocations[0].workload`).
    """
    if not isinstance(workload, dict):
        return (
            Finding(
                severity="INVALID",
                rule="V-B6",
                location=location,
                reason="workload must be an object",
            ),
        )
    mloc = f"{location}.input_manifest"
    manifest = workload.get("input_manifest")
    refused = values.check_manifest_version(manifest, mloc)
    if refused is not None:
        return (refused,)
    out: list[Finding] = list(values.check_manifest_entries(manifest, mloc))
    out.extend(verify_workload_digest(workload, location, canonical_pin))
    entries = manifest.get("entries") if isinstance(manifest, dict) else None
    if isinstance(entries, list):
        out.extend(staged.verify_input_files(root_fd, root, entries, mloc))
    return tuple(out)
