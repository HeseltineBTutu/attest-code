"""F3 manifest verification: digest, sidecar, and orchestration."""

from __future__ import annotations

import dataclasses
import os
from typing import Any

from attest_core import f3_fields as ff
from attest_core import f3_manifest_entries as entries
from attest_core import f3_manifest_shape as shape
from attest_core import f3_paths as paths
from attest_core.f3_digest import record_digest as compute_digest
from attest_core.f3_errors import F3Error, F3IncompleteError
from attest_sdk import canonical
from attest_sdk.errors import AttestError

MANIFEST_NAME = "manifest.json"
SIDECAR_NAME = "manifest.sha256"


@dataclasses.dataclass(frozen=True)
class ManifestReport:
    """Full manifest verification outcome (findings plus parsed manifest)."""

    manifest_findings: tuple[entries.Finding, ...]
    entries: tuple[entries.EntryResult, ...]
    manifest: dict[str, Any] | None

    @property
    def ok(self) -> bool:
        """True only when nothing failed anywhere."""
        if self.manifest_findings:
            return False
        return all(not item.findings for item in self.entries)


def _sidecar_digest(root_fd: int, root: str) -> str:
    """Read and shape-check the sidecar digest (raises on any problem)."""
    got = paths.read_confined_file(root_fd, root, SIDECAR_NAME, "8.3", "$.manifest.sha256")
    try:
        text = got.data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise F3Error(
            rule="V-B1",
            section="8.3",
            location="$.manifest.sha256",
            reason=f"malformed sidecar (non-ASCII bytes): {exc}",
        ) from exc
    if ff.DIGEST64_RE.fullmatch(text) is None:
        raise F3Error(
            rule="V-B1",
            section="8.3",
            location="$.manifest.sha256",
            reason="malformed sidecar (not a lowercase hex digest)",
        )
    return text


def verify_manifest(
    root: str | os.PathLike[str], *, manifest_digest: str | None = None
) -> ManifestReport:
    """Verify a package manifest and resolve every entry.

    Collects every violation instead of stopping at the first,
    except pin refusal (the package cannot be meaningfully
    verified further) and unreadable manifest bytes.
    """
    if manifest_digest is not None and (
        not isinstance(manifest_digest, str) or ff.DIGEST64_RE.fullmatch(manifest_digest) is None
    ):
        raise ValueError(f"explicit manifest digest must be SHA-256 hex: {manifest_digest!r}")
    path = os.fspath(root)
    if isinstance(path, bytes):
        raise ValueError("byte paths unsupported")
    root_fd = paths.open_root(path)
    try:
        return _verify_opened(root_fd, os.path.realpath(path), manifest_digest)
    finally:
        os.close(root_fd)


def _verify_opened(root_fd: int, root: str, trusted: str | None) -> ManifestReport:
    try:
        got = paths.read_confined_file(root_fd, root, MANIFEST_NAME, "8.3", "$.manifest")
    except F3Error as exc:
        finding = entries.finding_for(exc)
        return ManifestReport(manifest_findings=(finding,), entries=(), manifest=None)
    try:
        manifest = canonical.parse_bytes(got.data)
    except AttestError as exc:
        finding = entries.Finding(
            severity="INVALID",
            rule="V-B1",
            location="$",
            reason=f"corrupt manifest bytes: {exc.reason_class}: {exc}",
        )
        return ManifestReport(manifest_findings=(finding,), entries=(), manifest=None)
    if not isinstance(manifest, dict):
        finding = entries.Finding(
            severity="INVALID",
            rule="V-B6",
            location="$",
            reason="manifest must be a JSON object",
        )
        return ManifestReport(manifest_findings=(finding,), entries=(), manifest=None)
    findings, pins_ok = shape.shape_manifest(manifest)
    if not pins_ok:
        return ManifestReport(manifest_findings=tuple(findings), entries=(), manifest=manifest)
    digest = trusted
    if digest is None:
        try:
            digest = _sidecar_digest(root_fd, root)
        except F3IncompleteError as exc:
            findings.append(entries.finding_for(exc))
            digest = None
        except F3Error as exc:
            findings.append(entries.finding_for(exc))
            digest = None
    if digest is not None:
        try:
            computed = compute_digest("manifest", manifest)
        except F3Error as exc:
            findings.append(entries.finding_for(exc))
        else:
            if computed != digest:
                findings.append(
                    entries.Finding(
                        severity="INVALID",
                        rule="V-B1",
                        location="$.manifest_digest",
                        reason=f"digest mismatch: computed {computed} != listed {digest!r}",
                    )
                )
    records = manifest["records"] if isinstance(manifest.get("records"), list) else []
    evidence = manifest["evidence"] if isinstance(manifest.get("evidence"), list) else []
    results = entries.resolve_all(root_fd, root, records, evidence)
    return ManifestReport(
        manifest_findings=tuple(findings), entries=tuple(results), manifest=manifest
    )
