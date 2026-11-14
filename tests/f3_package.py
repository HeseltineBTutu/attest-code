"""Shared package builders for F3 manifest tests (hand-built fixtures)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from f3_fixtures import UUID_A

from attest_core.f3_digest import record_digest

CANON = {"name": "attest-canonical-json", "version": 1}
PROJ = {"name": "f3-digest-projection", "version": 1}


def manifest_dict(
    records: list[Any] | None = None, evidence: list[Any] | None = None, **overrides: Any
) -> dict[str, Any]:
    """A valid manifest document with optional entry lists."""
    base: dict[str, Any] = {
        "campaign_id": UUID_A,
        "canonicalization": dict(CANON),
        "digest_projection": dict(PROJ),
        "records": records if records is not None else [],
        "evidence": evidence if evidence is not None else [],
        "warmup_invocations": [],
    }
    base.update(overrides)
    return base


def record_entry(record: dict[str, Any], relpath: str, digest: str | None = None) -> dict[str, Any]:
    """A records[] entry with a correct (or explicitly wrong) digest."""
    kind = record["record_kind"]
    return {
        "record_id": record["record_id"],
        "kind": kind,
        "invocation_id": record["invocation_id"],
        "record_digest_sha256": digest if digest is not None else record_digest(kind, record),
        "relpath": relpath,
    }


def evidence_entry(
    invocation_id: str, relpath: str, data: bytes, digest: str | None = None
) -> dict[str, Any]:
    """An evidence[] entry with a correct (or explicitly wrong) digest."""
    return {
        "invocation_id": invocation_id,
        "role": "s3-report",
        "relpath": relpath,
        "evidence_digest_sha256": (
            digest if digest is not None else hashlib.sha256(data).hexdigest()
        ),
    }


def write_package(
    root: Path,
    manifest: dict[str, Any] | None = None,
    files: dict[str, bytes] | None = None,
    sidecar: str | bytes | None = "auto",
    raw_manifest: bytes | None = None,
) -> Path:
    """Write a package tree; sidecar auto-computed unless given/omitted."""
    for relpath, data in (files or {}).items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if raw_manifest is not None:
        body = raw_manifest
    else:
        assert manifest is not None
        body = (json.dumps(manifest) + "\n").encode()
    (root / "manifest.json").write_bytes(body)
    if sidecar == "auto":
        assert manifest is not None, "auto sidecar needs a manifest dict"
        (root / "manifest.sha256").write_text(record_digest("manifest", manifest) + "\n")
    elif isinstance(sidecar, str):
        (root / "manifest.sha256").write_text(sidecar)
    elif isinstance(sidecar, bytes):
        (root / "manifest.sha256").write_bytes(sidecar)
    return root
