"""Builders for P4 input-manifest tests (deterministic, hand-pinned goldens)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from f3_identity_pkg import TRIPLE, campaign, entry

EMPTY_DIGEST = "cbf0e06ab2d70490a3b0fdb0a4c812758bcf98e62433db3ac4f77bc8048ad64c"
LITERAL_DIGEST = "d07e4bc140f53bbde0620983455fb46d2ba24b7665c6c0eb48ad9d4d5996bb6a"


def file_entry(
    relpath: str = "inputs/data.bin",
    data: bytes = b"input-bytes",
    **overrides: Any,
) -> dict[str, Any]:
    """A file entry with correct size/hash unless overridden."""
    base: dict[str, Any] = {
        "kind": "file",
        "relpath": relpath,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    base.update(overrides)
    return base


def literal_entry(name: str = "seed", value: str = "abc") -> dict[str, Any]:
    """A literal entry (no staged file)."""
    return {"kind": "literal", "name": name, "value": value}


def manifest(entries: Any = (), version: Any = 1) -> dict[str, Any]:
    """An input_manifest object (validators judge its content)."""
    return {"manifest_version": version, "entries": list(entries)}


def workload(manifest_obj: dict[str, Any], digest: str | None = None) -> dict[str, Any]:
    """A workload declaration with a stated (possibly wrong) input_digest."""
    from attest_core.f3_input_digest import manifest_digest

    klass, wid, _ = TRIPLE
    return {
        "workload_class": klass,
        "workload_id": wid,
        "input_digest": manifest_digest(manifest_obj) if digest is None else digest,
        "input_manifest": manifest_obj,
    }


def validated_workload(
    manifest_obj: dict[str, Any], digest: str, invocation: str | None = None
) -> dict[str, Any]:
    """A P0-validated entry workload (realistic P0 → P4 pipeline input)."""
    from f3_identity_pkg import INVOCATION_1

    klass, wid, _ = TRIPLE
    camp = campaign(
        [entry(invocation or INVOCATION_1, 1, triple=(klass, wid, digest), manifest=manifest_obj)],
        targets=["repaired"],
    )
    return dict(camp.invocations[0]["workload"])


def stage(root: Path, files: dict[str, bytes]) -> None:
    """Write staged input files under a package root."""
    for relpath, data in files.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def triples(findings: Any) -> list[tuple[str, str, str]]:
    """Findings as (severity, rule, location) triples for exact assertions."""
    return [(item.severity, item.rule, item.location) for item in findings]
