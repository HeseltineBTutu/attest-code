"""F3 entry resolution: confined reads plus digest verification.

Record entries resolve by strict-parse, schema validation, and
digest comparison (V-B1). Evidence entries resolve by raw-byte
hash comparison only — their bytes are NEVER parsed (V-B5).
"""

from __future__ import annotations

import hashlib
from typing import Any

from attest_core import f3_paths as paths
from attest_core.f3_digest import record_digest
from attest_core.f3_errors import F3Error
from attest_sdk import canonical
from attest_sdk.errors import AttestError


def resolve_record(
    root_fd: int, root: str, entry: dict[str, Any], location: str
) -> tuple[dict[str, Any], tuple[int, int]]:
    """Resolve one record entry; returns (validated mapping, file identity)."""
    got = paths.read_confined_file(root_fd, root, entry["relpath"], "8.5", f"{location}.relpath")
    try:
        parsed: dict[str, Any] = canonical.parse_bytes(got.data)
    except AttestError as exc:
        raise F3Error(
            rule="V-B1",
            section="8.3",
            location=location,
            reason=f"corrupt record bytes: {exc.reason_class}: {exc}",
        ) from exc
    digest = record_digest(entry["kind"], parsed)
    if digest != entry["record_digest_sha256"]:
        raise F3Error(
            rule="V-B1",
            section="8.3",
            location=location,
            reason=f"digest mismatch: computed {digest} "
            f"!= listed {entry['record_digest_sha256']!r}",
        )
    return parsed, (got.dev, got.ino)


def resolve_evidence(
    root_fd: int, root: str, entry: dict[str, Any], location: str
) -> tuple[int, int]:
    """Resolve one evidence entry by raw-byte hash; returns file identity."""
    got = paths.read_confined_file(root_fd, root, entry["relpath"], "8.5", f"{location}.relpath")
    digest = hashlib.sha256(got.data).hexdigest()
    if digest != entry["evidence_digest_sha256"]:
        raise F3Error(
            rule="V-B1",
            section="8.3",
            location=location,
            reason=f"digest mismatch: computed {digest} "
            f"!= listed {entry['evidence_digest_sha256']!r}",
        )
    return (got.dev, got.ino)
