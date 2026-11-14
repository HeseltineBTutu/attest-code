"""F3 golden digest vectors: byte-exact canonical inputs and digests.

Vectors were generated from the implementation, then verified by
hand (key order, separators, escapes, NFC, exclusions) with digests
cross-checked against an independent sha256sum before committing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from f3_fixtures import (
    DIGEST,
    UUID_A,
    UUID_C,
    valid_attempt,
    valid_campaign,
    valid_env,
    valid_summary,
    valid_total,
)

from attest_core.f3_digest import project, record_digest
from attest_sdk import canonical

VECTORS = Path(__file__).resolve().parent / "f3_vectors"


def _vector(name: str) -> tuple[bytes, str]:
    blob = (VECTORS / f"{name}.bin").read_bytes()
    digest = (VECTORS / f"{name}.sha").read_text(encoding="utf-8").strip()
    return blob, digest


def _manifest() -> dict[str, Any]:
    return {
        "campaign_id": UUID_A,
        "canonicalization": {"name": "attest-canonical-json", "version": 1},
        "digest_projection": {"name": "f3-digest-projection", "version": 1},
        "records": [
            {
                "record_id": UUID_A,
                "kind": "attempt",
                "invocation_id": UUID_C,
                "record_digest_sha256": DIGEST,
                "relpath": "attempt-a.json",
            }
        ],
        "evidence": [
            {
                "invocation_id": UUID_C,
                "role": "s3-report",
                "relpath": "r.json",
                "evidence_digest_sha256": DIGEST,
            }
        ],
        "warmup_invocations": [1],
        "observed_start": "2026-11-13T10:00:00Z",
        "observed_end": "2026-11-13T10:01:00Z",
    }


def _summary_nfc() -> dict[str, Any]:
    # Explicit decomposed e + combining acute: canonical bytes MUST
    # carry composed U+00E9 as raw UTF-8 (C3 A9), proving NFC plus
    # non-ensure_ascii emission (stdlib json would emit \u00e9).
    return valid_summary(context={"note": "cafe\u0301", "campaign": "s3"})


def test_vector_attempt() -> None:
    blob, digest = _vector("v1_attempt")
    record = valid_attempt()
    assert canonical.canonicalize(project("attempt", record)) == blob
    assert record_digest("attempt", record) == digest


def test_vector_total() -> None:
    blob, digest = _vector("v2_total")
    record = valid_total()
    assert canonical.canonicalize(project("invocation_total", record)) == blob
    assert record_digest("invocation_total", record) == digest


def test_vector_environment() -> None:
    blob, digest = _vector("v3_env")
    record = valid_env()
    assert canonical.canonicalize(project("environment", record)) == blob
    assert record_digest("environment", record) == digest


def test_vector_campaign() -> None:
    blob, digest = _vector("v4_campaign")
    record = valid_campaign()
    assert b"observed_start_wallclock" not in blob
    assert canonical.canonicalize(project("campaign", record)) == blob
    assert record_digest("campaign", record) == digest


def test_vector_summary_nfc() -> None:
    blob, digest = _vector("v5_summary")
    record = _summary_nfc()
    assert b"\xc3\xa9" in blob
    assert b"e\xcc\x81" not in blob
    assert canonical.canonicalize(project("summary", record)) == blob
    assert record_digest("summary", record) == digest


def test_vector_manifest() -> None:
    blob, digest = _vector("v6_manifest")
    manifest = _manifest()
    assert b"observed_" not in blob
    assert b'"evidence":' in blob
    assert canonical.canonicalize(project("manifest", manifest)) == blob
    assert record_digest("manifest", manifest) == digest


def test_timestamp_mutation_invariance() -> None:
    base = record_digest("campaign", valid_campaign())
    moved = dict(valid_campaign(), observed_start_wallclock="2030-01-01T00:00:00Z")
    assert record_digest("campaign", moved) == base
    manifest = _manifest()
    mbase = record_digest("manifest", manifest)
    manifest["observed_start"] = "2030-01-01T00:00:00Z"
    assert record_digest("manifest", manifest) == mbase


def test_covered_field_mutation_changes_digest() -> None:
    base = record_digest("attempt", valid_attempt())
    assert record_digest("attempt", valid_attempt(pid=1)) != base
