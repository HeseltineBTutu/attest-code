"""F3 entry resolution: records and evidence end-to-end."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from f3_fixtures import (
    UUID_C,
    to_bytes,
    valid_attempt,
    valid_campaign,
    valid_env,
    valid_summary,
    valid_total,
)
from f3_package import evidence_entry, manifest_dict, record_entry, write_package

from attest_core.f3_manifest import verify_manifest

KINDS = {
    "attempt": valid_attempt,
    "invocation_total": valid_total,
    "environment": valid_env,
    "campaign": valid_campaign,
    "summary": valid_summary,
}


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_records_resolve_all_kinds(tmp_path: Path, kind: str) -> None:
    record = KINDS[kind]()
    entry = record_entry(record, "r.json")
    root = write_package(tmp_path, manifest_dict(records=[entry]), {"r.json": to_bytes(record)})
    (result,) = verify_manifest(root).entries
    assert result.severity == "VALID"
    assert result.record is not None
    assert result.record["record_kind"] == kind
    assert result.identity == record["record_id"]


def test_record_tampered_byte(tmp_path: Path) -> None:
    record = valid_attempt()
    entry = record_entry(record, "r.json")
    tampered = to_bytes(record).replace(b"41822", b"41823", 1)
    root = write_package(tmp_path, manifest_dict(records=[entry]), {"r.json": tampered})
    (result,) = verify_manifest(root).entries
    assert result.severity == "INVALID"
    assert result.findings[0].rule == "V-B1"
    assert "digest mismatch" in result.findings[0].reason
    assert result.record is None


def test_record_unparsable_bytes(tmp_path: Path) -> None:
    record = valid_attempt()
    entry = record_entry(record, "r.json")
    root = write_package(tmp_path, manifest_dict(records=[entry]), {"r.json": b"{oops"})
    (result,) = verify_manifest(root).entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-B1")
    assert "corrupt record bytes" in result.findings[0].reason


def test_record_schema_violation(tmp_path: Path) -> None:
    record = valid_attempt()
    del record["outcome"]
    entry = record_entry(valid_attempt(), "r.json")
    root = write_package(tmp_path, manifest_dict(records=[entry]), {"r.json": to_bytes(record)})
    (result,) = verify_manifest(root).entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-B6")


def test_record_kind_mismatch(tmp_path: Path) -> None:
    record = valid_attempt()
    entry = record_entry(record, "r.json")
    entry["kind"] = "invocation_total"
    root = write_package(tmp_path, manifest_dict(records=[entry]), {"r.json": to_bytes(record)})
    (result,) = verify_manifest(root).entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-B6")
    flipped = dict(valid_attempt(), record_kind="invocation_total")
    entry2 = record_entry(valid_attempt(), "t.json")
    root2 = tmp_path / "pkg2"
    root2.mkdir()
    write_package(root2, manifest_dict(records=[entry2]), {"t.json": to_bytes(flipped)})
    (result2,) = verify_manifest(root2).entries
    assert (result2.severity, result2.findings[0].rule) == ("INVALID", "V-B6")
    assert result2.findings[0].location == "$.record_kind"


def test_entry_invocation_null_mirror(tmp_path: Path) -> None:
    campaign = valid_campaign()
    bad = record_entry(campaign, "c.json")
    bad["invocation_id"] = UUID_C
    root = write_package(tmp_path, manifest_dict(records=[bad]), {"c.json": to_bytes(campaign)})
    (result,) = verify_manifest(root).entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-B6")
    assert result.findings[0].location.endswith(".invocation_id")
    attempt = valid_attempt()
    bad2 = record_entry(attempt, "a.json")
    bad2["invocation_id"] = None
    root2 = tmp_path / "pkg2"
    root2.mkdir()
    write_package(root2, manifest_dict(records=[bad2]), {"a.json": to_bytes(attempt)})
    (result2,) = verify_manifest(root2).entries
    assert (result2.severity, result2.findings[0].rule) == ("INVALID", "V-B6")


def test_record_missing_file(tmp_path: Path) -> None:
    entry = record_entry(valid_attempt(), "absent.json")
    root = write_package(tmp_path, manifest_dict(records=[entry]), {})
    (result,) = verify_manifest(root).entries
    assert (result.severity, result.findings[0].rule) == ("INCOMPLETE", "V-B1")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(record_id="nope"),
        lambda e: e.update(kind="bogus"),
        lambda e: e.update(invocation_id="nope"),
        lambda e: e.update(record_digest_sha256="zz"),
        lambda e: e.update(relpath=7),
        lambda e: e.pop("relpath"),
        lambda e: e.update(extra=1),
    ],
)
def test_record_entry_malformed(tmp_path: Path, mutate: Any) -> None:
    entry = record_entry(valid_attempt(), "r.json")
    mutate(entry)
    root = write_package(tmp_path, manifest_dict(records=[entry]), {})
    (result,) = verify_manifest(root).entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-B6")


def test_evidence_valid_and_opaque(tmp_path: Path) -> None:
    data = b'{"verdict": "PASSED", "opaque": true}\n'
    entry = evidence_entry(UUID_C, "r.json", data)
    root = write_package(tmp_path, manifest_dict(evidence=[entry]), {"r.json": data})
    (result,) = verify_manifest(root).entries
    assert result.severity == "VALID"
    assert result.record is None
    assert result.identity == f"({UUID_C}, s3-report)"


def test_evidence_non_json_bytes_validate(tmp_path: Path) -> None:
    data = b"\x00\x01\x02binary-\xff-not-json"
    entry = evidence_entry(UUID_C, "r.bin", data)
    root = write_package(tmp_path, manifest_dict(evidence=[entry]), {"r.bin": data})
    (result,) = verify_manifest(root).entries
    assert result.severity == "VALID"
    assert result.record is None


def test_evidence_tampered_and_missing(tmp_path: Path) -> None:
    data = b"original-bytes"
    entry = evidence_entry(UUID_C, "r.bin", data)
    root = write_package(tmp_path, manifest_dict(evidence=[entry]), {"r.bin": b"tampered-bytes"})
    (result,) = verify_manifest(root).entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-B1")
    assert "digest mismatch" in result.findings[0].reason
    root2 = tmp_path / "pkg2"
    root2.mkdir()
    write_package(root2, manifest_dict(evidence=[entry]), {})
    (result2,) = verify_manifest(root2).entries
    assert (result2.severity, result2.findings[0].rule) == ("INCOMPLETE", "V-B1")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(invocation_id="nope"),
        lambda e: e.update(role="s4-report"),
        lambda e: e.update(relpath=None),
        lambda e: e.update(evidence_digest_sha256="zz"),
        lambda e: e.pop("role"),
        lambda e: e.update(extra=1),
    ],
)
def test_evidence_entry_malformed(tmp_path: Path, mutate: Any) -> None:
    entry = evidence_entry(UUID_C, "r.bin", b"data")
    mutate(entry)
    root = write_package(tmp_path, manifest_dict(evidence=[entry]), {})
    (result,) = verify_manifest(root).entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-B6")


def test_duplicate_evidence_pairs_still_resolve(tmp_path: Path) -> None:
    data = b"evidence-bytes"
    first = evidence_entry(UUID_C, "a.bin", data)
    second = evidence_entry(UUID_C, "b.bin", data)
    manifest = manifest_dict(evidence=[first, second])
    root = write_package(tmp_path, manifest, {"a.bin": data, "b.bin": b"tampered!!"})
    first_result, second_result = verify_manifest(root).entries
    assert first_result.severity == "INVALID"
    assert [f.rule for f in first_result.findings] == ["V-B5"]
    assert "evidence[1]" in first_result.findings[0].reason
    assert second_result.severity == "INVALID"
    assert [f.rule for f in second_result.findings] == ["V-B5", "V-B1"]
