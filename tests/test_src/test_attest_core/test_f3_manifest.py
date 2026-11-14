"""F3 manifest documents: shape, pins, digest, and sidecar."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from f3_fixtures import to_bytes, valid_attempt
from f3_package import manifest_dict, record_entry, write_package

from attest_core.f3_digest import record_digest
from attest_core.f3_manifest import verify_manifest


def _findings(report: Any) -> list[tuple[str, str, str]]:
    return [(f.severity, f.rule, f.location) for f in report.manifest_findings]


def test_valid_empty_package(tmp_path: Path) -> None:
    report = verify_manifest(write_package(tmp_path, manifest_dict()))
    assert report.ok is True
    assert report.manifest_findings == ()
    assert report.entries == ()
    assert report.manifest is not None


def test_observed_keys_accepted(tmp_path: Path) -> None:
    manifest = manifest_dict(observed_note="anything", observed_count=7)
    report = verify_manifest(write_package(tmp_path, manifest))
    assert report.ok is True


def test_unknown_top_key(tmp_path: Path) -> None:
    manifest = manifest_dict(smuggled={"x": 1})
    report = verify_manifest(write_package(tmp_path, manifest))
    assert report.ok is False
    assert _findings(report) == [("INVALID", "V-B6", "$")]


def test_campaign_id_shape(tmp_path: Path) -> None:
    report = verify_manifest(write_package(tmp_path, manifest_dict(campaign_id="nope")))
    assert _findings(report) == [("INVALID", "V-B6", "$.campaign_id")]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("canonicalization", {"name": "nope", "version": 1}),
        ("canonicalization", {"name": "attest-canonical-json", "version": 2}),
        ("canonicalization", {"name": "attest-canonical-json"}),
        ("canonicalization", []),
        ("digest_projection", {"name": "f3-digest-projection", "version": 0}),
        ("digest_projection", {"name": "f3-digest-projection", "version": 1, "x": 1}),
    ],
)
def test_bad_pins_refuse_package(tmp_path: Path, key: str, value: Any) -> None:
    rec = valid_attempt()
    entry = record_entry(rec, "a.json")
    manifest = manifest_dict(**{key: value, "records": [entry]})
    report = verify_manifest(write_package(tmp_path, manifest, {"a.json": to_bytes(rec)}))
    assert report.ok is False
    assert report.entries == ()
    assert any(f.rule == "V-B6" and f.severity == "INVALID" for f in report.manifest_findings)


def test_missing_pin_key(tmp_path: Path) -> None:
    manifest = manifest_dict()
    del manifest["digest_projection"]
    report = verify_manifest(write_package(tmp_path, manifest))
    assert report.entries == ()
    assert ("INVALID", "V-B6", "$.digest_projection") in _findings(report)


def test_warmup_shapes(tmp_path: Path) -> None:
    for warmups in ([3, 1], [2, 2]):
        good = verify_manifest(write_package(tmp_path, manifest_dict(warmup_invocations=warmups)))
        assert good.ok is True
    bad = verify_manifest(write_package(tmp_path, manifest_dict(warmup_invocations={"a": 1})))
    assert _findings(bad) == [("INVALID", "V-B6", "$.warmup_invocations")]
    bad2 = verify_manifest(write_package(tmp_path, manifest_dict(warmup_invocations=[1, -2])))
    assert _findings(bad2) == [("INVALID", "V-B6", "$.warmup_invocations[1]")]


def test_records_evidence_must_be_lists(tmp_path: Path) -> None:
    report = verify_manifest(write_package(tmp_path, manifest_dict(records={})))
    assert report.entries == ()
    assert ("INVALID", "V-B6", "$.records") in _findings(report)


def test_manifest_digest_mismatch(tmp_path: Path) -> None:
    manifest = manifest_dict()
    root = write_package(tmp_path, manifest)
    tampered = dict(manifest, warmup_invocations=[9])
    (root / "manifest.json").write_bytes((json.dumps(tampered)).encode())
    report = verify_manifest(root)
    assert report.ok is False
    assert _findings(report) == [("INVALID", "V-B1", "$.manifest_digest")]
    assert "computed" in report.manifest_findings[0].reason


def test_explicit_digest_overrides_sidecar(tmp_path: Path) -> None:
    manifest = manifest_dict()
    digest = record_digest("manifest", manifest)
    root = write_package(tmp_path, manifest, sidecar="00" * 32 + "\n")
    assert verify_manifest(root, manifest_digest=digest).ok is True


def test_missing_sidecar_without_explicit(tmp_path: Path) -> None:
    report = verify_manifest(write_package(tmp_path, manifest_dict(), sidecar=None))
    assert report.ok is False
    assert [(f.severity, f.rule) for f in report.manifest_findings] == [("INCOMPLETE", "V-B1")]


@pytest.mark.parametrize("content", ["not-hex\n", "\n", "ab" * 31 + "\n", b"\xff\xfe"])
def test_malformed_sidecar(tmp_path: Path, content: str | bytes) -> None:
    report = verify_manifest(write_package(tmp_path, manifest_dict(), sidecar=content))
    assert report.ok is False
    assert [(f.severity, f.rule) for f in report.manifest_findings] == [("INVALID", "V-B1")]


def test_sidecar_non_regular(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_bytes((json.dumps(manifest_dict()) + "\n").encode())
    (tmp_path / "manifest.sha256").mkdir()
    report = verify_manifest(tmp_path)
    assert report.ok is False
    assert [(f.severity, f.rule) for f in report.manifest_findings] == [("INVALID", "V-P3")]


def test_manifest_file_problems(tmp_path: Path) -> None:
    missing = verify_manifest(tmp_path)
    assert missing.ok is False
    assert missing.manifest is None and missing.entries == ()
    assert missing.manifest_findings[0].severity == "INCOMPLETE"
    corrupt = verify_manifest(write_package(tmp_path, raw_manifest=b"{oops", sidecar=None))
    assert [(f.severity, f.rule) for f in corrupt.manifest_findings] == [("INVALID", "V-B1")]
    listed = verify_manifest(write_package(tmp_path, raw_manifest=b"[1,2]", sidecar=None))
    assert [(f.severity, f.rule) for f in listed.manifest_findings] == [("INVALID", "V-B6")]
    (tmp_path / "manifest.json").unlink()
    (tmp_path / "manifest.json").mkdir()
    (tmp_path / "manifest.sha256").write_text("ab" * 32)
    directory = verify_manifest(tmp_path)
    assert [(f.severity, f.rule) for f in directory.manifest_findings] == [("INVALID", "V-P3")]


def test_root_and_digest_misuse(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="package root"):
        verify_manifest(tmp_path / "missing")
    target = tmp_path / "file.txt"
    target.write_text("x")
    with pytest.raises(ValueError, match="package root"):
        verify_manifest(target)
    with pytest.raises(ValueError, match="SHA-256 hex"):
        verify_manifest(tmp_path, manifest_digest="zz")
    bad_root: Any = os.fsencode(tmp_path)
    with pytest.raises(ValueError, match="byte paths"):
        verify_manifest(bad_root)
