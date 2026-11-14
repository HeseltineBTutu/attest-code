"""F3 adversarial cases: aliasing, escapes, specials, substitution."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest
from f3_fixtures import UUID_C, UUID_D, to_bytes, valid_attempt
from f3_package import evidence_entry, manifest_dict, record_entry, write_package

from attest_core.f3_manifest import verify_manifest


def _record_package(root: Path) -> None:
    record = valid_attempt()
    entry = record_entry(record, "r.json")
    write_package(root, manifest_dict(records=[entry]), {"r.json": to_bytes(record)})


def test_duplicate_relpath_skips_resolution(tmp_path: Path) -> None:
    first = evidence_entry(UUID_C, "same.bin", b"data")
    second = evidence_entry(UUID_C, "same.bin", b"data")
    manifest = manifest_dict(evidence=[first, second])
    root = write_package(tmp_path, manifest, {})
    first_result, second_result = verify_manifest(root).entries
    assert [f.rule for f in first_result.findings] == ["V-P4"]
    assert [f.rule for f in second_result.findings] == ["V-P4"]
    assert first_result.severity == "INVALID"


def test_duplicate_relpath_cross_list(tmp_path: Path) -> None:
    record = valid_attempt()
    record_side = record_entry(record, "shared.bin")
    evidence_side = evidence_entry(UUID_C, "shared.bin", b"data")
    manifest = manifest_dict(records=[record_side], evidence=[evidence_side])
    root = write_package(tmp_path, manifest, {"shared.bin": to_bytes(record)})
    record_result, evidence_result = verify_manifest(root).entries
    assert record_result.findings[0].rule == "V-P4"
    assert evidence_result.findings[0].rule == "V-P4"
    assert "records[0]" in evidence_result.findings[0].reason


def test_hardlink_alias_invalid_despite_matching_bytes(tmp_path: Path) -> None:
    data = b"shared-content"
    os.link(tmp_path / "placeholder", tmp_path / "placeholder") if False else None
    (tmp_path / "a.bin").write_bytes(data)
    os.link(tmp_path / "a.bin", tmp_path / "b.bin")
    first = evidence_entry(UUID_C, "a.bin", data)
    second = evidence_entry("44444444-4444-4444-b444-444444444444", "b.bin", data)
    manifest = manifest_dict(evidence=[first, second])
    report = verify_manifest(write_package(tmp_path, manifest, {}))
    assert [e.severity for e in report.entries] == ["INVALID", "INVALID"]
    assert [f.rule for f in report.entries[0].findings] == ["V-P5"]
    assert "evidence[1]" in report.entries[0].findings[0].reason
    assert [f.rule for f in report.entries[1].findings] == ["V-P5"]
    assert "evidence[0]" in report.entries[1].findings[0].reason


def test_distinct_files_no_alias(tmp_path: Path) -> None:
    first = evidence_entry(UUID_C, "a.bin", b"same-bytes")
    second = evidence_entry("44444444-4444-4444-b444-444444444444", "b.bin", b"same-bytes")
    manifest = manifest_dict(evidence=[first, second])
    root = write_package(tmp_path, manifest, {"a.bin": b"same-bytes", "b.bin": b"same-bytes"})
    assert verify_manifest(root).ok is True


def test_in_root_symlinks_resolve(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f.bin").write_bytes(b"data")
    (tmp_path / "real" / "g.bin").write_bytes(b"data")
    os.symlink("real", tmp_path / "linkdir")
    os.symlink("real/f.bin", tmp_path / "alias.bin")
    first = evidence_entry(UUID_C, "alias.bin", b"data")
    second = evidence_entry(UUID_D, "linkdir/g.bin", b"data")
    manifest = manifest_dict(evidence=[first, second])
    report = verify_manifest(write_package(tmp_path, manifest, {}))
    assert [e.severity for e in report.entries] == ["VALID", "VALID"]


def test_escape_never_reads_outside(tmp_path: Path) -> None:
    os.symlink(__file__, tmp_path / "evasion")
    entry = evidence_entry(UUID_C, "evasion", b"data")
    report = verify_manifest(write_package(tmp_path, manifest_dict(evidence=[entry]), {}))
    (result,) = report.entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-P2")


def test_escape_to_missing_is_invalid_not_gap(tmp_path: Path) -> None:
    os.symlink("/definitely-absent-xyz-123/f.bin", tmp_path / "evasion")
    entry = evidence_entry(UUID_C, "evasion", b"data")
    report = verify_manifest(write_package(tmp_path, manifest_dict(evidence=[entry]), {}))
    (result,) = report.entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-P2")


def test_dangling_and_loop_are_gaps(tmp_path: Path) -> None:
    os.symlink("gone.bin", tmp_path / "dangling")
    os.symlink("loop-b", tmp_path / "loop-a")
    os.symlink("loop-a", tmp_path / "loop-b")
    first = evidence_entry(UUID_C, "dangling", b"data")
    second = evidence_entry(UUID_D, "loop-a", b"data")
    manifest = manifest_dict(evidence=[first, second])
    report = verify_manifest(write_package(tmp_path, manifest, {}))
    assert [(e.severity, e.findings[0].rule) for e in report.entries] == [
        ("INCOMPLETE", "V-B1"),
        ("INCOMPLETE", "V-B1"),
    ]


def test_special_files_rejected(tmp_path: Path) -> None:
    (tmp_path / "subdir").mkdir()
    os.mkfifo(tmp_path / "pipe")
    entries = [
        evidence_entry(UUID_C, "subdir", b"data"),
        evidence_entry(UUID_D, "pipe", b"data"),
    ]
    manifest = manifest_dict(evidence=entries)
    report = verify_manifest(write_package(tmp_path, manifest, {}))
    assert [(e.severity, e.findings[0].rule) for e in report.entries] == [("INVALID", "V-P3")] * 2


def test_socket_file_rejected(tmp_path: Path) -> None:
    try:
        sock = socket.socket(socket.AF_UNIX)
    except PermissionError:
        pytest.skip("sandbox forbids socket creation")
    try:
        sock.bind(str(tmp_path / "sock"))
    finally:
        sock.close()
    entry = evidence_entry(UUID_C, "sock", b"data")
    manifest = manifest_dict(evidence=[entry])
    report = verify_manifest(write_package(tmp_path, manifest, {}))
    assert [(e.severity, e.findings[0].rule) for e in report.entries] == [("INVALID", "V-P3")]


def test_absolute_entry_path_invalid(tmp_path: Path) -> None:
    entry = evidence_entry(UUID_C, "/etc/hostname", b"data")
    report = verify_manifest(write_package(tmp_path, manifest_dict(evidence=[entry]), {}))
    (result,) = report.entries
    assert (result.severity, result.findings[0].rule) == ("INVALID", "V-P1")


def test_substitution_across_runs_detected(tmp_path: Path) -> None:
    _record_package(tmp_path)
    assert verify_manifest(tmp_path).ok is True
    (tmp_path / "r.json").write_bytes(b'{"record_kind": "attempt"}')
    report = verify_manifest(tmp_path)
    assert report.ok is False
    assert report.entries[0].severity == "INVALID"


def test_double_resolution_deterministic(tmp_path: Path) -> None:
    _record_package(tmp_path)
    first = verify_manifest(tmp_path)
    second = verify_manifest(tmp_path)
    assert first == second
    assert first.ok is True


def test_tampered_manifest_keeps_entry_results(tmp_path: Path) -> None:
    record = valid_attempt()
    entry = record_entry(record, "r.json")
    manifest = manifest_dict(records=[entry], warmup_invocations=[])
    root = write_package(tmp_path, manifest, {"r.json": to_bytes(record)})
    tampered = dict(manifest, warmup_invocations=[7])
    (root / "manifest.json").write_bytes((json.dumps(tampered) + "\n").encode())
    report = verify_manifest(root)
    assert report.ok is False
    assert [(f.severity, f.rule) for f in report.manifest_findings] == [("INVALID", "V-B1")]
    assert report.entries[0].severity == "VALID"
