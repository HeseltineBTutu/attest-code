"""F3 staged input-file verification (V-B13(c))."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from f3_input_pkg import file_entry, stage, triples

from attest_core import f3_paths as paths
from attest_core.f3_input_files import verify_input_files

DATA = b"staged-input-bytes"


def _verify(tmp_path: Path, entries: list) -> tuple:
    root = str(tmp_path.resolve())
    fd = paths.open_root(root)
    try:
        return verify_input_files(fd, root, entries)
    finally:
        os.close(fd)


def test_valid_staged_file(tmp_path: Path) -> None:
    stage(tmp_path, {"inputs/data.bin": DATA})
    assert _verify(tmp_path, [file_entry("inputs/data.bin", DATA)]) == ()


def test_one_byte_substitution(tmp_path: Path) -> None:
    stage(tmp_path, {"inputs/data.bin": b"staged-input-bytex"})
    (finding,) = _verify(tmp_path, [file_entry("inputs/data.bin", DATA)])
    assert (finding.severity, finding.rule) == ("INVALID", "V-B13")
    assert finding.location == "$.entries[0].sha256"


def test_truncation(tmp_path: Path) -> None:
    stage(tmp_path, {"inputs/data.bin": DATA[:4]})
    kinds = triples(_verify(tmp_path, [file_entry("inputs/data.bin", DATA)]))
    assert ("INVALID", "V-B13", "$.entries[0].size_bytes") in kinds
    assert ("INVALID", "V-B13", "$.entries[0].sha256") in kinds


def test_missing_file(tmp_path: Path) -> None:
    (finding,) = _verify(tmp_path, [file_entry("inputs/gone.bin", DATA)])
    assert (finding.severity, finding.rule) == ("INCOMPLETE", "V-B13")
    assert finding.location == "$.entries[0]"
    assert "inputs/gone.bin" in finding.reason


def test_directory_rejected(tmp_path: Path) -> None:
    (tmp_path / "inputs").mkdir()
    (finding,) = _verify(tmp_path, [file_entry("inputs", DATA)])
    assert (finding.severity, finding.rule) == ("INVALID", "V-P3")


def test_absolute_and_traversal_rejected(tmp_path: Path) -> None:
    for bad_path in ("/etc/hostname", "../escape"):
        (finding,) = _verify(tmp_path, [file_entry(bad_path, DATA)])
        assert (finding.severity, finding.rule) == ("INVALID", "V-P1")


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    outside = os.path.realpath(__file__)
    os.symlink(outside, tmp_path / "evasion")
    (finding,) = _verify(tmp_path, [file_entry("evasion", DATA)])
    assert (finding.severity, finding.rule) == ("INVALID", "V-P2")


def test_symlink_inside_root_ok(tmp_path: Path) -> None:
    stage(tmp_path, {"inputs/real.bin": DATA})
    os.symlink("real.bin", tmp_path / "inputs" / "alias.bin")
    assert _verify(tmp_path, [file_entry("inputs/alias.bin", DATA)]) == ()


def test_dangling_symlink_incomplete(tmp_path: Path) -> None:
    os.symlink("nowhere.bin", tmp_path / "dangling")
    (finding,) = _verify(tmp_path, [file_entry("dangling", DATA)])
    assert (finding.severity, finding.rule) == ("INCOMPLETE", "V-B13")


def test_unreadable_file_incomplete(tmp_path: Path) -> None:
    target = tmp_path / "locked.bin"
    target.write_bytes(DATA)
    target.chmod(0o000)
    try:
        try:
            with open(target, "rb"):
                pass
        except OSError:
            pass
        else:
            pytest.skip("unreadable-file simulation unsupported (readable anyway)")
        (finding,) = _verify(tmp_path, [file_entry("locked.bin", DATA)])
        assert (finding.severity, finding.rule) == ("INCOMPLETE", "V-B13")
    finally:
        target.chmod(0o644)


def test_literals_need_no_file(tmp_path: Path) -> None:
    entries = [{"kind": "literal", "name": "seed", "value": "abc"}]
    assert _verify(tmp_path, entries) == ()


def test_shared_relpath_across_manifests_ok(tmp_path: Path) -> None:
    """V-P4/V-P5 do not span input manifests: sharing is expected."""
    stage(tmp_path, {"inputs/shared.bin": DATA})
    first = [file_entry("inputs/shared.bin", DATA)]
    second = [file_entry("inputs/shared.bin", DATA)]
    assert _verify(tmp_path, first) == ()
    assert _verify(tmp_path, second) == ()


def test_non_list_entries_rejected(tmp_path: Path) -> None:
    (finding,) = _verify(tmp_path, {"not": "a list"})  # type: ignore[arg-type]
    assert finding.rule == "V-B6"
