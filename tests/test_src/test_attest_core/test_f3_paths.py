"""F3 path confinement: shape, containment, and safe reads (V-P1–V-P6)."""

from __future__ import annotations

import os
import socket
import stat
from pathlib import Path
from typing import Any

import pytest

from attest_core.f3_errors import F3Error, F3IncompleteError
from attest_core.f3_paths import (
    ConfinedBytes,
    check_shape,
    open_root,
    read_confined_file,
    resolve_within_root,
)

LOC = "$.relpath"


@pytest.mark.parametrize(
    "value", ["a.json", "sub/dir/f.json", "a.b-c_d", "a0/x-9_8.z", "a\nb", "x" * 5000]
)
def test_shape_accepts(value: str) -> None:
    assert check_shape(value, "8.5", LOC) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/abs",
        "/",
        "C:/x",
        "C:foo",
        "d:bar",
        "\\\\unc\\x",
        "~",
        "~/x",
        "~user/x",
        "mid~dle",
        "a\\b",
        "a//b",
        "a/./b",
        ".",
        "..",
        "a/../b",
        "../x",
        "a/",
        "a\x00b",
    ],
)
def test_shape_rejects(value: str) -> None:
    with pytest.raises(F3Error) as caught:
        check_shape(value, "8.5", LOC)
    assert caught.value.rule == "V-P1"
    assert caught.value.location == LOC


@pytest.mark.parametrize("value", [7, None, True, ["a"]])
def test_shape_rejects_non_string(value: Any) -> None:
    with pytest.raises(F3Error) as caught:
        check_shape(value, "8.5", LOC)
    assert caught.value.rule == "V-B6"


def test_open_root(tmp_path: Path) -> None:
    fd = open_root(tmp_path)
    try:
        assert stat.S_ISDIR(os.fstat(fd).st_mode)
    finally:
        os.close(fd)
    with pytest.raises(ValueError, match="package root"):
        open_root(tmp_path / "missing")
    target = tmp_path / "file.txt"
    target.write_text("x")
    with pytest.raises(ValueError, match="package root"):
        open_root(target)


def _write(root: Path, name: str, data: bytes = b"payload") -> None:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def test_containment(tmp_path: Path) -> None:
    root = str(tmp_path.resolve())
    _write(tmp_path, "a/b.json")
    assert resolve_within_root(root, "a/b.json").endswith("b.json")
    os.symlink("a", tmp_path / "linkdir")
    resolved = resolve_within_root(root, "linkdir/b.json")
    assert resolved == os.path.join(root, "a", "b.json")
    for evil in ("../escape", "a/../../escape", "/etc/hostname"):
        with pytest.raises(F3Error) as caught:
            resolve_within_root(root, evil)
        assert caught.value.rule == "V-P1"
    outside = os.path.realpath(__file__)
    assert not outside.startswith(root + os.sep)
    os.symlink(outside, tmp_path / "evasion")
    with pytest.raises(F3Error) as caught:
        resolve_within_root(root, "evasion")
    assert caught.value.rule == "V-P2"


def test_escape_beats_missing(tmp_path: Path) -> None:
    """Escape to a nonexistent path is INVALID (order proof), not a gap."""
    root = str(tmp_path.resolve())
    os.symlink("/definitely-absent-xyz-123/f.bin", tmp_path / "evasion")
    with pytest.raises(F3Error) as caught:
        resolve_within_root(root, "evasion")
    assert caught.value.rule == "V-P2"


def _read(root: Path, relpath: str) -> ConfinedBytes:
    fd = open_root(root)
    try:
        return read_confined_file(fd, str(root.resolve()), relpath, "8.5", LOC)
    finally:
        os.close(fd)


def test_read_regular_and_symlink(tmp_path: Path) -> None:
    _write(tmp_path, "f.bin", b"\x00\x01binary")
    got = _read(tmp_path, "f.bin")
    assert got.data == b"\x00\x01binary"
    assert (got.dev, got.ino) != (0, 0)
    os.symlink("f.bin", tmp_path / "alias")
    assert _read(tmp_path, "alias").data == b"\x00\x01binary"


def test_read_missing_and_dangling(tmp_path: Path) -> None:
    with pytest.raises(F3IncompleteError):
        _read(tmp_path, "absent.json")
    os.symlink("gone.json", tmp_path / "dangling")
    with pytest.raises(F3IncompleteError) as caught:
        _read(tmp_path, "dangling")
    assert "dangling" in caught.value.reason


def test_read_loop_is_gap_not_hang(tmp_path: Path) -> None:
    os.symlink("loop-b", tmp_path / "loop-a")
    os.symlink("loop-a", tmp_path / "loop-b")
    with pytest.raises(F3IncompleteError):
        _read(tmp_path, "loop-a")


def test_read_rejects_non_regular(tmp_path: Path) -> None:
    (tmp_path / "subdir").mkdir()
    with pytest.raises(F3Error) as caught:
        _read(tmp_path, "subdir")
    assert caught.value.rule == "V-P3"
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(F3Error) as caught:
        _read(tmp_path, "pipe")
    assert caught.value.rule == "V-P3"
    try:
        sock = socket.socket(socket.AF_UNIX)
    except PermissionError:
        pytest.skip("sandbox forbids socket creation")
    try:
        sock.bind(str(tmp_path / "sock"))
    finally:
        sock.close()
    with pytest.raises(F3Error) as caught:
        _read(tmp_path, "sock")
    assert caught.value.rule == "V-P3"
