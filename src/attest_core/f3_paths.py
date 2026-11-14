"""F3 path confinement and safe evidence reads (V-P1–V-P6).

Every external path the validator reads passes shape checks,
containment resolution, kind verification, and a single
confined read. Violations raise F3Error carrying the V-P
rule; missing or unobtainable files raise F3IncompleteError
(a gap, never a contradiction). Linux/POSIX assumed.
"""

from __future__ import annotations

import dataclasses
import os
import stat
from pathlib import Path
from typing import Any

from attest_core.f3_errors import F3Error, F3IncompleteError, F3SchemaError

_OPEN_FLAGS = os.O_RDONLY | os.O_NONBLOCK
_READ_CHUNK = 1 << 20


@dataclasses.dataclass(frozen=True)
class ConfinedBytes:
    """Exact bytes read through one confined open, plus file identity."""

    data: bytes
    dev: int
    ino: int


def open_root(root: str | os.PathLike[str]) -> int:
    """Open a package root directory, returning a handle for anchored opens."""
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise ValueError(f"package root unusable: {root!r}: {exc}") from exc


def check_shape(relpath: Any, section: str = "8.5", location: str = "$") -> str:
    """V-P1 lexical shape: reject absolute, traversal, and malformed paths."""

    def bad(reason: str) -> F3Error:
        return F3Error(rule="V-P1", section=section, location=location, reason=reason)

    if not isinstance(relpath, str):
        raise F3SchemaError(
            rule="V-B6", section=section, location=location, reason="relpath must be a string"
        )
    if not relpath:
        raise bad("relpath must be non-empty")
    if "\x00" in relpath:
        raise bad("relpath must not contain NUL bytes")
    if relpath.startswith("\\\\"):
        raise bad("UNC paths rejected")
    if "\\" in relpath:
        raise bad("backslashes rejected (use '/' separators)")
    if "~" in relpath:
        raise bad("tilde paths rejected")
    if relpath.startswith("/"):
        raise bad("absolute paths rejected")
    if len(relpath) >= 2 and relpath[1] == ":" and relpath[0].isalpha() and relpath[0].isascii():
        raise bad("drive-qualified paths rejected")
    if relpath.endswith("/"):
        raise bad("trailing slashes rejected")
    segments = relpath.split("/")
    if any(not part for part in segments):
        raise bad("empty path segments rejected")
    if any(part in (".", "..") for part in segments):
        raise bad("dot and parent-traversal segments rejected")
    return relpath


def resolve_within_root(
    root_resolved: str, relpath: str, section: str = "8.5", location: str = "$"
) -> str:
    """V-P2: resolve all symlinks; the target MUST stay within the root."""
    check_shape(relpath, section, location)
    try:
        resolved = os.path.realpath(os.path.join(root_resolved, relpath))
    except (OSError, RuntimeError) as exc:
        raise F3IncompleteError(
            rule="V-B1", section=section, location=location, reason=f"path unresolvable: {exc}"
        ) from exc
    if not Path(resolved).is_relative_to(root_resolved):
        raise F3Error(
            rule="V-P2",
            section=section,
            location=location,
            reason=f"path escapes campaign root: {relpath!r}",
        )
    return resolved


def _describe_io_error(exc: OSError, relpath: str) -> str:
    """Human detail for an I/O failure (never a tampering claim)."""
    return f"{relpath!r}: unreadable ({exc})"


def read_confined_file(
    root_fd: int, root_resolved: str, relpath: str, section: str = "8.5", location: str = "$"
) -> ConfinedBytes:
    """V-P3/V-P6: lstat-kind gate, anchored open, identity check, one read.

    Opens relative to the root handle (V-P3, no root-swap race);
    O_NONBLOCK prevents FIFO/device blocking; fstat must confirm a
    regular file whose identity matches the pre-open lstat (swap
    detection). Reads all bytes exactly once.
    """
    check_shape(relpath, section, location)
    resolved = resolve_within_root(root_resolved, relpath, section, location)
    try:
        before = os.lstat(resolved)
    except OSError as exc:
        raise F3IncompleteError(
            rule="V-B1", section=section, location=location, reason=_describe_io_error(exc, relpath)
        ) from exc
    if stat.S_ISLNK(before.st_mode):
        raise F3IncompleteError(
            rule="V-B1",
            section=section,
            location=location,
            reason=f"dangling symlink (unresolvable target): {relpath!r}",
        )
    if not stat.S_ISREG(before.st_mode):
        raise F3Error(
            rule="V-P3",
            section=section,
            location=location,
            reason=f"not a regular file: {relpath!r}",
        )
    try:
        fd = os.open(relpath, _OPEN_FLAGS, dir_fd=root_fd)
    except OSError as exc:
        raise F3IncompleteError(
            rule="V-B1", section=section, location=location, reason=_describe_io_error(exc, relpath)
        ) from exc
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode):
            raise F3Error(
                rule="V-P3",
                section=section,
                location=location,
                reason=f"file kind changed during verification: {relpath!r}",
            )
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise F3Error(
                rule="V-P3",
                section=section,
                location=location,
                reason=f"file replaced during verification: {relpath!r}",
            )
        chunks: list[bytes] = []
        while True:
            try:
                chunk = os.read(fd, _READ_CHUNK)
            except OSError as exc:
                raise F3IncompleteError(
                    rule="V-B1",
                    section=section,
                    location=location,
                    reason=_describe_io_error(exc, relpath),
                ) from exc
            if not chunk:
                break
            chunks.append(chunk)
        return ConfinedBytes(data=b"".join(chunks), dev=after.st_dev, ino=after.st_ino)
    finally:
        os.close(fd)
