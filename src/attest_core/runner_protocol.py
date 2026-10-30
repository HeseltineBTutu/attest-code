"""Parent/runner wire protocol: version contract for contained launches.

The parent (live tree) spawns the runner from the F7 snapshot (HEAD
bytes), so the two sides can differ while work is uncommitted. Every
runner advertises ``RUNNER_PROTOCOL_VERSION`` in its source; the parent
AST-parses that marker (never imports the snapshot) and spawns only on
an exact match. Unknown, legacy, and newer versions all refuse safely
before any child runs. v1 is the pre-seccomp ``[src, fd, stage, scope?]``
shape; v2 adds the trailing seccomp flag.
"""

from __future__ import annotations

import ast
from pathlib import Path

RUNNER_PROTOCOL_VERSION = 2
"""Wire version this parent speaks; the snapshot runner must match exactly."""

_MARKER = "RUNNER_PROTOCOL_VERSION"
"""Module-level integer constant every runner source must define."""


def snapshot_protocol(snapshot_root: Path) -> int:
    """Read the snapshot runner's advertised protocol version (0 if unknown).

    Static parse only: missing files, syntax errors, and non-integer
    markers all yield 0, which never matches a real version.
    """
    runner = snapshot_root / "src" / "attest_core" / "contained_runner.py"
    try:
        tree = ast.parse(runner.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError, RecursionError):
        return 0
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id != _MARKER:
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, int):
            return value.value
    return 0


def is_supported(version: int) -> bool:
    """Whether this parent can speak a snapshot runner's protocol version."""
    return version == RUNNER_PROTOCOL_VERSION
