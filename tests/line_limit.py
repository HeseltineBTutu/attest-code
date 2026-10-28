"""First-party Python 200-physical-line enforcement (deterministic).

Fails when any in-scope ``*.py`` file exceeds MAX_LINES physical lines;
blank lines and comments count. Discovery is a sorted filesystem walk
that ignores git state entirely, so untracked and newly created files
are never silently skipped.

Included: every ``*.py`` file under the repository root.
Excluded directories (by name, at any depth): virtual environments,
tool caches, build outputs, and git metadata (see EXCLUDED_DIR_NAMES
and EGG_INFO_SUFFIX). ``.agents/`` is intentionally included: skill
helpers are first-party code when they exist.

Pre-existing violations are recorded in BASELINE as
``{relative-posix-path: lines-at-baseline}``. A baselined file passes
only while it does not grow; growth, new violations, and stale
entries (now compliant or removed) all fail, so the baseline can only
shrink. Each entry must be removed by a separately scoped refactor.

Usage: ``uv run python tests/line_limit.py`` (exit 1 on violations).
The pytest suite enforces the same check via test_line_limit.py.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_LINES = 200
"""Inclusive maximum physical lines per Python file."""

EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".versche",
        "__pycache__",
        "build",
        "dist",
    }
)
"""Directory names never descended into (virtualenvs, caches, outputs)."""

EGG_INFO_SUFFIX = ".egg-info"
"""Directory-name suffix marking build artifacts (also excluded)."""

BASELINE: dict[str, int] = {
    # Pre-existing violations (15); remove an entry only via a scoped
    # refactor that brings the file to 200 lines or fewer. Entries are
    # sorted by path; counts were observed, never negotiated.
    "src/apps/verify.py": 222,
    "src/attest_core/envelope.py": 226,
    "src/attest_core/origin.py": 231,
    "src/attest_core/sandbox.py": 223,
    "src/attest_core/snapshot.py": 311,
    "src/integrations/meta_models/client.py": 232,
    "src/integrations/meta_models/protocol.py": 245,
    "tests/test_cli/test_snapshot_cli.py": 378,
    "tests/test_cli/test_verify_cli.py": 339,
    "tests/test_src/test_attest_core/test_evidence.py": 220,
    "tests/test_src/test_attest_core/test_git.py": 288,
    "tests/test_src/test_attest_core/test_runtime.py": 220,
    "tests/test_src/test_attest_core/test_sandbox.py": 428,
    "tests/test_src/test_attest_core/test_snapshot.py": 378,
    "tests/test_src/test_integrations/test_meta_models.py": 624,
}
"""Grandfathered over-limit files; growth or staleness fails the check."""


@dataclass(frozen=True)
class Violation:
    """One over-limit file: relative POSIX path and observed line count."""

    path: str
    lines: int


def repo_root() -> Path:
    """Repository root derived from this file's location (CWD-independent)."""
    return Path(__file__).resolve().parent.parent


def _excluded(dirname: str) -> bool:
    return dirname in EXCLUDED_DIR_NAMES or dirname.endswith(EGG_INFO_SUFFIX)


def iter_python_files(root: Path) -> list[str]:
    """Sorted relative POSIX paths of in-scope ``*.py`` files."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if not _excluded(name))
        for name in sorted(filenames):
            if name.endswith(".py"):
                found.append((Path(dirpath) / name).relative_to(root).as_posix())
    return sorted(found)


def count_lines(path: Path) -> int:
    """Physical lines: newline count plus a trailing unterminated fragment."""
    data = path.read_bytes()
    if not data:
        return 0
    newlines = data.count(b"\n")
    return newlines if data.endswith(b"\n") else newlines + 1


def check_tree(
    root: Path, baseline: dict[str, int] | None = None
) -> tuple[list[Violation], list[str]]:
    """Return (violations, stale_baseline_entries), each sorted by path.

    A file over MAX_LINES fails unless baselined at an equal-or-higher
    count. A baseline entry fails as stale when its file is now at or
    below MAX_LINES or no longer exists.
    """
    allowed = BASELINE if baseline is None else baseline
    violations: list[Violation] = []
    seen: dict[str, int] = {}
    for rel in iter_python_files(root):
        lines = count_lines(root / rel)
        seen[rel] = lines
        if lines > MAX_LINES and (rel not in allowed or lines > allowed[rel]):
            violations.append(Violation(rel, lines))
    stale = sorted(path for path in allowed if seen.get(path, 0) <= MAX_LINES)
    return violations, stale


def format_report(violations: list[Violation], stale: list[str]) -> str:
    """Human-readable failure detail naming every path, count, and maximum."""
    details = [f"{item.path}: {item.lines} lines (max {MAX_LINES})" for item in violations]
    details.extend(f"{path}: stale baseline entry (remove it)" for path in stale)
    return "\n".join(details)


def main(argv: list[str] | None = None) -> int:
    """Run the check against an optional root (default: repository root)."""
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(args[0]).resolve() if args else repo_root()
    violations, stale = check_tree(root)
    if not violations and not stale:
        if BASELINE:
            print(
                f"line limit OK: no new violations ({len(BASELINE)} grandfathered entries remain)"
            )
        else:
            print(f"line limit OK: all Python files at or below {MAX_LINES} lines")
        return 0
    print(format_report(violations, stale))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
