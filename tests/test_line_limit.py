"""Focused tests for the 200-physical-line enforcement check."""

from __future__ import annotations

from pathlib import Path

from line_limit import MAX_LINES, check_tree, count_lines, format_report, repo_root


def _write_lines(root: Path, rel: str, lines: list[str]) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(lines), encoding="utf-8")
    return path


def _code(total: int) -> list[str]:
    return ["x = 1\n"] * total


def test_exactly_200_lines_passes(tmp_path: Path) -> None:
    _write_lines(tmp_path, "ok.py", _code(200))
    assert check_tree(tmp_path, baseline={}) == ([], [])


def test_201_lines_fails(tmp_path: Path) -> None:
    _write_lines(tmp_path, "big.py", _code(201))
    violations, stale = check_tree(tmp_path, baseline={})
    assert stale == []
    assert [(item.path, item.lines) for item in violations] == [("big.py", 201)]
    report = format_report(violations, stale)
    assert "big.py" in report and "201" in report and str(MAX_LINES) in report


def test_blank_lines_and_comments_count(tmp_path: Path) -> None:
    mixed = ["# comment\n"] * 100 + ["\n"] * 99 + ["x = 1\n"] * 2
    _write_lines(tmp_path, "mixed.py", mixed)
    violations, _ = check_tree(tmp_path, baseline={})
    assert [(item.path, item.lines) for item in violations] == [("mixed.py", 201)]
    _write_lines(tmp_path, "mixed.py", mixed[:-1])
    assert check_tree(tmp_path, baseline={}) == ([], [])


def test_count_lines_edge_cases(tmp_path: Path) -> None:
    empty = tmp_path / "empty.py"
    empty.write_text("", encoding="utf-8")
    assert count_lines(empty) == 0
    bare = tmp_path / "bare.py"
    bare.write_text("a\nb", encoding="utf-8")
    assert count_lines(bare) == 2


def test_violations_sorted_deterministically(tmp_path: Path) -> None:
    for name in ("zebra.py", "apple.py", "middle.py"):
        _write_lines(tmp_path, name, _code(201))
    first = check_tree(tmp_path, baseline={})
    second = check_tree(tmp_path, baseline={})
    assert [item.path for item in first[0]] == ["apple.py", "middle.py", "zebra.py"]
    assert format_report(*first) == format_report(*second)


def test_new_nested_files_detected(tmp_path: Path) -> None:
    _write_lines(tmp_path, "pkg/sub/added.py", _code(250))
    violations, _ = check_tree(tmp_path, baseline={})
    assert [(item.path, item.lines) for item in violations] == [("pkg/sub/added.py", 250)]


def test_exclusions(tmp_path: Path) -> None:
    excluded = [
        ".venv/lib/huge.py",
        ".versche/lib/huge.py",
        "__pycache__/huge.py",
        ".pytest_cache/huge.py",
        ".mypy_cache/huge.py",
        ".ruff_cache/huge.py",
        ".git/objects/huge.py",
        "build/lib/huge.py",
        "dist/huge.py",
        "pkg.egg-info/huge.py",
        "src/nested/__pycache__/huge.py",
    ]
    for rel in excluded:
        _write_lines(tmp_path, rel, _code(500))
    _write_lines(tmp_path, "notes.txt", ["text\n"] * 500)
    assert check_tree(tmp_path, baseline={}) == ([], [])
    _write_lines(tmp_path, "build.py", _code(201))
    violations, _ = check_tree(tmp_path, baseline={})
    assert [item.path for item in violations] == ["build.py"]


def test_baseline_freezes_but_never_masks(tmp_path: Path) -> None:
    frozen = tmp_path / "frozen"
    grown = tmp_path / "grown"
    shrunk = tmp_path / "shrunk"
    masked = tmp_path / "masked"
    _write_lines(frozen, "old.py", _code(210))
    assert check_tree(frozen, baseline={"old.py": 210}) == ([], [])
    _write_lines(grown, "old.py", _code(211))
    grown_violations, _ = check_tree(grown, baseline={"old.py": 210})
    assert [(item.path, item.lines) for item in grown_violations] == [("old.py", 211)]
    _write_lines(shrunk, "old.py", _code(200))
    _, shrunk_stale = check_tree(shrunk, baseline={"old.py": 210})
    assert shrunk_stale == ["old.py"]
    _write_lines(masked, "old.py", _code(200))
    _write_lines(masked, "new.py", _code(201))
    masked_violations, masked_stale = check_tree(masked, baseline={"old.py": 210})
    assert [item.path for item in masked_violations] == ["new.py"]
    assert masked_stale == ["old.py"]


def test_repo_has_no_new_violations_or_stale_entries() -> None:
    """Enforcement gate: any growth, new violation, or stale entry fails.

    A pass means no *new* violations — BASELINE still records the
    pre-existing over-limit files, each awaiting a scoped refactor.
    """
    violations, stale = check_tree(repo_root())
    assert (violations, stale) == ([], []), format_report(violations, stale)
