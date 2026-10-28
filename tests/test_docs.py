"""Executable documentation policy, enforced in the normal suite.

Executable (stdlib ``doctest``, no new dependency): ``src/**/*.py``
docstrings with ``>>>`` run via module import (deterministic only: no
network, secrets, or side effects); Markdown `````python`` fences in
``README.md``/``docs/*.md`` with ``>>>`` run self-contained.
Illustrative (never executed): ``sh``/plain/other fences — the README
shell blocks mutate the environment — and YAML, whose validity the
suite covers by loading the real invariant files. A `````python``
fence without ``>>>``, an unclosed fence, or ``>>>`` in a ``tests/``
docstring fails loudly. Nothing is silently skipped.
"""

from __future__ import annotations

import ast
import contextlib
import doctest
import importlib
import io
from dataclasses import dataclass
from pathlib import Path

import pytest
from line_limit import iter_python_files, repo_root


def _doc_files() -> list[Path]:
    """README plus every Markdown file under docs/ (globbed, never pinned)."""
    root = repo_root()
    return [root / "README.md", *sorted((root / "docs").glob("*.md"))]


@dataclass(frozen=True)
class Fence:
    """One fenced block: info tag, 1-based opening line, and body text."""

    language: str
    lineno: int
    body: str


def _fenced_blocks(text: str) -> list[Fence]:
    """Parse ``` fences; an unclosed fence raises with its opening line."""
    blocks: list[Fence] = []
    language = ""
    start = 0
    body: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            if start == 0:
                language, start = stripped[3:].strip(), lineno
            else:
                blocks.append(Fence(language, start, "\n".join(body) + "\n"))
                language, start, body = "", 0, []
        elif start > 0:
            body.append(line)
    if start > 0:
        raise ValueError(f"unclosed fence opened at line {start}")
    return blocks


def _run_doctest(source: str, name: str) -> None:
    """Execute >>> examples; any failure raises naming the example."""
    test = doctest.DocTestParser().get_doctest(source, {}, name, name, 0)
    if test.examples:
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            failed, _ = doctest.DocTestRunner(verbose=False).run(test)
        if failed:
            raise AssertionError(f"doctest failed in {name}:\n{captured.getvalue()}")


def _check_markdown_file(path: Path) -> None:
    """Enforce the fence policy and execute ```python examples."""
    try:
        blocks = _fenced_blocks(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise AssertionError(f"{path}: {exc}") from exc
    for block in blocks:
        if block.language != "python":
            continue
        label = f"{path}:{block.lineno}"
        if ">>>" not in block.body:
            raise AssertionError(
                f"{label}: python fence without >>> — add an example "
                "or retag it illustrative (e.g. text)"
            )
        _run_doctest(block.body, label)


def _docstring_has_doctest(path: Path) -> bool:
    """True when any real docstring (not a fixture string) holds >>>."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    if (doc := ast.get_docstring(tree)) is not None and ">>>" in doc:
        return True
    return any(
        (doc := ast.get_docstring(node)) is not None and ">>>" in doc
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )


def _check_module_doctests(module_name: str) -> None:
    """Import a src module and fail loudly on any doctest failure."""
    module = importlib.import_module(module_name)
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        results = doctest.testmod(module, verbose=False)
    if results.failed:
        raise AssertionError(f"doctest failed in {module_name}:\n{captured.getvalue()}")


def _dotted_name(rel: str) -> str:
    """Map src/a/b.py to a.b (packages resolve through src/ on sys.path)."""
    parts = Path(rel).with_suffix("").parts[1:]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def test_markdown_python_fences_are_executed() -> None:
    for path in _doc_files():
        _check_markdown_file(path)


def test_src_docstring_examples_are_executed() -> None:
    root = repo_root()
    for rel in iter_python_files(root):
        if not rel.startswith("src/"):
            continue
        if _docstring_has_doctest(root / rel):
            _check_module_doctests(_dotted_name(rel))


def test_tests_docstrings_hold_no_doctests() -> None:
    root = repo_root()
    # This policy module is exempt: its own specification prose necessarily
    # names the marker. Real examples still belong in src/ or Markdown.
    offenders = [
        rel
        for rel in iter_python_files(root)
        if rel.startswith("tests/")
        and rel != "tests/test_docs.py"
        and _docstring_has_doctest(root / rel)
    ]
    assert not offenders, f"move >>> examples to src/ or Markdown: {offenders}"


def test_fence_parser(tmp_path: Path) -> None:
    sample = "# T\n```python\n>>> 1 + 1\n2\n```\ntext\n```sh\nuv run x\n```\n```\ndiagram\n```\n"
    blocks = _fenced_blocks(sample)
    assert [(b.language, b.lineno) for b in blocks] == [("python", 2), ("sh", 7), ("", 10)]
    assert ">>> 1 + 1" in blocks[0].body
    with pytest.raises(ValueError, match="unclosed fence"):
        _fenced_blocks("```python\n>>> 1\n")


def test_python_fence_without_prompt_is_rejected(tmp_path: Path) -> None:
    page = tmp_path / "page.md"
    page.write_text("```python\nx = 1\n```\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="without >>>"):
        _check_markdown_file(page)
    page.write_text("```python\n>>> 1 + 1\n2\n```\n", encoding="utf-8")
    _check_markdown_file(page)


def test_doctest_failure_is_reported_not_skipped() -> None:
    _run_doctest(">>> 1 + 1\n2\n", "passing-fixture")
    with pytest.raises(AssertionError, match="doctest failed in failing-fixture"):
        _run_doctest(">>> 1 + 1\n3\n", "failing-fixture")


def test_module_doctest_failure_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ok_mod.py").write_text('""">>> 1 + 1\n2\n"""\n', encoding="utf-8")
    (tmp_path / "bad_mod.py").write_text('""">>> 1 + 1\n3\n"""\n', encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    _check_module_doctests("ok_mod")
    with pytest.raises(AssertionError, match="doctest failed in bad_mod"):
        _check_module_doctests("bad_mod")
