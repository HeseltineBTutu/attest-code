"""Module-origin binding: unit checks plus subprocess mismatch refusal."""

from __future__ import annotations

import io
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

import apps
import examples.admin_authorization as admin_checks
from apps.review import run_review
from attest_core.origin import (
    EXPECTED_PACKAGES,
    OriginError,
    check_origins,
    parent_origins,
    probe_worker_origins,
    require_within_root,
    resolve_repo_root,
    verify_code_origin,
)


def _checkout_root() -> Path:
    assert isinstance(apps.__file__, str)
    return Path(apps.__file__).resolve().parents[2]


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


def test_expected_packages_are_covered() -> None:
    assert set(EXPECTED_PACKAGES) == {
        "attest_spec",
        "attest_core",
        "apps",
        "examples",
        "integrations",
    }


def test_loaded_tree_passes_parent_origins() -> None:
    checked = check_origins(parent_origins(), _checkout_root(), actor="test")
    assert set(checked) == set(EXPECTED_PACKAGES)


def test_worker_probe_matches_loaded_tree() -> None:
    checked = check_origins(probe_worker_origins(30.0), _checkout_root(), actor="test")
    assert set(checked) == set(EXPECTED_PACKAGES)


def test_other_checkout_is_refused(git_repo: Path) -> None:
    with pytest.raises(OriginError, match="outside the repository tree"):
        verify_code_origin(git_repo, 30.0)


def test_unresolvable_module_is_refused() -> None:
    origins = dict.fromkeys(EXPECTED_PACKAGES)
    with pytest.raises(OriginError, match="cannot resolve"):
        check_origins(origins, _checkout_root(), actor="test")


def test_outside_path_is_refused() -> None:
    origins = dict.fromkeys(EXPECTED_PACKAGES, "/elsewhere/src/apps/__init__.py")
    with pytest.raises(OriginError, match="outside the repository tree"):
        check_origins(origins, _checkout_root(), actor="test")


def test_resolve_repo_root_accepts_top_level(git_repo: Path) -> None:
    assert resolve_repo_root(git_repo) == git_repo.resolve()


def test_resolve_repo_root_rejects_subdirectory(git_repo: Path) -> None:
    subdir = git_repo / "src"
    subdir.mkdir()
    with pytest.raises(OriginError, match="not the repository root"):
        resolve_repo_root(subdir)


def test_resolve_repo_root_rejects_bad_paths(tmp_path: Path) -> None:
    with pytest.raises(OriginError, match="not a directory"):
        resolve_repo_root(tmp_path / "missing")
    plain_file = tmp_path / "file.txt"
    plain_file.write_text("x", encoding="utf-8")
    with pytest.raises(OriginError, match="not a directory"):
        resolve_repo_root(plain_file)
    with pytest.raises(OriginError):
        resolve_repo_root(tmp_path)


def test_require_within_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    inside = root / "sub" / "f.yaml"
    assert require_within_root(inside, root, "input") == inside.resolve()
    with pytest.raises(OriginError, match="outside the repository tree"):
        require_within_root(tmp_path / "outside.yaml", root, "input")
    with pytest.raises(OriginError, match="outside the repository tree"):
        require_within_root(root / "sub" / ".." / ".." / "escape.yaml", root, "input")


def test_probe_rejects_bad_timeout() -> None:
    with pytest.raises(ValueError, match="positive"):
        probe_worker_origins(0.0)


def test_another_checkout_is_refused_end_to_end(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = staged_repo.run(
        "verify",
        str(staged_repo.invariant),
        "--revision",
        "HEAD",
        "--repo",
        str(staged_repo.root),
        "--approvals",
        str(staged_repo.approvals),
        env={"PYTHONPATH": str(_checkout_root() / "src")},
    )
    assert proc.returncode == 3
    assert "outside the repository tree" in proc.stderr


def test_unrelated_install_location_is_refused(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    sitepkgs = tmp_path.parent / f"{tmp_path.name}-sitepkgs"
    shutil.copytree(staged_repo.src, sitepkgs, ignore=shutil.ignore_patterns("__pycache__"))
    proc = staged_repo.run(
        "verify",
        str(staged_repo.invariant),
        "--revision",
        "HEAD",
        "--repo",
        str(staged_repo.root),
        "--approvals",
        str(staged_repo.approvals),
        env={"PYTHONPATH": str(sitepkgs)},
    )
    assert proc.returncode == 3
    assert "outside the repository tree" in proc.stderr


def test_pythonpath_shadow_is_refused(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    shadow = tmp_path.parent / f"{tmp_path.name}-shadow" / "examples"
    shadow.mkdir(parents=True)
    (shadow / "__init__.py").write_text("", encoding="utf-8")
    assert isinstance(admin_checks.__file__, str)
    shutil.copy(admin_checks.__file__, shadow / "admin_authorization.py")
    proc = staged_repo.run(
        "verify",
        str(staged_repo.invariant),
        "--revision",
        "HEAD",
        "--repo",
        str(staged_repo.root),
        "--approvals",
        str(staged_repo.approvals),
        env={"PYTHONPATH": os.pathsep.join([str(shadow.parent), str(staged_repo.src)])},
    )
    assert proc.returncode == 3
    assert "examples" in proc.stderr and "outside the repository tree" in proc.stderr
