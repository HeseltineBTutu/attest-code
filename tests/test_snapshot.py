"""Execution snapshots: object-sourced bytes, manifest identity, re-verification."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from attest_core.bounds import run_bounded
from attest_core.invariants import approval_digest, create_approval, load_definitions
from attest_core.origin import EXPECTED_PACKAGES, prepare_worker_sys_path
from attest_core.snapshot import Snapshot, SnapshotError, build_snapshot, verify_snapshot
from attest_core.verification import AttemptReport
from attest_spec import ApprovalRecord, AttemptOutcome, Invariant


def _invariant(staged: Any) -> Invariant:
    definitions = load_definitions(staged.invariant)
    assert len(definitions) == 1
    return definitions[0]


def _approval(invariant: Invariant) -> ApprovalRecord:
    return create_approval(
        invariant,
        approver="snapshot-test-operator",
        approved_at="2026-10-28T00:00:00Z",
        method="test-operator-fixture",
    )


def _build(staged: Any, invariant: Invariant | None = None) -> Snapshot:
    resolved = invariant if invariant is not None else _invariant(staged)
    return build_snapshot(
        repo=staged.root,
        head="HEAD",
        invariant=resolved,
        approval=_approval(resolved),
        invariant_path=staged.invariant,
    )


def _commit(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_build_is_deterministic(staged_repo: Any) -> None:
    first = _build(staged_repo)
    second = _build(staged_repo)
    assert first.digest == second.digest
    assert first.files == second.files
    assert first.root != second.root


def test_build_covers_exact_scope(staged_repo: Any) -> None:
    snapshot = _build(staged_repo)
    paths = [path for path, _ in snapshot.files]
    assert paths == sorted(paths)
    assert paths
    assert all(path.startswith("src/") for path in paths)
    tops = {path.split("/")[1] for path in paths}
    assert tops == set(EXPECTED_PACKAGES)
    assert snapshot.manifest["snapshot_policy"] == "attest-snapshot-v1"
    assert len(snapshot.digest) == 64


def test_verify_accepts_fresh_build(staged_repo: Any) -> None:
    verify_snapshot(_build(staged_repo))


def _writable(path: Path) -> Path:
    os.chmod(path, 0o644)
    return path


def test_verify_detects_modified_file(staged_repo: Any) -> None:
    snapshot = _build(staged_repo)
    target = _writable(snapshot.root / "src" / "apps" / "demo_api.py")
    target.write_bytes(target.read_bytes() + b"# tampered\n")
    with pytest.raises(SnapshotError, match="integrity check failed"):
        verify_snapshot(snapshot)


def test_verify_detects_deleted_file(staged_repo: Any) -> None:
    snapshot = _build(staged_repo)
    (snapshot.root / "src" / "apps" / "demo_api.py").unlink()
    with pytest.raises(SnapshotError, match="integrity check failed"):
        verify_snapshot(snapshot)


def test_verify_detects_extra_file(staged_repo: Any) -> None:
    snapshot = _build(staged_repo)
    (snapshot.root / "src" / "apps" / "extra.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(SnapshotError, match="integrity check failed"):
        verify_snapshot(snapshot)


def test_tracked_symlink_is_rejected(staged_repo: Any) -> None:
    link = staged_repo.src / "examples" / "linkmod.py"
    link.symlink_to(staged_repo.root / "invariants" / "auth-admin-001.yaml")
    _commit(staged_repo.root, "add", "-A")
    _commit(staged_repo.root, "commit", "-qm", "tracked symlink")
    with pytest.raises(SnapshotError, match="symlink.*rejected"):
        _build(staged_repo)


def test_submodule_is_rejected(staged_repo: Any, tmp_path: Path) -> None:
    sub = tmp_path / "subsrc"
    sub.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(sub)], check=True)
    (sub / "mod.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(sub), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(sub),
            "-c",
            "user.email=t@e.c",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "sub",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(staged_repo.root),
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "-q",
            "add",
            str(sub),
            "src/subrepo",
        ],
        check=True,
    )
    _commit(staged_repo.root, "commit", "-qm", "submodule")
    with pytest.raises(SnapshotError, match="submodule.*rejected"):
        _build(staged_repo)


def test_stray_top_level_entry_is_rejected(staged_repo: Any) -> None:
    (staged_repo.src / "stray.py").write_text("x = 1\n", encoding="utf-8")
    _commit(staged_repo.root, "add", "-A")
    _commit(staged_repo.root, "commit", "-qm", "stray module")
    with pytest.raises(SnapshotError, match="must be exactly"):
        _build(staged_repo)


def test_stdlib_shadow_is_rejected(staged_repo: Any) -> None:
    (staged_repo.src / "base64.py").write_text("HOSTILE = True\n", encoding="utf-8")
    _commit(staged_repo.root, "add", "-A")
    _commit(staged_repo.root, "commit", "-qm", "stdlib shadow")
    with pytest.raises(SnapshotError, match="must be exactly"):
        _build(staged_repo)


def test_missing_init_is_rejected(staged_repo: Any) -> None:
    _commit(staged_repo.root, "rm", "-q", "src/apps/__init__.py")
    _commit(staged_repo.root, "commit", "-qm", "drop init")
    with pytest.raises(SnapshotError, match="__init__.py"):
        _build(staged_repo)


def test_tracked_pyc_is_rejected(staged_repo: Any) -> None:
    cached = staged_repo.src / "apps" / "__pycache__" / "demo_api.pyc"
    cached.parent.mkdir(exist_ok=True)
    cached.write_bytes(b"fake bytecode")
    subprocess.run(
        ["git", "-C", str(staged_repo.root), "add", "-f", str(cached)],
        check=True,
        capture_output=True,
    )
    _commit(staged_repo.root, "commit", "-qm", "tracked pyc")
    with pytest.raises(SnapshotError, match="importable artifact.*rejected"):
        _build(staged_repo)


def test_export_attributes_do_not_change_snapshot_bytes(staged_repo: Any) -> None:
    target = staged_repo.src / "apps" / "demo_api.py"
    original = target.read_bytes()
    target.write_bytes(original + b"\nX = '$Format:%H$'\n")
    (staged_repo.root / ".gitattributes").write_text(
        "src/apps/demo_api.py export-subst\n", encoding="utf-8"
    )
    _commit(staged_repo.root, "add", "-A")
    _commit(staged_repo.root, "commit", "-qm", "export subst")
    snapshot = _build(staged_repo)
    exported = (snapshot.root / "src" / "apps" / "demo_api.py").read_bytes()
    assert exported == target.read_bytes()
    assert b"$Format" in exported


def test_different_invariant_different_digest(staged_repo: Any) -> None:
    baseline = _build(staged_repo)
    (staged_repo.root / "other.yaml").write_text(
        "- id: AUTH-ADMIN-001\n  version: 1\n  title: changed\n"
        "  requirement: different bytes\n  scope:\n    - /admin/users\n",
        encoding="utf-8",
    )
    other = load_definitions(staged_repo.root / "other.yaml")[0]
    changed = build_snapshot(
        repo=staged_repo.root,
        head="HEAD",
        invariant=other,
        approval=_approval(other),
        invariant_path=staged_repo.root / "other.yaml",
    )
    assert changed.digest != baseline.digest
    assert changed.manifest["invariant_source"] == "worktree"
    assert baseline.manifest["invariant_source"] == "head"


def test_live_dirt_does_not_change_digest(staged_repo: Any) -> None:
    baseline = _build(staged_repo)
    target = staged_repo.src / "apps" / "demo_api.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"# live dirt\n")
        assert _build(staged_repo).digest == baseline.digest
    finally:
        target.write_bytes(original)


def test_config_absent_and_tracked(staged_repo: Any) -> None:
    first = _build(staged_repo)
    assert first.manifest["config"]["pyproject.toml"] == "absent"
    assert first.manifest["config"]["uv.lock"] == "absent"
    body = b'[project]\nname = "attest"\n'
    (staged_repo.root / "pyproject.toml").write_bytes(body)
    _commit(staged_repo.root, "add", "pyproject.toml")
    _commit(staged_repo.root, "commit", "-qm", "manifest")
    second = _build(staged_repo)
    assert second.manifest["config"]["pyproject.toml"] == hashlib.sha256(body).hexdigest()
    assert second.digest != first.digest


def test_approval_digest_deterministic(staged_repo: Any) -> None:
    approval = _approval(_invariant(staged_repo))
    assert approval_digest(approval) == approval_digest(approval)
    assert len(approval_digest(approval)) == 64


def test_non_git_dir_refused(tmp_path: Path, auth_admin_invariant: Invariant) -> None:
    with pytest.raises(SnapshotError):
        build_snapshot(
            repo=tmp_path,
            head="HEAD",
            invariant=auth_admin_invariant,
            approval=_approval(auth_admin_invariant),
            invariant_path=tmp_path / "inv.yaml",
        )


def test_invariant_outside_root_refused(staged_repo: Any, tmp_path: Path) -> None:
    sibling = tmp_path.parent / f"{tmp_path.name}-sibling"
    sibling.mkdir(parents=True, exist_ok=True)
    outsider = sibling / "outside.yaml"
    outsider.write_text("[]\n", encoding="utf-8")
    with pytest.raises(SnapshotError, match="outside the repository tree"):
        build_snapshot(
            repo=staged_repo.root,
            head="HEAD",
            invariant=_invariant(staged_repo),
            approval=_approval(_invariant(staged_repo)),
            invariant_path=outsider,
        )


def test_mid_build_live_hammer_ignored(staged_repo: Any) -> None:
    baseline = _build(staged_repo)
    target = staged_repo.src / "apps" / "demo_api.py"
    original = target.read_bytes()
    stop = threading.Event()

    def hammer() -> None:
        counter = 0
        while not stop.is_set():
            target.write_bytes(original + f"# {counter}\n".encode())
            counter += 1

    worker = threading.Thread(target=hammer)
    worker.start()
    try:
        assert _build(staged_repo).digest == baseline.digest
    finally:
        stop.set()
        worker.join(timeout=30)
        target.write_bytes(original)


def _import_examples_marker() -> AttemptReport:
    import examples.admin_authorization  # noqa: F401

    return AttemptReport(AttemptOutcome.PASS, (), "imported")


def test_missing_package_fails_self_check(
    staged_repo: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _build(staged_repo)
    shutil.rmtree(snapshot.root / "src" / "examples")
    monkeypatch.setattr(sys, "path", list(sys.path))
    prepare_worker_sys_path(snapshot.root / "src", staged_repo.root)
    report = run_bounded(_import_examples_marker, 30.0, snapshot_root=snapshot.root)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "self-check" in report.detail


def test_missing_submodule_fails_import(staged_repo: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = _build(staged_repo)
    (snapshot.root / "src" / "examples" / "admin_authorization.py").unlink()
    monkeypatch.setattr(sys, "path", list(sys.path))
    prepare_worker_sys_path(snapshot.root / "src", staged_repo.root)
    report = run_bounded(_import_examples_marker, 30.0, snapshot_root=snapshot.root)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "ModuleNotFoundError" in report.detail


def test_prepare_worker_sys_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    live = tmp_path / "live"
    (live / "src").mkdir(parents=True)
    snap = tmp_path / "snap" / "src"
    snap.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setattr(
        sys, "path", ["", str(live / "src"), str(live), str(elsewhere), "/usr/lib/python"]
    )
    prepare_worker_sys_path(snap, live)
    assert sys.path[0] == str(snap)
    assert "" not in sys.path
    assert not any(entry.startswith(str(live)) for entry in sys.path)
    assert str(elsewhere) in sys.path


def test_prepare_worker_sys_path_keeps_in_repo_site_packages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """In-repo venv dependencies survive stripping; live project code does not.

    Without the dependency-directory exemption, an in-repository `.venv`
    loses its `site-packages` from worker `sys.path` and spawned workers
    fail third-party imports (`ModuleNotFoundError: yaml`).
    """
    live = tmp_path / "live"
    (live / "src").mkdir(parents=True)
    site_packages = live / ".venv" / "lib" / "python3.11" / "site-packages"
    site_packages.mkdir(parents=True)
    dist_packages = live / ".venv" / "lib" / "python3" / "dist-packages"
    dist_packages.mkdir(parents=True)
    snap = tmp_path / "snap" / "src"
    snap.mkdir(parents=True)
    monkeypatch.setattr(
        sys,
        "path",
        ["", str(live / "src"), str(live), str(site_packages), str(dist_packages)],
    )
    prepare_worker_sys_path(snap, live)
    assert sys.path[0] == str(snap)
    assert str(site_packages) in sys.path
    assert str(dist_packages) in sys.path
    assert str(live / "src") not in sys.path
    assert str(live) not in sys.path
    assert "" not in sys.path
