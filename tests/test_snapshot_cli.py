"""Snapshot and environment gates end to end: fresh-process refusal paths."""

from __future__ import annotations

import io
import json
import os
import py_compile
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from apps.review import run_review
from examples import admin_authorization as admin_checks


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


def _commit(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _verify(staged: Any, *extra: str, env: Any = None) -> subprocess.CompletedProcess[str]:
    proc: subprocess.CompletedProcess[str] = staged.run(
        "verify",
        str(staged.invariant),
        "--revision",
        "HEAD",
        "--repo",
        str(staged.root),
        "--approvals",
        str(staged.approvals),
        *extra,
        env=env,
    )
    return proc


def test_root_startup_module_is_refused_end_to_end(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.root / "sitecustomize.py").write_text("x = 1\n", encoding="utf-8")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "exists at the repository root" in proc.stderr


def test_dirty_lockfile_is_refused(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (staged_repo.root / "uv.lock").write_text("pinned\n", encoding="utf-8")
    _commit(staged_repo.root, "add", "pyproject.toml", "uv.lock")
    _commit(staged_repo.root, "commit", "-qm", "manifests")
    (staged_repo.root / "uv.lock").write_text("tampered\n", encoding="utf-8")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "uncommitted" in proc.stderr


def test_ignored_executable_is_refused_end_to_end(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.src / "stray.pyc").write_bytes(b"fake bytecode")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "ignored executable" in proc.stderr


def test_pythonhome_is_refused(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    proc = _verify(staged_repo, env={"PYTHONHOME": sys.base_prefix})
    assert proc.returncode == 3
    assert "PYTHONHOME" in proc.stderr


def test_pythonpath_escape_is_refused(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir(parents=True, exist_ok=True)
    proc = _verify(
        staged_repo,
        env={"PYTHONPATH": os.pathsep.join([str(staged_repo.src), str(outside)])},
    )
    assert proc.returncode == 3
    assert "escapes the repository tree" in proc.stderr


def test_clean_manifests_still_pass(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (staged_repo.root / "uv.lock").write_text("pinned\n", encoding="utf-8")
    _commit(staged_repo.root, "add", "pyproject.toml", "uv.lock")
    _commit(staged_repo.root, "commit", "-qm", "manifests")
    proc = _verify(staged_repo, "--target", "repaired")
    assert proc.returncode == 0, proc.stderr
    assert "verdict: PASSED" in proc.stdout


def _startup_import_active(tmp_path: Path, name: str) -> bool:
    """Probe whether a fresh `-c` interpreter autoimports `<name>.py` via PYTHONPATH."""
    probe_dir = tmp_path / f"startup-probe-{name}"
    probe_dir.mkdir(exist_ok=True)
    marker = probe_dir / "marker.txt"
    if marker.exists():
        marker.unlink()
    (probe_dir / f"{name}.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran\\n')\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(probe_dir)
    proc = subprocess.run(
        [sys.executable, "-c", "pass"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return proc.returncode == 0 and marker.exists()


@pytest.mark.parametrize("name", ["sitecustomize", "usercustomize"])
def test_root_startup_module_refused_before_worker_spawn(
    staged_repo: Any, tmp_path: Path, name: str
) -> None:
    if not _startup_import_active(tmp_path, name):
        pytest.skip(f"{name} autoimport is inactive on this interpreter")
    _approve(staged_repo.invariant, staged_repo.approvals)
    marker = tmp_path / f"{name}.marker.jsonl"
    (staged_repo.root / f"{name}.py").write_text(
        "import json, sys\n"
        f"with open({str(marker)!r}, 'a') as fh:\n"
        "    fh.write(json.dumps(sys.argv) + '\\n')\n",
        encoding="utf-8",
    )
    proc = _verify(
        staged_repo,
        env={"PYTHONPATH": os.pathsep.join([str(staged_repo.root), str(staged_repo.src)])},
    )
    assert proc.returncode == 3
    assert f"{name}.py exists at the repository root" in proc.stderr
    runs = [json.loads(line) for line in marker.read_text(encoding="utf-8").splitlines()]
    assert runs, "startup module never executed; mechanism probe disagreed with the run"
    for argv in runs:
        assert argv[1:2] == ["verify"], f"non-parent process executed startup code: {argv}"


def test_self_deleting_startup_module_is_refused(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    target = staged_repo.root / "sitecustomize.py"
    marker = tmp_path / "self-delete.marker.txt"
    target.write_text(
        f"import os\nopen({str(marker)!r}, 'w').write('ran\\n')\nos.unlink({str(target)!r})\n",
        encoding="utf-8",
    )
    proc = _verify(
        staged_repo,
        env={"PYTHONPATH": os.pathsep.join([str(staged_repo.root), str(staged_repo.src)])},
    )
    assert proc.returncode == 3
    assert "verdict" not in proc.stdout
    if marker.exists():
        assert not target.exists()
        assert "was already imported from the repository tree" in proc.stderr
    else:
        assert "exists at the repository root" in proc.stderr


def test_dangling_startup_symlink_is_refused(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.root / "sitecustomize.py").symlink_to(staged_repo.root / "no-such-target.py")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "exists at the repository root" in proc.stderr


def test_startup_preflight_precedes_origin_diagnostics(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.root / "sitecustomize.py").write_text("x = 1\n", encoding="utf-8")
    shadow = tmp_path / "shadow" / "examples"
    shadow.mkdir(parents=True)
    (shadow / "__init__.py").write_text("", encoding="utf-8")
    assert isinstance(admin_checks.__file__, str)
    shutil.copy(admin_checks.__file__, shadow / "admin_authorization.py")
    proc = _verify(
        staged_repo,
        env={"PYTHONPATH": os.pathsep.join([str(shadow.parent), str(staged_repo.src)])},
    )
    assert proc.returncode == 3
    assert "exists at the repository root" in proc.stderr
    assert "outside the repository tree" not in proc.stderr


def _plant_matching_pyc(source: Path) -> Path:
    """Write hostile bytecode whose header matches the clean source stats.

    A same-size `!=`/`==` flip in the demo guard inverts authorization while
    keeping the file size identical; the restored clean file keeps the
    hostile compile's mtime, so timestamp validation accepts the planted
    bytecode for the clean source.
    """
    tag = sys.implementation.cache_tag
    cached = source.parent / "__pycache__" / f"{source.stem}.{tag}.pyc"
    cached.parent.mkdir(exist_ok=True)
    original = source.read_bytes()
    hostile = original.replace(b'if principal != "admin":', b'if principal == "admin":')
    assert hostile != original and len(hostile) == len(original)
    fixed_time = 1700000000
    source.write_bytes(hostile)
    os.utime(source, (fixed_time, fixed_time))
    py_compile.compile(str(source), cfile=str(cached), doraise=True)
    source.write_bytes(original)
    os.utime(source, (fixed_time, fixed_time))
    return cached


def test_planted_bytecode_cache_does_not_poison_workers(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    _plant_matching_pyc(staged_repo.src / "apps" / "demo_api.py")
    proc = _verify(staged_repo, "--target", "repaired")
    assert proc.returncode == 0, proc.stderr
    assert "verdict: PASSED" in proc.stdout


def test_planted_bytecode_control_proves_poison(staged_repo: Any) -> None:
    _plant_matching_pyc(staged_repo.src / "apps" / "demo_api.py")
    code = (
        "from fastapi.testclient import TestClient;"
        "from apps.demo_api import ADMIN_TOKEN, create_repaired_app;"
        "client = TestClient(create_repaired_app());"
        "response = client.get("
        "'/admin/users', headers={'Authorization': f'Bearer {ADMIN_TOKEN}'});"
        "print(response.status_code)"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(staged_repo.src)
    env.pop("PYTHONPYCACHEPREFIX", None)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=staged_repo.root,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "403"


def test_tracked_symlink_refuses_snapshot_build(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    link = staged_repo.src / "examples" / "linkmod.py"
    link.symlink_to(staged_repo.invariant)
    _commit(staged_repo.root, "add", "-A")
    _commit(staged_repo.root, "commit", "-qm", "tracked symlink")
    proc = _verify(staged_repo, "--target", "repaired")
    assert proc.returncode == 3
    assert "symlink" in proc.stderr and "rejected" in proc.stderr


def test_submodule_refuses_snapshot_build(staged_repo: Any, tmp_path: Path) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
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
    proc = _verify(staged_repo, "--target", "repaired")
    assert proc.returncode == 3
    assert "submodule" in proc.stderr and "rejected" in proc.stderr


def test_stdlib_shadow_refuses_snapshot_build(staged_repo: Any) -> None:
    # sunau (never imported by the CLI chain) reaches the snapshot gate; an
    # eagerly-imported name like base64 would break the parent interpreter
    # before any gate runs (trusted-launch residual, documented).
    _approve(staged_repo.invariant, staged_repo.approvals)
    (staged_repo.src / "sunau.py").write_text("HOSTILE = True\n", encoding="utf-8")
    _commit(staged_repo.root, "add", "-A")
    _commit(staged_repo.root, "commit", "-qm", "stdlib shadow")
    proc = _verify(staged_repo, "--target", "repaired")
    assert proc.returncode == 3
    assert "must be exactly" in proc.stderr


def test_tracked_src_startup_module_is_refused(staged_repo: Any, tmp_path: Path) -> None:
    if not _startup_import_active(tmp_path, "sitecustomize"):
        pytest.skip("sitecustomize autoimport is inactive on this interpreter")
    _approve(staged_repo.invariant, staged_repo.approvals)
    marker = tmp_path / "src-startup.marker.jsonl"
    (staged_repo.src / "sitecustomize.py").write_text(
        "import json, sys\n"
        f"with open({str(marker)!r}, 'a') as fh:\n"
        "    fh.write(json.dumps(sys.argv) + '\\n')\n",
        encoding="utf-8",
    )
    _commit(staged_repo.root, "add", "-A")
    _commit(staged_repo.root, "commit", "-qm", "tracked src startup")
    proc = _verify(staged_repo)
    assert proc.returncode == 3
    assert "exists in the source tree" in proc.stderr
    runs = [json.loads(line) for line in marker.read_text(encoding="utf-8").splitlines()]
    assert runs, "startup module never executed; mechanism probe disagreed with the run"
    for argv in runs:
        assert argv[1:2] == ["verify"], f"non-parent process executed startup code: {argv}"


def test_config_digest_stable_across_runs(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    digests = set()
    for _ in range(2):
        proc = _verify(staged_repo, "--target", "repaired", "--format", "json")
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["verdict"] == "PASSED"
        digests.add(payload["config_digest"])
        outcomes = [attempt["outcome"] for attempt in payload["attempts"]]
        assert outcomes == ["PASS", "PASS", "PASS"]
    assert len(digests) == 1


def test_export_subst_repo_verifies_blob_bytes(staged_repo: Any) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    target = staged_repo.src / "apps" / "demo_api.py"
    target.write_bytes(target.read_bytes() + b"\nX = '$Format:%H$'\n")
    (staged_repo.root / ".gitattributes").write_text(
        "src/apps/demo_api.py export-subst\n", encoding="utf-8"
    )
    _commit(staged_repo.root, "add", "-A")
    _commit(staged_repo.root, "commit", "-qm", "export subst")
    proc = _verify(staged_repo, "--target", "repaired")
    assert proc.returncode == 0, proc.stderr
    assert "verdict: PASSED" in proc.stdout
