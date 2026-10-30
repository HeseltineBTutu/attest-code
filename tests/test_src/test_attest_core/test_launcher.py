"""Launcher battery: spawn descriptor lifecycle and interpreter identity.

Proves failed spawns release the result pipe (no descriptor leaks on
the Popen-raise or input-refusal paths) and that a first-party module
resolving from the interpreter environment instead of the snapshot is
rejected by the contained origin check without running checks.
"""

from __future__ import annotations

import os
import pickle
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from attest_core.contain import _BOOTSTRAP, ContainedError, run_contained
from attest_core.ns_setup import supports_containment
from attest_core.pidns_probes import probe_module_origins
from attest_core.sandbox import SandboxWorkdir

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="user+mount+PID+network namespaces unavailable"
)


def _workdir(root: Path) -> SandboxWorkdir:
    return SandboxWorkdir(
        root=root,
        result=root / "r",
        stdout=root / "o",
        stderr=root / "e",
        pycache=root / "c",
        pgid=root / "g",
    )


def test_spawn_failure_closes_result_pipe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_pipe = os.pipe
    created: list[tuple[int, int]] = []

    def _tracking_pipe() -> tuple[int, int]:
        created.append(real_pipe())
        return created[-1]

    def _assert_closed(fd: int) -> None:
        with pytest.raises(OSError):
            os.fstat(fd)

    def _boom_popen(*args: object, **kwargs: object) -> object:
        raise RuntimeError("stop-before-spawn")

    def _boom_write(data: bytes) -> int:
        raise BrokenPipeError("child gone")

    monkeypatch.setattr(os, "pipe", _tracking_pipe)
    snap = tmp_path / "snap"
    (snap / "src" / "attest_core").mkdir(parents=True)
    paths = _workdir(tmp_path)
    monkeypatch.setattr(subprocess, "Popen", _boom_popen)
    with pytest.raises(RuntimeError, match="stop-before-spawn"):
        run_contained(payload=b"{}", snapshot_root=snap, paths=paths)
    for fd in created[-1]:
        _assert_closed(fd)
    dead = SimpleNamespace(
        stdin=SimpleNamespace(write=_boom_write, close=lambda: None),
        stdout=SimpleNamespace(),
        stderr=SimpleNamespace(),
        wait=lambda: 0,
    )

    def _dead_popen(*args: object, **kwargs: object) -> object:
        return dead

    monkeypatch.setattr(subprocess, "Popen", _dead_popen)
    with pytest.raises(ContainedError, match="refused input"):
        run_contained(payload=b"{}", snapshot_root=snap, paths=paths)
    _assert_closed(created[-1][0])


@pytest.fixture()
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("launcher-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


@pytest.fixture()
def nospec_snapshot(src_tree: Path, tmp_path: Path) -> Path:
    """Valid snapshot with attest_spec removed (venv fallback resolves it)."""
    root = tmp_path / "nospec-snap"
    shutil.copytree(src_tree, root)
    shutil.rmtree(root / "src" / "attest_spec")
    return root


@pytest.fixture()
def staged_venv(tmp_path: Path) -> Path:
    """Interpreter tree: real third-party deps plus a benign attest_spec."""
    root = tmp_path / "staged-venv"
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    site = root / f"lib/python{version}/site-packages"
    site.mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    os.symlink(sys.executable, root / "bin" / "python")
    shutil.copyfile(Path(sys.prefix) / "pyvenv.cfg", root / "pyvenv.cfg")
    # Copy, never symlink: absolute links dangle once pivot detaches the host.
    real_site = Path(sys.prefix) / f"lib/python{version}/site-packages"
    for name in ("yaml", "_yaml"):
        shutil.copytree(real_site / name, site / name, ignore=shutil.ignore_patterns("__pycache__"))
    live_spec = Path(__file__).resolve().parents[3] / "src" / "attest_spec"
    shutil.copytree(live_spec, site / "attest_spec", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _run_runner(
    python: Path, snapshot_src: Path, stage: Path, payload: bytes
) -> tuple[int, bytes, bytes]:
    """Spawn the real bootstrap under one interpreter; return rc, result, stderr."""
    result_r, result_w = os.pipe()
    argv = [str(python), "-I", "-S", "-c", _BOOTSTRAP, str(snapshot_src), str(result_w), str(stage)]
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(result_w,),
        cwd=stage,
        env={"LC_ALL": "C.UTF-8"},
    )
    os.close(result_w)
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    try:
        _, err = proc.communicate(payload, timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    finally:
        chunks: list[bytes] = []
        while True:
            try:
                chunk = os.read(result_r, 65536)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        os.close(result_r)
    return proc.returncode, b"".join(chunks), err


@NEEDS_CONTAINMENT
def test_venv_fallback_rejected(nospec_snapshot: Path, staged_venv: Path, tmp_path: Path) -> None:
    python = staged_venv / "bin" / "python"
    ident = subprocess.run(
        [str(python), "-I", "-S", "-c", "import sys; print(sys.executable)"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert ident.returncode == 0
    assert ident.stdout.strip() == str(python)
    stage = tmp_path / "stage"
    stage.mkdir()
    payload = pickle.dumps(probe_module_origins)
    status, result, _ = _run_runner(python, nospec_snapshot / "src", stage, payload)
    assert status == 0
    assert b"origin self-check failed" in result
    assert b"origins:" not in result
