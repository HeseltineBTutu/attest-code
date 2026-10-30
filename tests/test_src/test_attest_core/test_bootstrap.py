"""Bootstrap/import-boundary battery: live-checkout target code never runs.

Proves the contained runner's bootstrap pins first-party imports to the
approved snapshot: a poisoned package on the interpreter path is never
imported, preloaded target modules are evicted before use, site
initialization is disabled, and incomplete snapshots fail closed.
Poison tests invoke the real launcher bootstrap string directly.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from attest_core.bounds import run_bounded
from attest_core.contain import _BOOTSTRAP, run_contained
from attest_core.ns_setup import supports_containment
from attest_core.pidns_probes import probe_module_origins
from attest_core.sandbox import SandboxWorkdir
from attest_spec import AttemptOutcome

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="user+mount+PID+network namespaces unavailable"
)

_POISON_INIT = (
    "from pathlib import Path\n"
    "import os\n"
    "Path(os.environ['POISON_MARKER_DIR']).joinpath('poison-imported').write_text('live')\n"
)
_POISON_RUNNER = (
    "from pathlib import Path\n"
    "import os\n"
    "def main(argv):\n"
    "    Path(os.environ['POISON_MARKER_DIR']).joinpath('poison-main').write_text('live')\n"
    "    return 9\n"
)


@pytest.fixture()
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("bootstrap-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


@pytest.fixture()
def poison_live_src(tmp_path: Path) -> Path:
    """Fake live checkout: importing it proves the boundary failed."""
    package = tmp_path / "fake-live" / "attest_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(_POISON_INIT, encoding="utf-8")
    (package / "contained_runner.py").write_text(_POISON_RUNNER, encoding="utf-8")
    return tmp_path / "fake-live"


@pytest.fixture()
def broken_snapshot(tmp_path: Path) -> Path:
    root = tmp_path / "broken-snap"
    (root / "src").mkdir(parents=True)
    return root


@pytest.fixture()
def nospec_snapshot(src_tree: Path, tmp_path: Path) -> Path:
    """Valid snapshot with attest_spec removed (no fallback allowed)."""
    root = tmp_path / "nospec-snap"
    shutil.copytree(src_tree, root)
    shutil.rmtree(root / "src" / "attest_spec")
    return root


@pytest.fixture()
def marker_dir(tmp_path: Path) -> Path:
    path = tmp_path / "markers"
    path.mkdir()
    return path


def _run_bootstrap(
    poison: Path, snapshot_src: Path, tmp_path: Path, markers: Path, *, preload: bool
) -> subprocess.CompletedProcess[str]:
    """Invoke the real bootstrap with poison first on the path."""
    preamble = f"import sys; sys.path.insert(0, {str(poison)!r}); "
    if preload:
        preamble += "import attest_core.contained_runner; "
    argv = [
        sys.executable,
        "-I",
        "-S",
        "-c",
        preamble + _BOOTSTRAP,
        str(snapshot_src),
        "999",
        str(tmp_path),
    ]
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,
        env={"LC_ALL": "C.UTF-8", "POISON_MARKER_DIR": str(markers)},
    )


def test_poisoned_path_never_imported(
    poison_live_src: Path, broken_snapshot: Path, tmp_path: Path, marker_dir: Path
) -> None:
    completed = _run_bootstrap(
        poison_live_src, broken_snapshot / "src", tmp_path, marker_dir, preload=False
    )
    assert completed.returncode == 2
    assert "snapshot incomplete" in completed.stderr
    assert not (marker_dir / "poison-imported").exists()
    assert not (marker_dir / "poison-main").exists()


def test_preloaded_target_evicted(
    poison_live_src: Path, broken_snapshot: Path, tmp_path: Path, marker_dir: Path
) -> None:
    completed = _run_bootstrap(
        poison_live_src, broken_snapshot / "src", tmp_path, marker_dir, preload=True
    )
    assert completed.returncode == 2
    assert (marker_dir / "poison-imported").exists()
    assert not (marker_dir / "poison-main").exists()


def test_snapshot_wins_over_poisoned_path(
    poison_live_src: Path, src_tree: Path, tmp_path: Path, marker_dir: Path
) -> None:
    completed = _run_bootstrap(
        poison_live_src, src_tree / "src", tmp_path, marker_dir, preload=False
    )
    assert completed.returncode == 2
    assert "received no payload" in completed.stderr
    assert not (marker_dir / "poison-imported").exists()
    assert not (marker_dir / "poison-main").exists()


def test_site_initialization_disabled() -> None:
    argv = [sys.executable, "-I", "-S", "-c", "import sys; print('site' in sys.modules)"]
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0
    assert completed.stdout.strip() == "False"


def test_launcher_disables_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def _fake_popen(argv: list[str], **kwargs: object) -> object:
        seen.append(list(argv))
        raise RuntimeError("stop-before-spawn")

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    snap = tmp_path / "snap"
    (snap / "src" / "attest_core").mkdir(parents=True)
    paths = SandboxWorkdir(
        root=tmp_path,
        result=tmp_path / "result.json",
        stdout=tmp_path / "stdout.log",
        stderr=tmp_path / "stderr.log",
        pycache=tmp_path / "pycache",
        pgid=tmp_path / "pgid",
    )
    with pytest.raises(RuntimeError, match="stop-before-spawn"):
        run_contained(payload=b"{}", snapshot_root=snap, paths=paths)
    (recorded,) = seen
    assert recorded[:4] == [sys.executable, "-I", "-S", "-c"]
    assert recorded[4] == _BOOTSTRAP


@NEEDS_CONTAINMENT
def test_snapshot_modules_load_from_snapshot(src_tree: Path) -> None:
    report = run_bounded(probe_module_origins, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    origins = report.detail.removeprefix("origins:").split(",")
    assert len(origins) == 2
    assert all(origin.startswith("/snapshot/") for origin in origins)


@NEEDS_CONTAINMENT
def test_missing_snapshot_module_fails_closed(nospec_snapshot: Path) -> None:
    report = run_bounded(probe_module_origins, 30.0, snapshot_root=nospec_snapshot, contained=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "exited 3" in report.detail
    assert "contained child failed" in report.detail
    assert "attest_spec" in report.detail
