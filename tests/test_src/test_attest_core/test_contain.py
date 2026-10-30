"""M1 filesystem-isolation battery: adversarial probes, real boundary.

Each test runs a verifier-owned probe from ``attest_core.contain_probes``
inside user+mount namespaces via ``run_bounded(..., contained=True)``
and asserts the operating system denied the hostile action. Probes
report ``denied:``/``ALLOWED:`` markers; secret contents never appear
in details, captures, or evidence. Tests use a copy of the live source
tree as the snapshot root (snapshot integrity itself is F7's tested
domain); tests requiring namespaces skip explicitly where unsupported.
"""

from __future__ import annotations

import functools
import os
import shutil
import stat
from pathlib import Path

import pytest

from attest_core.bounds import run_bounded
from attest_core.contain_probes import (
    probe_big_detail,
    probe_environ,
    probe_escape_write,
    probe_exec_scratch,
    probe_python_version,
    probe_scratch_fill,
    probe_secret_read,
    probe_snapshot_write,
)
from attest_core.ns_setup import supports_containment
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome
from examples.admin_authorization import run_target_attempt

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="M1 user+mount namespaces unavailable"
)

_NS_ENV_DETAIL = "env:ATTEST_CONTAINED,HOME,LC_ALL,PATH,PYTHONPYCACHEPREFIX,TMPDIR"


@pytest.fixture(scope="session")
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("m1-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


@pytest.fixture()
def secret0600(tmp_path: Path) -> Path:
    """Operator-only fixture with a random token (not a real secret)."""
    path = tmp_path / "operator-only.txt"
    token = f"token-{os.urandom(8).hex()}"
    path.write_text(token + "\n", encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def test_supports_containment_is_stable() -> None:
    first, second = supports_containment(), supports_containment()
    assert isinstance(first, bool) and first == second


@NEEDS_CONTAINMENT
def test_contained_quick_relay(src_tree: Path) -> None:
    report = run_bounded(probe_python_version, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail.startswith("python:")


@NEEDS_CONTAINMENT
def test_snapshot_write_denied(src_tree: Path) -> None:
    report = run_bounded(probe_snapshot_write, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "denied:snapshot-write"


@NEEDS_CONTAINMENT
def test_escape_write_denied_and_fixture_identical(src_tree: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    target.write_bytes(b"untouched")
    probe = functools.partial(probe_escape_write, str(target))
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "denied:escape-write:outside.txt"
    assert target.read_bytes() == b"untouched"


@NEEDS_CONTAINMENT
def test_secret_read_denied(src_tree: Path, secret0600: Path) -> None:
    probe = functools.partial(probe_secret_read, str(secret0600))
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "denied:secret-read:operator-only.txt"
    token = secret0600.read_text(encoding="utf-8").strip()
    assert token not in report.detail


@NEEDS_CONTAINMENT
def test_repo_dotenv_denied_without_reading(src_tree: Path) -> None:
    dotenv = Path(__file__).resolve().parents[3] / ".env"
    if not dotenv.is_file():
        pytest.skip("no repository .env on this machine")
    probe = functools.partial(probe_secret_read, str(dotenv))
    report = run_bounded(probe, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "denied:secret-read:.env"


@NEEDS_CONTAINMENT
def test_scratch_overflow_denied(src_tree: Path) -> None:
    report = run_bounded(probe_scratch_fill, 60.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "denied:scratch-overflow"


@NEEDS_CONTAINMENT
def test_scratch_noexec(src_tree: Path) -> None:
    report = run_bounded(probe_exec_scratch, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "denied:scratch-exec"


@NEEDS_CONTAINMENT
def test_environ_exactly_minimal(src_tree: Path) -> None:
    report = run_bounded(probe_environ, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == _NS_ENV_DETAIL


@NEEDS_CONTAINMENT
def test_oversize_detail_rejected(src_tree: Path) -> None:
    report = run_bounded(probe_big_detail, 30.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "invalid" in report.detail


def test_contained_without_snapshot_is_infra() -> None:
    report = run_bounded(probe_python_version, 30.0, snapshot_root=None, contained=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "contained" in report.detail


def _legacy_quick() -> AttemptReport:
    return AttemptReport(AttemptOutcome.PASS, (), "legacy")


def test_legacy_path_unchanged() -> None:
    report = run_bounded(_legacy_quick, 30.0)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "legacy"


@NEEDS_CONTAINMENT
def test_real_checks_contained(src_tree: Path) -> None:
    probe = functools.partial(run_target_attempt, "repaired", ("/admin/users", "/admin/settings"))
    report = run_bounded(probe, 120.0, snapshot_root=src_tree, contained=True)
    assert report.outcome == AttemptOutcome.PASS
