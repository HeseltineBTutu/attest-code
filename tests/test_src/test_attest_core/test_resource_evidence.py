"""Resource evidence: counters, unavailable markers, run_bounded wiring."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from attest_core import scopes
from attest_core.bounds import run_bounded
from attest_core.ns_setup import supports_containment
from attest_core.pidns_probes import probe_pid
from attest_core.resource_evidence import collect_resources, with_resources
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="user+mount+PID+network namespaces unavailable"
)

_EVENTS = {"oom": 1, "oom_kill": 2, "pids_max": 3, "throttled_usec": 4000}


@pytest.fixture(scope="session")
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("rsc-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def test_no_scope_no_annotation() -> None:
    assert collect_resources(None) == ""


def test_gone_scope_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scopes, "find_scope", lambda unit: None)
    assert collect_resources("u.scope") == "[resources] unavailable(scope-gone-before-collection)"


def test_counters_format_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scopes, "find_scope", lambda unit: "/sys/x.scope")
    monkeypatch.setattr(scopes, "read_scope_events", lambda path: dict(_EVENTS))
    assert collect_resources("u.scope") == (
        "[resources] oom=1 oom_kill=2 pids_max=3 throttled_usec=4000"
    )


def test_read_failure_clips_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scopes, "find_scope", lambda unit: "/sys/x.scope")

    def _raise(path: str) -> Any:
        raise scopes.ScopeError("x" * 500)

    monkeypatch.setattr(scopes, "read_scope_events", _raise)
    marker = collect_resources("u.scope")
    assert marker.startswith("[resources] unavailable(xxx")
    assert len(marker) < 200


def test_distinct_scopes_stay_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, dict[str, int]] = {
        "a.scope": dict(_EVENTS),
        "b.scope": {"oom": 9, "oom_kill": 9, "pids_max": 9, "throttled_usec": 9},
    }
    monkeypatch.setattr(scopes, "find_scope", lambda unit: f"/sys/{unit}")
    monkeypatch.setattr(scopes, "read_scope_events", lambda path: seen[path.rsplit("/", 1)[1]])
    first = collect_resources("a.scope")
    assert first == collect_resources("a.scope")
    assert first != collect_resources("b.scope")


def test_with_resources_keeps_detail_verbatim() -> None:
    report = AttemptReport(AttemptOutcome.PASS, (), "ok")
    assert with_resources(report, "") is report
    attached = with_resources(report, "[resources] oom=0")
    assert attached.outcome == AttemptOutcome.PASS
    assert attached.detail == "ok"
    assert attached.resources == "[resources] oom=0"


@NEEDS_CONTAINMENT
def test_production_tamper_detected_with_counters(
    src_tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Filesystem-level limit tamper fails a real run_bounded quota attempt."""
    scope = tmp_path / "attest-scope-tampered.scope"
    scope.mkdir()
    (scope / "memory.max").write_text("999\n", encoding="ascii")
    (scope / "pids.max").write_text("64\n", encoding="ascii")
    (scope / "cpu.max").write_text("200000 100000\n", encoding="ascii")
    (scope / "memory.events").write_text("oom_kill 7\n", encoding="ascii")
    (scope / "pids.events").write_text("max 0\n", encoding="ascii")
    (scope / "cpu.stat").write_text("throttled_usec 11\n", encoding="ascii")
    seen = [str(scope), str(scope), None, None]
    monkeypatch.setattr(scopes, "supports_quotas", lambda: True)
    monkeypatch.setattr(scopes, "launch_env", lambda: {"XDG_RUNTIME_DIR": "/x"})
    monkeypatch.setattr(scopes, "find_scope", lambda unit: seen.pop(0))
    report = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "memory.max" in report.detail
    assert "oom_kill=" not in report.detail
    assert "oom_kill=7" in report.resources


@NEEDS_CONTAINMENT
def test_counters_stay_with_their_attempt(src_tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two quota attempts each report their own scope's counters."""
    first = {"oom": 1, "oom_kill": 1, "pids_max": 1, "throttled_usec": 111}
    second = {"oom": 2, "oom_kill": 2, "pids_max": 2, "throttled_usec": 222}
    reads = [first, second]
    monkeypatch.setattr(scopes, "supports_quotas", lambda: True)
    monkeypatch.setattr(scopes, "launch_env", lambda: {"XDG_RUNTIME_DIR": "/x"})
    monkeypatch.setattr(scopes, "find_scope", lambda unit: "/sys/x.scope")
    monkeypatch.setattr(scopes, "read_scope_events", lambda path: reads.pop(0))
    monkeypatch.setattr(scopes, "terminate_scope_by_unit", lambda unit, limits: None)
    one = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    two = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert "throttled_usec=111" in one.resources
    assert "throttled_usec=222" in two.resources
    assert "throttled_usec=222" not in one.resources
    assert "throttled_usec=" not in one.detail
    assert "throttled_usec=" not in two.detail


@NEEDS_CONTAINMENT
def test_quota_failure_carries_unavailable_not_failed(
    src_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scopes, "supports_quotas", lambda: True)
    monkeypatch.setattr(scopes, "launch_env", lambda: {"XDG_RUNTIME_DIR": "/x"})
    report = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "[resources]" not in report.detail
    assert "[resources] unavailable(" in report.resources


@NEEDS_CONTAINMENT
def test_collected_counters_annotate_failed_result(
    src_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mocked counters reach resources even when placement refusal fails closed."""
    monkeypatch.setattr(scopes, "supports_quotas", lambda: True)
    monkeypatch.setattr(scopes, "launch_env", lambda: {"XDG_RUNTIME_DIR": "/x"})
    monkeypatch.setattr(scopes, "scope_argv", lambda limits, unit, cmd: cmd)
    monkeypatch.setattr(scopes, "find_scope", lambda unit: "/sys/x.scope")
    monkeypatch.setattr(scopes, "read_scope_events", lambda path: dict(_EVENTS))
    monkeypatch.setattr(scopes, "terminate_scope_by_unit", lambda unit, limits: None)
    report = run_bounded(probe_pid, 30.0, snapshot_root=src_tree, contained=True, quotas=True)
    assert report.outcome == AttemptOutcome.INFRA_FAILURE
    assert "throttled_usec=" not in report.detail
    assert "throttled_usec=4000" in report.resources
