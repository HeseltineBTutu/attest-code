"""CLI --env-log: opt-in environment sidecar with verdict isolation."""

import io
import json
import shlex
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from apps.cli import main
from apps.review import run_review
from attest_core.bench_env import collect_environment


@pytest.fixture(autouse=True)
def _restore_sys_path() -> Iterator[None]:
    old = list(sys.path)
    yield
    sys.path[:] = old


def _approve(invariant: Path, approvals: Path) -> None:
    run_review(
        invariant_file=invariant,
        approvals_file=approvals,
        approver="ada",
        invariant_id=None,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )


def _args(staged_repo: Any, *extra: str) -> list[str]:
    base = ["verify", str(staged_repo.invariant), "--revision", "HEAD"]
    base += ["--repo", str(staged_repo.root), "--approvals", str(staged_repo.approvals)]
    return [*base, *extra]


def _stub_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apps.verify.verify_code_origin", lambda *args, **kwargs: None)


def test_env_collection_opt_in_and_args(
    staged_repo: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    _stub_origin(monkeypatch)
    calls: list[dict[str, Any]] = []

    def _fake(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"profile": kwargs["profile"]}

    monkeypatch.setattr("apps.cli.collect_environment", _fake)
    assert main(_args(staged_repo)) == 0
    assert calls == []
    argv = _args(staged_repo, "--exec", "hardened", "--env-log", str(tmp_path / "e.json"))
    main(argv)
    assert len(calls) == 1
    assert calls[0]["profile"] == "hardened"
    assert calls[0]["command"] == "attest " + shlex.join(argv)


def test_env_log_writes_json_and_preserves_stdout(
    staged_repo: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    _stub_origin(monkeypatch)
    assert main(_args(staged_repo)) == 0
    off = capsys.readouterr().out
    log = tmp_path / "env.json"
    assert main(_args(staged_repo, "--env-log", str(log))) == 0
    assert capsys.readouterr().out == off
    payload = json.loads(log.read_text(encoding="utf-8"))
    assert payload["profile"] == "standard"
    assert payload["command"].startswith("attest verify")
    expected = collect_environment(profile="standard", command="attest verify")
    assert set(payload) == set(expected)


def test_env_log_failures_keep_verdict(
    staged_repo: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    _stub_origin(monkeypatch)
    log = tmp_path / "env.json"
    log.write_text("sentinel\n", encoding="utf-8")
    assert main(_args(staged_repo, "--env-log", str(log))) == 0
    assert "env log failed" in capsys.readouterr().err
    assert log.read_text(encoding="utf-8") == "sentinel\n"
    missing = tmp_path / "nodir" / "env.json"
    assert main(_args(staged_repo, "--env-log", str(missing))) == 0
    assert "env log failed" in capsys.readouterr().err


def test_collection_failure_keeps_verdict(
    staged_repo: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    _stub_origin(monkeypatch)

    def _boom(**kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("injected")

    monkeypatch.setattr("apps.cli.collect_environment", _boom)
    argv = _args(staged_repo, "--env-log", str(tmp_path / "e.json"))
    assert main(argv) == 0
    assert "env log failed" in capsys.readouterr().err
    assert not (tmp_path / "e.json").exists()


def test_timing_and_env_coexist(
    staged_repo: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _approve(staged_repo.invariant, staged_repo.approvals)
    _stub_origin(monkeypatch)
    timing_log = tmp_path / "t.jsonl"
    env_log = tmp_path / "e.json"
    argv = _args(staged_repo, "--timing-log", str(timing_log), "--env-log", str(env_log))
    assert main(argv) == 0
    timing_lines = timing_log.read_text(encoding="utf-8").splitlines()
    assert len(timing_lines) == 4
    assert all("record_type" in json.loads(line) for line in timing_lines)
    env = json.loads(env_log.read_text(encoding="utf-8"))
    assert env["profile"] == "standard" and len(env) == 13
