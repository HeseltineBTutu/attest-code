"""Runtime binding: env validation and deterministic runtime settings."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import pytest

from attest_core.evidence import canonical_bytes, sha256_hex
from attest_core.runtime import (
    RuntimeConfigError,
    check_environment,
    collect_runtime_settings,
)


def test_empty_environment_passes(tmp_path: Path) -> None:
    assert check_environment(tmp_path, {}) == ""


def test_pythonpath_within_root_passes_and_normalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    (root / "src").mkdir(parents=True)
    monkeypatch.chdir(root)
    assert check_environment(root, {"PYTHONPATH": "src"}) == str(root / "src")
    assert check_environment(root, {"PYTHONPATH": f"src{os.pathsep}."}) == (
        f"{root / 'src'}{os.pathsep}{root}"
    )


def test_pythonpath_outside_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(RuntimeConfigError, match="escapes the repository tree"):
        check_environment(root, {"PYTHONPATH": str(tmp_path / "elsewhere")})
    with pytest.raises(RuntimeConfigError, match="escapes the repository tree"):
        check_environment(root, {"PYTHONPATH": f"{root}{os.pathsep}/tmp"})


def test_pythonpath_dot_dot_escape_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    with pytest.raises(RuntimeConfigError, match="escapes the repository tree"):
        check_environment(root, {"PYTHONPATH": str(root / "sub" / ".." / ".." / "x")})


def test_empty_entry_resolves_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    trailing = f"{root}{os.pathsep}"
    monkeypatch.chdir(root)
    assert check_environment(root, {"PYTHONPATH": trailing}) == f"{root}{os.pathsep}{root}"
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeConfigError, match="escapes the repository tree"):
        check_environment(root, {"PYTHONPATH": trailing})


def test_pythonhome_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RuntimeConfigError, match="PYTHONHOME"):
        check_environment(tmp_path, {"PYTHONHOME": "/opt/other-python"})
    assert check_environment(tmp_path, {"PYTHONHOME": ""}) == ""


def test_collect_binds_expected_keys(tmp_path: Path) -> None:
    settings = collect_runtime_settings(tmp_path, {})
    assert settings["python.implementation"]
    assert re.fullmatch(r"\d+\.\d+\.\d+.*", settings["python.version"])
    assert settings["pythonpath"] == ""
    assert settings["pyproject.toml.sha256"] == "absent"
    assert settings["uv.lock.sha256"] == "absent"
    assert settings[".gitignore.sha256"] == "absent"
    assert settings[".gitattributes.sha256"] == "absent"


def test_collect_hashes_config_files(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_bytes(b"pinned")
    (tmp_path / ".gitattributes").write_bytes(b"* text=auto\n")
    settings = collect_runtime_settings(tmp_path, {})
    assert settings["uv.lock.sha256"] == hashlib.sha256(b"pinned").hexdigest()
    assert settings[".gitattributes.sha256"] == hashlib.sha256(b"* text=auto\n").hexdigest()


def test_collect_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    first = collect_runtime_settings(tmp_path, {"PYTHONPATH": str(tmp_path)})
    second = collect_runtime_settings(tmp_path, {"PYTHONPATH": str(tmp_path)})
    assert first == second
    assert sha256_hex(canonical_bytes(first)) == sha256_hex(canonical_bytes(second))


def test_config_digest_reflects_runtime_drift(tmp_path: Path) -> None:
    baseline = collect_runtime_settings(tmp_path, {})
    drifted = collect_runtime_settings(tmp_path, {"PYTHONPATH": str(tmp_path)})
    assert baseline != drifted
    assert sha256_hex(canonical_bytes(baseline)) != sha256_hex(canonical_bytes(drifted))


def test_unreadable_config_file_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").mkdir()
    with pytest.raises(RuntimeConfigError, match="cannot read"):
        collect_runtime_settings(tmp_path, {})
