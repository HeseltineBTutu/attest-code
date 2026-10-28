"""Runtime binding: env validation and deterministic runtime settings."""

from __future__ import annotations

import hashlib
import os
import re
import sys
import types
from importlib import metadata as importlib_metadata
from pathlib import Path

import pytest

from attest_core.evidence import canonical_bytes, sha256_hex
from attest_core.runtime import (
    RuntimeConfigError,
    check_environment,
    check_root_startup_modules,
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


@pytest.mark.parametrize("name", ["sitecustomize.py", "usercustomize.py"])
def test_root_startup_module_is_refused(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(RuntimeConfigError, match="exists at the repository root"):
        check_environment(tmp_path, {})


def test_root_startup_module_symlink_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real.py"
    target.write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "sitecustomize.py").symlink_to(target)
    with pytest.raises(RuntimeConfigError, match="exists at the repository root"):
        check_environment(tmp_path, {})


def test_collect_records_installed_versions(tmp_path: Path) -> None:
    settings = collect_runtime_settings(tmp_path, {})
    assert settings["deps.attest-code"] == importlib_metadata.version("attest-code")
    assert settings["deps.fastapi"] == importlib_metadata.version("fastapi")
    assert settings["deps.httpx"] == importlib_metadata.version("httpx")
    assert settings["deps.pyyaml"] == importlib_metadata.version("pyyaml")


def test_missing_distribution_records_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(importlib_metadata, "requires", lambda dist: ["bogus-dist-999>=1"])
    settings = collect_runtime_settings(tmp_path, {})
    assert settings["deps.bogus-dist-999"] == "absent"


def test_dependency_drift_changes_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    baseline = collect_runtime_settings(tmp_path, {})
    real_version = importlib_metadata.version

    def fake_version(name: str) -> str:
        return "0.0.0" if name == "fastapi" else real_version(name)

    monkeypatch.setattr(importlib_metadata, "version", fake_version)
    drifted = collect_runtime_settings(tmp_path, {})
    assert drifted["deps.fastapi"] == "0.0.0"
    assert sha256_hex(canonical_bytes(baseline)) != sha256_hex(canonical_bytes(drifted))


def test_root_startup_module_dangling_symlink_is_refused(tmp_path: Path) -> None:
    (tmp_path / "sitecustomize.py").symlink_to(tmp_path / "no-such-target.py")
    with pytest.raises(RuntimeConfigError, match="exists at the repository root"):
        check_root_startup_modules(tmp_path)


@pytest.mark.parametrize("name", ["sitecustomize.py", "usercustomize.py"])
def test_src_startup_module_is_refused(tmp_path: Path, name: str) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / name).write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(RuntimeConfigError, match="exists in the source tree"):
        check_root_startup_modules(tmp_path)


def test_src_startup_module_symlink_is_refused(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "real.py"
    target.write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "src" / "sitecustomize.py").symlink_to(target)
    with pytest.raises(RuntimeConfigError, match="exists in the source tree"):
        check_root_startup_modules(tmp_path)


def _stage_loaded_module(monkeypatch: pytest.MonkeyPatch, name: str, file: str | None) -> None:
    module = types.ModuleType(name)
    if file is not None:
        module.__dict__["__file__"] = file
    monkeypatch.setitem(sys.modules, name, module)


@pytest.mark.parametrize("name", ["sitecustomize.py", "usercustomize.py"])
def test_already_imported_startup_module_from_tree_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    # The file need not exist on disk: this mirrors a startup module that
    # executed and deleted itself before the preflight ran.
    _stage_loaded_module(monkeypatch, name.removesuffix(".py"), str(tmp_path / name))
    with pytest.raises(RuntimeConfigError, match="already imported from the repository tree"):
        check_root_startup_modules(tmp_path)


def test_already_imported_startup_module_from_elsewhere_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _stage_loaded_module(
        monkeypatch, "sitecustomize", str(tmp_path / "elsewhere" / "sitecustomize.py")
    )
    check_root_startup_modules(root)
    assert check_environment(root, {}) == ""


def test_startup_module_imported_from_unknown_location_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stage_loaded_module(monkeypatch, "sitecustomize", None)
    with pytest.raises(RuntimeConfigError, match="unknown location"):
        check_root_startup_modules(tmp_path)


def test_blocked_startup_import_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "sitecustomize", None)
    check_root_startup_modules(tmp_path)
