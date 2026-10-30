"""Direct tests for transient systemd scope management (M3-A)."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import time

import pytest
from scope_helpers import NEEDS_QUOTAS, wait_for_scope

import attest_core.scopes as scopes_mod
from attest_core.scopes import (
    QuotaLimits,
    ScopeError,
    find_scope,
    read_scope_events,
    scope_argv,
    supports_quotas,
    terminate_scope_by_unit,
)

_BURNER = """\
import os, sys, time
sys.stdin.readline()
if os.fork() == 0:
    time.sleep(300)
    os._exit(0)
kids = []
for _ in range(3):
    pid = os.fork()
    if pid == 0:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            pass
        os._exit(0)
    kids.append(pid)
deadline = time.monotonic() + 2
while time.monotonic() < deadline:
    pass
for pid in kids:
    os.waitpid(pid, 0)
"""

_HOG = """\
import os, sys, time
sys.stdin.readline()
if os.fork() == 0:
    time.sleep(300)
    os._exit(0)
held = []
pages = (50 << 20) // 4096
for _ in range(12):
    chunk = bytearray(50 << 20)
    chunk[0::4096] = b"\\x01" * pages
    held.append(chunk)
"""

_FORKER = """\
import os, sys, time
sys.stdin.readline()
for _ in range(70):
    try: pid = os.fork()
    except OSError: continue
    if pid == 0: time.sleep(30); os._exit(0)
sys.stdin.readline()
"""


def test_supports_quotas_is_stable() -> None:
    assert supports_quotas() == supports_quotas()


def test_scope_argv_builds_launch_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scopes_mod, "_host_has_swap", lambda: True)
    argv = scope_argv(QuotaLimits(), "u.scope", ["echo", "hi"])
    assert argv[:5] == ["/usr/bin/systemd-run", "--user", "--quiet", "--scope", "--unit=u.scope"]
    assert "--expand-environment=no" in argv
    assert argv[-6:] == ["--", "/usr/bin/env", "-i", "LC_ALL=C.UTF-8", "echo", "hi"]
    assert "MemorySwapMax=0" in argv
    monkeypatch.setattr(scopes_mod, "_host_has_swap", lambda: False)
    assert "MemorySwapMax=0" not in scope_argv(QuotaLimits(), "u.scope", ["echo", "hi"])


def test_events_of_missing_scope_raise() -> None:
    with pytest.raises(ScopeError, match="cannot read scope events"):
        read_scope_events("/nonexistent-attest-scope")


def test_terminate_vanished_scope_reports_error() -> None:
    error = terminate_scope_by_unit("gone.scope", QuotaLimits())
    assert error == "scope vanished before verification"


@NEEDS_QUOTAS
def test_scope_tamper_detected() -> None:
    unit = f"attest-test-tamper-{secrets.token_hex(4)}.scope"
    proc = subprocess.Popen(scope_argv(QuotaLimits(), unit, ["sleep", "30"]))
    try:
        path = wait_for_scope(unit)
        with open(os.path.join(path, "memory.max"), "w", encoding="ascii") as handle:
            handle.write("max")
        error = terminate_scope_by_unit(unit, QuotaLimits(), proc)
        assert error is not None and "memory.max" in error
        assert find_scope(unit) is None
    finally:
        proc.kill()
        proc.wait()
        terminate_scope_by_unit(unit, QuotaLimits())


@NEEDS_QUOTAS
def test_scope_stop_kills_members() -> None:
    unit = f"attest-test-kill-{secrets.token_hex(4)}.scope"
    proc = subprocess.Popen(scope_argv(QuotaLimits(), unit, ["sleep", "30"]))
    try:
        wait_for_scope(unit)
        assert terminate_scope_by_unit(unit, QuotaLimits(), proc) is None
        assert proc.wait(timeout=10) != 0
    finally:
        proc.kill()
        proc.wait()
        terminate_scope_by_unit(unit, QuotaLimits())


@NEEDS_QUOTAS
def test_cpu_throttle_observed() -> None:
    unit = f"attest-test-throttle-{secrets.token_hex(4)}.scope"
    burner = subprocess.Popen(
        scope_argv(QuotaLimits(), unit, [sys.executable, "-c", _BURNER]),
        stdin=subprocess.PIPE,
    )
    try:
        assert burner.stdin is not None
        burner.stdin.write(b"go\n")
        burner.stdin.close()
        assert burner.wait(timeout=30) == 0
        path = find_scope(unit)
        assert path is not None
        assert read_scope_events(path)["throttled_usec"] > 0
    finally:
        burner.kill()
        burner.wait()
        terminate_scope_by_unit(unit, QuotaLimits())


@NEEDS_QUOTAS
def test_oom_counter_observed() -> None:
    unit = f"attest-test-oom-{secrets.token_hex(4)}.scope"
    hog = subprocess.Popen(
        scope_argv(QuotaLimits(), unit, [sys.executable, "-c", _HOG]),
        stdin=subprocess.PIPE,
    )
    try:
        assert hog.stdin is not None
        hog.stdin.write(b"go\n")
        hog.stdin.close()
        assert hog.wait(timeout=30) != 0
        path = find_scope(unit)
        assert path is not None
        assert read_scope_events(path)["oom_kill"] >= 1
    finally:
        hog.kill()
        hog.wait()
        terminate_scope_by_unit(unit, QuotaLimits())


@NEEDS_QUOTAS
def test_pids_counter_observed() -> None:
    unit = f"attest-test-pids-{secrets.token_hex(4)}.scope"
    forker = subprocess.Popen(
        scope_argv(QuotaLimits(), unit, [sys.executable, "-c", _FORKER]),
        stdin=subprocess.PIPE,
    )
    try:
        assert forker.stdin is not None
        forker.stdin.write(b"go\n")
        forker.stdin.flush()
        deadline = time.monotonic() + 30.0
        denied = 0
        path = wait_for_scope(unit)
        while denied == 0:
            assert time.monotonic() < deadline, "task limit never tripped"
            denied = read_scope_events(path)["pids_max"]
            time.sleep(0.05)
    finally:
        forker.kill()
        forker.wait()
        terminate_scope_by_unit(unit, QuotaLimits())
