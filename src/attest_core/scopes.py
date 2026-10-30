"""Transient systemd scopes for M3-A quotas (Linux-only, stdlib-only).

systemd-run launches each attempt INTO a scope; the parent stops the
scope and verifies emptiness before accepting any result."""

from __future__ import annotations

import contextlib
import functools
import os
import secrets
import subprocess
import time
from dataclasses import dataclass

CGROUP_ROOT = "/sys/fs/cgroup"
_START_TIMEOUT = 5.0
_STOP_TIMEOUT = 10.0
_PROBE_SH = "/bin/sleep 300 <&- >&- 2>&- & /bin/cat /proc/self/cgroup; /bin/ls /proc/self/fd"


class ScopeError(Exception):
    """Scope provisioning, placement, or verification failure."""


@dataclass(frozen=True)
class QuotaLimits:
    """Provisional quotas (P0 headroom, CI unverified); override freely."""

    memory_max: int = 536870912
    tasks_max: int = 64
    cpu_percent: int = 200


def _read_text(path: str) -> str:
    with open(path, encoding="ascii") as handle:
        return handle.read().strip()


def find_scope(unit: str) -> str | None:
    """Resolve a unit name to its cgroup dir; None when absent."""
    try:
        own = _read_text("/proc/self/cgroup")
    except OSError:
        return None
    parts = own[3:].strip("/").split("/") if own.startswith("0::/") else []
    top = os.path.join(CGROUP_ROOT, *parts[:2]) if len(parts) >= 2 else CGROUP_ROOT
    return next((os.path.join(root, unit) for root, dirs, _ in os.walk(top) if unit in dirs), None)


def _poll_gone(unit: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and find_scope(unit) is not None:
        time.sleep(0.05)
    return find_scope(unit) is None


def _host_has_swap() -> bool:
    try:
        return len(_read_text("/proc/swaps").splitlines()) > 1
    except OSError as exc:
        raise ScopeError(f"cannot inspect host swap: {exc}") from exc


def launch_env() -> dict[str, str] | None:
    """Bus address for the systemd-run prefix; None when the host has none."""
    names = ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
    env = {key: os.environ[key] for key in names if key in os.environ}
    return env or None


def _reap(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(Exception):
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=_START_TIMEOUT)


def _stop_unit(unit: str) -> None:
    with contextlib.suppress(Exception):
        subprocess.run(["systemctl", "--user", "stop", unit], timeout=_STOP_TIMEOUT, check=False)


def _verify_limits(path: str, limits: QuotaLimits) -> None:
    wants = {"memory.max": str(limits.memory_max), "pids.max": str(limits.tasks_max)}
    wants["cpu.max"] = f"{limits.cpu_percent * 1000} 100000"
    if _host_has_swap():
        wants["memory.swap.max"] = "0"
    for name, want in wants.items():
        try:
            actual = _read_text(os.path.join(path, name))
        except OSError as exc:
            raise ScopeError(f"cannot read {name}: {exc}") from exc
        if actual != want:
            raise ScopeError(f"{name} is {actual!r}, want {want!r}")


def scope_argv(limits: QuotaLimits, unit: str, command: list[str]) -> list[str]:
    """Prefix launching command inside a fresh scope; migration is kernel-denied."""
    argv = ["/usr/bin/systemd-run", "--user", "--quiet", "--scope"]
    argv += [f"--unit={unit}", "-p", "Delegate=yes", "--expand-environment=no"]
    argv += ["-p", f"MemoryMax={limits.memory_max}", "-p", f"TasksMax={limits.tasks_max}"]
    argv += ["-p", f"CPUQuota={limits.cpu_percent}%"]
    argv += ["-p", "MemorySwapMax=0"] if _host_has_swap() else []
    return argv + ["--", "/usr/bin/env", "-i", "LC_ALL=C.UTF-8"] + command


def _counter(path: str, key: str) -> int:
    for line in _read_text(path).splitlines():
        if line.startswith(key + " "):
            return int(line.split()[1])
    return 0


def read_scope_events(scope_path: str) -> dict[str, int]:
    """Bounded resource counters; unreadable scope raises ScopeError."""
    try:
        events = _counter(os.path.join(scope_path, "memory.events"), "oom")
        mem = _counter(os.path.join(scope_path, "memory.events"), "oom_kill")
        pids = _counter(os.path.join(scope_path, "pids.events"), "max")
        cpu = _counter(os.path.join(scope_path, "cpu.stat"), "throttled_usec")
    except (OSError, ValueError) as exc:
        raise ScopeError(f"cannot read scope events: {exc}") from exc
    return {"oom": events, "oom_kill": mem, "pids_max": pids, "throttled_usec": cpu}


def terminate_scope_by_unit(
    unit: str, limits: QuotaLimits, leader: subprocess.Popen[bytes] | None = None
) -> str | None:
    """Stop the attempt scope and verify emptiness. Never raises; error or None."""
    try:
        path = find_scope(unit)
        if path is None:
            return "scope vanished before verification"
        try:
            _verify_limits(path, limits)
            tampered: str | None = None
        except ScopeError as exc:
            tampered = str(exc)
        _stop_unit(unit)
        if not _poll_gone(unit, _STOP_TIMEOUT):
            kill = os.path.join(path, "cgroup.kill")
            with contextlib.suppress(OSError), open(kill, "w", encoding="ascii") as handle:
                handle.write("1")
            if not _poll_gone(unit, _STOP_TIMEOUT):
                try:
                    procs = _read_text(os.path.join(path, "cgroup.procs"))
                except OSError:
                    return "scope not empty after kill (unknown procs)"
                return f"scope not empty after kill ({len(procs.split())} procs)"
        if leader is not None:
            _reap(leader)
        return tampered
    except Exception as exc:
        return f"scope teardown failed: {exc}"


@functools.lru_cache(maxsize=1)
def supports_quotas() -> bool:
    """True when launch-into-scope with verified quotas works end to end."""
    token = secrets.token_hex(8)
    unit = f"attest-probe-{token}.scope"
    penv = launch_env()
    if penv is None:
        return False
    argv = scope_argv(QuotaLimits(), unit, ["/bin/sh", "-c", _PROBE_SH])
    reader, writer = os.pipe()
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(writer,),
            env=penv,
        )
    except OSError:
        os.close(reader)
        os.close(writer)
        return False
    os.close(reader)
    os.close(writer)
    try:
        out = proc.communicate(timeout=_START_TIMEOUT)[0].decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        _stop_unit(unit)
        _reap(proc)
        return False
    good = token in out and f"\n{writer}\n" in f"\n{out}"
    path = find_scope(unit) if good else None
    if path is None:
        return False
    try:
        _verify_limits(path, QuotaLimits())
        read_scope_events(path)
    except ScopeError:
        terminate_scope_by_unit(unit, QuotaLimits())
        return False
    return terminate_scope_by_unit(unit, QuotaLimits()) is None
