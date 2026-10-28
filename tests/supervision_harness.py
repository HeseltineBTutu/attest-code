"""Shared harness for S2 supervision tests (helpers only, no tests).

Spawns real child/grandchild processes, records their pids, and asserts
on observed death via /proc state where available. Imported by the
supervision test modules; not collected as tests itself.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from attest_core.process_group import establish_worker_group, supports_process_groups
from attest_core.verification import AttemptReport
from attest_spec import AttemptOutcome

NEEDS_GROUPS = pytest.mark.skipif(
    not supports_process_groups(), reason="process-group supervision unavailable"
)

SLEEP_SECONDS = 30


def _sleep_script(extra: str = "") -> str:
    return f"import time; {extra} time.sleep({SLEEP_SECONDS})"


def read_pids(pid_dir: Path) -> list[int]:
    pids: list[int] = []
    for path in sorted(pid_dir.glob("*.pid")):
        try:
            pids.append(int(path.read_text(encoding="utf-8").strip()))
        except (OSError, ValueError):
            continue
    return pids


def kill_all(pid_dir: Path) -> None:
    for pid in read_pids(pid_dir):
        with contextlib.suppress(OSError):
            os.kill(pid, 9)


def _proc_state(pid: int) -> str | None:
    """Linux process state letter, or None when gone/unreadable."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            content = handle.read(4096).decode("ascii", errors="replace")
    except OSError:
        return None
    fields = content.rsplit(")", 1)[-1].split()
    return fields[0] if fields else None


def eventually_dead(pid: int, timeout: float = 10.0) -> bool:
    """True once the pid is gone (zombies count as dead on Linux)."""
    deadline = time.monotonic() + timeout
    while True:
        if os.path.isdir("/proc"):
            state = _proc_state(pid)
            if state is None or state == "Z":
                return True
        else:
            try:
                os.kill(pid, 0)
            except OSError:
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def wait_for_pidfile(pid_dir: Path, name: str, timeout: float = 10.0) -> int:
    deadline = time.monotonic() + timeout
    while True:
        path = pid_dir / name
        try:
            return int(path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                raise AssertionError(f"pidfile {name} never appeared") from None
            time.sleep(0.05)


def spawn_sleeper(pid_dir: str, name: str, extra: str = "") -> int:
    child = subprocess.Popen(
        [sys.executable, "-c", _sleep_script(extra)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    Path(pid_dir, f"{name}.pid").write_text(str(child.pid), encoding="utf-8")
    return child.pid


def spawn_child_and_hang(pid_dir: str) -> AttemptReport:
    spawn_sleeper(pid_dir, "child")
    time.sleep(SLEEP_SECONDS)
    raise AssertionError("unreachable")


def spawn_grandchild_tree(pid_dir: str) -> AttemptReport:
    middle = (
        "import subprocess,sys,time;"
        "grandchild=subprocess.Popen([sys.executable,'-c',"
        f"'import time; time.sleep({SLEEP_SECONDS})']);"
        "open(sys.argv[1],'w').write(str(grandchild.pid));"
        f"time.sleep({SLEEP_SECONDS})"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", middle, str(Path(pid_dir, "grandchild.pid"))],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    Path(pid_dir, "child.pid").write_text(str(child.pid), encoding="utf-8")
    time.sleep(SLEEP_SECONDS)
    raise AssertionError("unreachable")


def ignore_term_and_hang() -> AttemptReport:
    import signal

    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(SLEEP_SECONDS)
    raise AssertionError("unreachable")


def spawn_termproof_child_and_hang(pid_dir: str) -> AttemptReport:
    spawn_sleeper(pid_dir, "child", "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN);")
    time.sleep(SLEEP_SECONDS)
    raise AssertionError("unreachable")


def spawn_child_and_return(pid_dir: str) -> AttemptReport:
    spawn_sleeper(pid_dir, "child")
    time.sleep(0.5)
    return AttemptReport(AttemptOutcome.PASS, (), "returned with live child")


def quick_pass() -> AttemptReport:
    return AttemptReport(AttemptOutcome.PASS, (), "quick")


def grouped_quick_exit(paths: Any) -> None:
    establish_worker_group(paths)
