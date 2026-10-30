"""M4 seccomp tests: builder, install failures, live enforcement.

Unit tests pin exact BPF bytes, table consistency, and fail-closed
mapping. Live tests assert parent-observed termination evidence from
real contained attempts. The diagnostic harness bisects a SIGSYS
death to its rule; it runs only here, never in production.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import signal
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from attest_core import seccomp as seccomp_mod
from attest_core.bounds import run_bounded
from attest_core.ns_setup import RunnerError, supports_containment
from attest_core.seccomp import POLICY, build_insns, install_denylist
from attest_core.seccomp_probes import (
    probe_allowed,
    probe_denylist,
    probe_fallback,
    probe_inherit,
)
from attest_spec import AttemptOutcome

NEEDS_CONTAINMENT = pytest.mark.skipif(
    not supports_containment(), reason="user+mount+PID+network namespaces unavailable"
)


@pytest.fixture(scope="session")
def src_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Live source copied into snapshot layout (root/src/*, no extras)."""
    root = tmp_path_factory.mktemp("m4-snapshot")
    live = Path(__file__).resolve().parents[3] / "src"
    shutil.copytree(live, root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _bisect_killers(rules: list[str], dead: Callable[[frozenset[str]], bool]) -> set[str]:
    """Smallest omission set that revives the workload (ddmin)."""
    if not dead(frozenset()):
        raise AssertionError("workload survives full policy; nothing to bisect")
    omit, gran = list(rules), 2
    while len(omit) >= 2:
        size = max(1, len(omit) // gran)
        chunks = [omit[i : i + size] for i in range(0, len(omit), size)]
        kept = [[x for x in omit if x not in c] for c in chunks]
        drop = next((k for k in kept if not dead(frozenset(k))), None)
        if drop is not None:
            omit, gran = drop, max(2, gran - 1)
            continue
        solo = next((c for c in chunks if not dead(frozenset(c))), None)
        if solo is not None:
            omit, gran = solo, 2
            continue
        if gran >= len(omit):
            break
        gran = min(len(omit), gran * 2)
    return set(omit)


def test_build_exact_bytes() -> None:
    program = build_insns(0xC000003E, [165, 101], 56, 435, True)
    assert program == [
        (0x20, 0, 0, 4),
        (0x15, 0, 11, 0xC000003E),
        (0x20, 0, 0, 0),
        (0x45, 9, 0, 0x40000000),
        (0x15, 8, 0, 165),
        (0x15, 7, 0, 101),
        (0x15, 5, 0, 435),
        (0x15, 0, 3, 56),
        (0x20, 0, 0, 16),
        (0x54, 0, 0, 0x7E020080),
        (0x15, 0, 2, 0),
        (0x06, 0, 0, 0x7FFF0000),
        (0x06, 0, 0, 0x50026),
        (0x06, 0, 0, 0x80000000),
    ]
    small = build_insns(0xC00000B7, [40], 220, 435, False)
    assert len(small) == 12
    assert all(insn[0] != 0x45 for insn in small)


def test_policy_tables_consistent() -> None:
    names = [name for name, _, _ in POLICY]
    assert len(names) == len(set(names)) == 43
    assert all(isinstance(n, int) for _, *pair in POLICY for n in pair)
    assert {"clone", "clone3", "seccomp"} <= set(names)


def test_clone_mask_matches_headers() -> None:
    bits = (0x20000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80)
    mask = 0
    for bit in bits:
        mask |= bit
    assert seccomp_mod._NS_CLONE_MASK == mask == 0x7E020080


@pytest.mark.parametrize(
    ("fail_at", "match"),
    [("prctl", "no-new-privs"), ("avail", "KILL_PROCESS"), ("install", "seccomp install failed")],
)
def test_install_failure_fails_closed(
    fail_at: str, match: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = {"prctl": 0, "avail": 0, "install": 0}
    script[fail_at] = -1
    state = {"n": 0}

    def _prctl(*args: object) -> int:
        return script["prctl"]

    def _syscall(*args: object) -> int:
        state["n"] += 1
        return script["avail" if state["n"] == 1 else "install"]

    monkeypatch.setattr(seccomp_mod, "_LIBC", SimpleNamespace(prctl=_prctl, syscall=_syscall))
    with pytest.raises(RunnerError, match=match):
        install_denylist()


def test_install_refuses_unknown_arch(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = SimpleNamespace(sysname="", nodename="", release="", version="", machine="riscv64")
    monkeypatch.setattr(os, "uname", lambda: fake)
    with pytest.raises(RunnerError, match="unsupported"):
        install_denylist()


def test_bisect_finds_planted_killers() -> None:
    killers = {"bpf", "mount"}

    def dead(omit: frozenset[str]) -> bool:
        return not killers.issubset(omit)

    rules = ["mount", "bpf", "ptrace", "reboot", "acct"]
    assert _bisect_killers(rules, dead) == killers
    with pytest.raises(AssertionError, match="nothing to bisect"):
        _bisect_killers(rules, lambda omit: False)


@NEEDS_CONTAINMENT
def test_seccomp_denylist_enforced(src_tree: Path) -> None:
    report = run_bounded(probe_denylist, 60.0, snapshot_root=src_tree, contained=True, seccomp=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail.startswith("denied:")


@NEEDS_CONTAINMENT
def test_seccomp_allowed_controls(src_tree: Path) -> None:
    report = run_bounded(probe_allowed, 30.0, snapshot_root=src_tree, contained=True, seccomp=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "controls-ok"


@NEEDS_CONTAINMENT
def test_seccomp_inherit(src_tree: Path) -> None:
    report = run_bounded(probe_inherit, 30.0, snapshot_root=src_tree, contained=True, seccomp=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "fork-inherited-sigsys"


@NEEDS_CONTAINMENT
def test_seccomp_fallback(src_tree: Path) -> None:
    report = run_bounded(probe_fallback, 30.0, snapshot_root=src_tree, contained=True, seccomp=True)
    assert report.outcome == AttemptOutcome.PASS
    assert report.detail == "enosys-then-fork-ok"


def test_diagnostic_bisect_finds_mount() -> None:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    def dead(omit: frozenset[str]) -> bool:
        pid = os.fork()
        if pid != 0:
            _, status = os.waitpid(pid, 0)
            return os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGSYS
        try:
            install_denylist(omit)
            libc.mount(None, None, None, 0, None)
        except BaseException:
            pass
        os._exit(0)

    rules = [name for name, _, _ in POLICY]
    assert _bisect_killers(rules, dead) == {"mount"}


def test_seccomp_requires_contained() -> None:
    with pytest.raises(ValueError, match="contained"):
        run_bounded(probe_allowed, 1.0, contained=False, seccomp=True)
