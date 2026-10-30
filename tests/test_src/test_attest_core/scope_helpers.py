"""Quota-test support: skip marker and scope-ready polling (M3-A)."""

from __future__ import annotations

import os
import time

import pytest

from attest_core.ns_setup import supports_containment
from attest_core.scopes import find_scope, supports_quotas

NEEDS_QUOTAS = pytest.mark.skipif(
    not (supports_containment() and supports_quotas()),
    reason="systemd scope quotas unavailable",
)


def wait_for_scope(unit: str, timeout: float = 5.0) -> str:
    """Poll until systemd materializes the scope; fail loudly after timeout."""
    deadline = time.monotonic() + timeout
    while True:
        path = find_scope(unit)
        if path is not None:
            return path
        assert time.monotonic() < deadline, f"scope never appeared: {unit}"
        time.sleep(0.05)


def pgid_members() -> set[int]:
    """Pids currently in this process's group (zombies excluded)."""
    mine = str(os.getpgrp())
    found: set[int] = set()
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/stat", encoding="ascii") as handle:
                fields = handle.read().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if len(fields) >= 3 and fields[2] == mine and fields[0] != "Z":
            found.add(int(pid))
    return found
