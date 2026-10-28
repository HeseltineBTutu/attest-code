"""Supervised-tree membership observation (S2).

Pure inspection: is any live process still holding the verified
group? Linux reads /proc directly (zombies — already reaped or awaiting
adoption — count as dead); other platforms probe conservatively with
killpg(..., 0), where any error other than "no such group" counts as
present. Never signals for effect and never mutates state.
"""

from __future__ import annotations

import os


def _proc_group_members(pgid: int) -> bool:
    """True if any non-zombie process holds the group (Linux /proc)."""
    try:
        candidates = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return _kill_group_members(pgid)
    for pid in candidates:
        try:
            with open(f"/proc/{pid}/stat", "rb") as handle:
                content = handle.read(4096).decode("ascii", errors="replace")
        except OSError:
            continue
        fields = content.rsplit(")", 1)[-1].split()
        if len(fields) < 3:
            continue
        state, group = fields[0], fields[2]
        if state == "Z" or not group.isdigit() or int(group) != pgid:
            continue
        return True
    return False


def _kill_group_members(pgid: int) -> bool:
    """Conservative group-membership probe; zombies count as present."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def group_has_members(pgid: int) -> bool:
    """True unless the verified group is observably empty."""
    if os.path.isdir("/proc"):
        return _proc_group_members(pgid)
    return _kill_group_members(pgid)
