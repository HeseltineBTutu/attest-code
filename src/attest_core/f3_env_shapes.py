"""F3 environment nested shapes (§7.3 sub-objects)."""

from __future__ import annotations

import functools
from typing import Any

from attest_core import f3_fields as ff
from attest_core import f3_schema as sc


def worktree(value: Any, section: str, location: str) -> dict[str, Any]:
    """Clean/dirty state object or an unavailable marker."""
    if isinstance(value, dict) and set(value) == {"unavailable"}:
        return sc.unavailable_marker(value, section, location)
    obj = sc.check_object(value, section, location)
    state = obj.get("state")
    if state == "clean" and set(obj) == {"state"}:
        return {"state": "clean"}
    if state == "dirty" and set(obj) == {"state", "status"}:
        status = sc.nonblank_str(obj["status"], section, f"{location}.status")
        return {"state": "dirty", "status": status}
    sc.fail(section, location, "must be {clean} or {dirty,status} or a marker")


def python_info(value: Any, section: str, location: str) -> dict[str, Any]:
    """Interpreter implementation and version, or a marker."""
    if isinstance(value, dict) and set(value) == {"unavailable"}:
        return sc.unavailable_marker(value, section, location)
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, frozenset({"implementation", "version"}), section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    return {
        "implementation": one("implementation", sc.nonblank_str),
        "version": one("version", sc.nonblank_str),
    }


def cgroup_limits(value: Any, section: str, location: str) -> dict[str, Any]:
    """Memory cgroup envelope: unlimited, limited, or a marker."""
    if isinstance(value, dict) and set(value) == {"unavailable"}:
        return sc.unavailable_marker(value, section, location)
    obj = sc.check_object(value, section, location)
    limited = obj.get("limited")
    if limited is False and set(obj) == {"limited"}:
        return {"limited": False}
    if limited is True and set(obj) == {"limited", "memory_max_bytes"}:
        size = sc.field(obj, "memory_max_bytes", section, location, sc.positive_int)
        return {"limited": True, "memory_max_bytes": size}
    sc.fail(section, location, "must be {limited:false}, {limited:true,...}, or a marker")


def container_runtime(value: Any, section: str, location: str) -> dict[str, Any]:
    """Container runtime, bare-metal marker, or unavailable marker."""
    if isinstance(value, dict) and set(value) == {"unavailable"}:
        return sc.unavailable_marker(value, section, location)
    obj = sc.check_object(value, section, location)
    if set(obj) == {"bare_metal"}:
        if obj["bare_metal"] is True:
            return {"bare_metal": True}
        sc.fail(section, location, "bare_metal must be exactly true")
    sc.reject_unknown(obj, frozenset({"runtime", "version"}), section, location)
    tagged = functools.partial(sc.ascii_bounded, max_len=64)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    return {"runtime": one("runtime", tagged), "version": one("version", tagged)}


def runner_settings(value: Any, section: str, location: str) -> dict[str, str]:
    """v1 mandates the undefined-runner-settings marker and nothing else."""
    marker = sc.unavailable_marker(value, section, location)
    if marker != {"unavailable": "runner-settings-undefined-in-v1"}:
        sc.fail(section, location, "v1 admits only the undefined-runner-settings marker")
    return marker


def env_map(value: Any, section: str, location: str) -> dict[str, str]:
    """Allowlisted environment mapping: non-blank names to strings."""
    obj = sc.check_object(value, section, location)
    out: dict[str, str] = {}
    for key in obj:
        if not isinstance(key, str) or not key.strip():
            sc.fail(section, location, "variable names must be non-blank strings")
        item = obj[key]
        if not isinstance(item, str):
            sc.fail(section, f"{location}.{key}", "variable values must be strings")
        out[key] = item
    return out


def condition(value: Any, section: str, location: str) -> dict[str, str]:
    """One observed interference condition: fixed category plus detail."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, frozenset({"category", "detail"}), section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    return {
        "category": one("category", ff.interference_category),
        "detail": one("detail", ff.detail),
    }


def interference(value: Any, section: str, location: str) -> dict[str, Any]:
    """Three-state interference assessment (R5-04)."""
    obj = sc.check_object(value, section, location)
    assessment = obj.get("assessment")
    if assessment in ("none-declared", "unknown") and set(obj) == {"assessment"}:
        return {"assessment": assessment}
    if assessment == "observed" and set(obj) == {"assessment", "conditions"}:
        raw = obj["conditions"]
        if not isinstance(raw, list) or not raw:
            sc.fail(section, location, "observed requires a non-empty conditions list")
        conditions = [
            condition(item, section, f"{location}.conditions[{index}]")
            for index, item in enumerate(raw)
        ]
        return {"assessment": "observed", "conditions": conditions}
    sc.fail(section, location, "must be none-declared, unknown, or observed+conditions")
