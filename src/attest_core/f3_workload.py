"""F3 workload identity and input-manifest shapes (§7.4, V-B13(a)).

Structural validation only: version is checked for integer
type here, while version value, entry ordering, and digest
equality belong to V-B13 in a later phase.
"""

from __future__ import annotations

import functools
from typing import Any

from attest_core import f3_fields as ff
from attest_core import f3_schema as sc

_WORKLOAD_KEYS = frozenset({"workload_class", "workload_id", "input_digest", "input_manifest"})
_MANIFEST_KEYS = frozenset({"manifest_version", "entries"})
_FILE_ENTRY_KEYS = frozenset({"kind", "relpath", "size_bytes", "sha256"})
_LITERAL_ENTRY_KEYS = frozenset({"kind", "name", "value"})


def _nonempty_str(value: Any, section: str, location: str) -> str:
    """Non-empty string (relpath shape checked later per V-P1)."""
    if not isinstance(value, str) or not value:
        sc.fail(section, location, "must be a non-empty string")
    return value


def _file_entry(value: Any, section: str, location: str) -> dict[str, Any]:
    """File input entry shape (confinement checked later)."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _FILE_ENTRY_KEYS, section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    return {
        "kind": "file",
        "relpath": one("relpath", _nonempty_str),
        "size_bytes": one("size_bytes", sc.nonnegative_int),
        "sha256": one("sha256", ff.digest64),
    }


def _literal_entry(value: Any, section: str, location: str) -> dict[str, str]:
    """Literal input entry shape (ASCII name and value)."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _LITERAL_ENTRY_KEYS, section, location)
    name = functools.partial(sc.ascii_bounded, max_len=128)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    return {"kind": "literal", "name": one("name", name), "value": one("value", ff.ascii_text)}


def _manifest_entry(value: Any, section: str, location: str) -> dict[str, Any]:
    """One input-manifest entry, dispatched on kind (shape only)."""
    obj = sc.check_object(value, section, location)
    if obj.get("kind") == "file":
        return _file_entry(value, section, location)
    if obj.get("kind") == "literal":
        return _literal_entry(value, section, location)
    sc.fail(section, f"{location}.kind", 'entry kind must be "file" or "literal"')


def _input_manifest(value: Any, section: str, location: str) -> dict[str, Any]:
    """Input-manifest structure (version value and order checked later)."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _MANIFEST_KEYS, section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    version = one("manifest_version", sc.strict_int)
    raw = one("entries", _entries_list)
    entries = [
        _manifest_entry(item, section, f"{location}.entries[{index}]")
        for index, item in enumerate(raw)
    ]
    return {"manifest_version": version, "entries": entries}


def _entries_list(value: Any, section: str, location: str) -> list[Any]:
    """A JSON list of entries (possibly empty: no inputs declared)."""
    if not isinstance(value, list):
        sc.fail(section, location, "entries must be a JSON list")
    return value


def validate_workload(value: Any, section: str, location: str) -> dict[str, Any]:
    """Workload triple plus embedded input manifest (shape only)."""
    obj = sc.check_object(value, section, location)
    sc.reject_unknown(obj, _WORKLOAD_KEYS, section, location)

    def one(key: str, func: sc.Check) -> Any:
        return sc.field(obj, key, section, location, func)

    return {
        "workload_class": one("workload_class", ff.workload_class),
        "workload_id": one("workload_id", ff.workload_id),
        "input_digest": one("input_digest", ff.digest64),
        "input_manifest": one("input_manifest", _input_manifest),
    }
