"""F3 workload input-manifest value checks (V-B13(a)).

Version refusal, byte-wise entry ordering, duplicate detection,
and V-P1 file-relpath shape. P0 owns field shapes; this module
owns the value-level rules P0 deferred. Unknown kinds or shapes
fall back to V-B6 defensively.
"""

from __future__ import annotations

from typing import Any

from attest_core import f3_paths as paths
from attest_core.f3_errors import F3Error
from attest_core.f3_manifest_entries import Finding, finding_for

INPUT_MANIFEST_VERSION = 1


def check_manifest_version(manifest: Any, location: str = "$") -> Finding | None:
    """Exact-version-or-refuse for the input-manifest contract version."""
    if not isinstance(manifest, dict):
        return Finding(
            severity="INVALID",
            rule="V-B6",
            location=location,
            reason="input_manifest must be an object",
        )
    found = manifest.get("manifest_version")
    if found != INPUT_MANIFEST_VERSION:
        return Finding(
            severity="INVALID",
            rule="V-B13",
            location=f"{location}.manifest_version",
            reason=(
                f"unsupported input-manifest version: {found!r} "
                f"(implements {INPUT_MANIFEST_VERSION})"
            ),
        )
    return None


def check_manifest_entries(manifest: Any, location: str = "$") -> tuple[Finding, ...]:
    """Ordering, duplicates, and V-P1 relpaths for manifest entries."""
    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), list):
        return (
            Finding(
                severity="INVALID",
                rule="V-B6",
                location=location,
                reason="input_manifest entries must be a list",
            ),
        )
    out: list[Finding] = []
    keys: list[tuple[int, tuple[bytes, bytes]]] = []
    for index, entry in enumerate(manifest["entries"]):
        eloc = f"{location}.entries[{index}]"
        key = _entry_key(entry, eloc, out)
        if key is not None:
            keys.append((index, key))
        if isinstance(entry, dict) and entry.get("kind") == "file":
            try:
                paths.check_shape(entry.get("relpath"), "8.5", f"{eloc}.relpath")
            except F3Error as exc:
                out.append(finding_for(exc))
    seen: dict[tuple[bytes, bytes], int] = {}
    previous: tuple[bytes, bytes] | None = None
    for index, key in keys:
        if key in seen:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B13",
                    location=f"{location}.entries[{index}]",
                    reason=(
                        f"duplicate input-manifest entry {key!r} "
                        f"(also at {location}.entries[{seen[key]}])"
                    ),
                )
            )
        elif previous is not None and key < previous:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B13",
                    location=f"{location}.entries[{index}]",
                    reason="entries must be sorted byte-wise by (kind, relpath/name)",
                )
            )
        else:
            seen[key] = index
        previous = key
    return tuple(out)


def check_manifest_value(manifest: Any, location: str = "$") -> tuple[Finding, ...]:
    """Full value validation: version gate plus entry rules."""
    refused = check_manifest_version(manifest, location)
    if refused is not None:
        return (refused,)
    return check_manifest_entries(manifest, location)


def _entry_key(entry: Any, eloc: str, out: list[Finding]) -> tuple[bytes, bytes] | None:
    """Byte-wise (kind, relpath/name) sort key, or None with a V-B6 finding."""

    def malformed(reason: str) -> None:
        out.append(Finding(severity="INVALID", rule="V-B6", location=eloc, reason=reason))

    if not isinstance(entry, dict):
        malformed("input-manifest entry must be an object")
        return None
    kind = entry.get("kind")
    if kind == "file":
        name = entry.get("relpath")
    elif kind == "literal":
        name = entry.get("name")
    else:
        malformed(f"entry kind must be 'file' or 'literal', got {kind!r}")
        return None
    if not isinstance(name, str):
        malformed("entry relpath/name must be a string")
        return None
    return (str(kind).encode("utf-8"), name.encode("utf-8"))
