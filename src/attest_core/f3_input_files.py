"""F3 staged input files: per-entry verification (V-B13(c)).

Each file entry resolves under V-P1–V-P3 through the P2
confined reader; exact bytes must match size_bytes and
sha256. Missing or unreadable files are INCOMPLETE gaps
(remapped to V-B13: input files are not manifest records).
V-P4/V-P5 deliberately do not apply: entries verify
independently, and relpath sharing across manifests is
expected. P2's concurrent-mutation TOCTOU qualification
carries forward unchanged.
"""

from __future__ import annotations

import hashlib
from typing import Any

from attest_core import f3_paths as paths
from attest_core.f3_errors import F3Error, F3IncompleteError
from attest_core.f3_manifest_entries import Finding, finding_for


def verify_input_files(
    root_fd: int, root: str, entries: Any, location: str = "$"
) -> tuple[Finding, ...]:
    """Verify every file entry's staged bytes against its declaration."""
    if not isinstance(entries, list):
        return (
            Finding(
                severity="INVALID",
                rule="V-B6",
                location=location,
                reason="input_manifest entries must be a list",
            ),
        )
    out: list[Finding] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("kind") != "file":
            continue  # Literals need no file; malformed entries are V-B6 elsewhere.
        eloc = f"{location}.entries[{index}]"
        relpath = entry.get("relpath")
        if not isinstance(relpath, str):
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B6",
                    location=f"{eloc}.relpath",
                    reason="relpath must be a string",
                )
            )
            continue
        try:
            got = paths.read_confined_file(root_fd, root, relpath, "8.5", f"{eloc}.relpath")
        except F3IncompleteError as exc:
            out.append(
                Finding(
                    severity="INCOMPLETE",
                    rule="V-B13",
                    location=eloc,
                    reason=f"input file {relpath!r} unavailable: {exc.reason}",
                )
            )
            continue
        except F3Error as exc:
            out.append(finding_for(exc))  # Native V-P1/V-P2/V-P3 or V-B6.
            continue
        if len(got.data) != entry.get("size_bytes"):
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B13",
                    location=f"{eloc}.size_bytes",
                    reason=(
                        f"size mismatch: read {len(got.data)} bytes "
                        f"!= declared {entry.get('size_bytes')!r}"
                    ),
                )
            )
        digest = hashlib.sha256(got.data).hexdigest()
        if digest != entry.get("sha256"):
            out.append(
                Finding(
                    severity="INVALID",
                    rule="V-B13",
                    location=f"{eloc}.sha256",
                    reason=(
                        f"digest mismatch: staged bytes hash {digest} "
                        f"!= declared {entry.get('sha256')!r}"
                    ),
                )
            )
    return tuple(out)
