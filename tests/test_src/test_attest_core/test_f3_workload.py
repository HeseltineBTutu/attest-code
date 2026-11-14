"""F3 workload identity and input-manifest shapes (V-B13 structure)."""

from __future__ import annotations

from typing import Any

import pytest
from f3_fixtures import UUID_C, assert_fails, valid_campaign

from attest_core.f3_records_campaign import validate_campaign


def _workload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "workload_class": "Medium",
        "workload_id": "auth-admin-001",
        "input_digest": "ab" * 32,
        "input_manifest": {
            "manifest_version": 1,
            "entries": [
                {
                    "kind": "file",
                    "relpath": "inputs/auth-admin-001.yaml",
                    "size_bytes": 5231,
                    "sha256": "cd" * 32,
                }
            ],
        },
    }
    base.update(overrides)
    return base


def _entry_case(**overrides: Any) -> dict[str, Any]:
    payload = valid_campaign()
    entry: dict[str, Any] = {
        "run_sequence": 1,
        "invocation_id": UUID_C,
        "sample_class": "warmup",
        "target": "repaired",
        "workload": _workload(),
    }
    entry.update(overrides)
    payload["invocations"] = [entry]
    return payload


def _manifest_case(manifest: Any) -> dict[str, Any]:
    return _entry_case(workload=_workload(input_manifest=manifest))


def test_manifest_shapes() -> None:
    good_file = {"kind": "file", "relpath": "a/b", "size_bytes": 0, "sha256": "ef" * 32}
    good_literal = {"kind": "literal", "name": "seed", "value": ""}
    manifest = {"manifest_version": 1, "entries": [good_file, good_literal]}
    assert validate_campaign(_manifest_case(manifest)) is not None
    unsorted = {"manifest_version": 99, "entries": []}
    assert validate_campaign(_manifest_case(unsorted)) is not None


@pytest.mark.parametrize(
    ("manifest", "location"),
    [
        (
            {"manifest_version": "1", "entries": []},
            "$.invocations[0].workload.input_manifest.manifest_version",
        ),
        ({"manifest_version": 1}, "$.invocations[0].workload.input_manifest.entries"),
        (
            {"manifest_version": 1, "entries": {}, "zzz": 1},
            "$.invocations[0].workload.input_manifest",
        ),
        (
            {"manifest_version": 1, "entries": [{"kind": "blob"}]},
            "$.invocations[0].workload.input_manifest.entries[0].kind",
        ),
        (
            {"manifest_version": 1, "entries": [{"kind": "file"}]},
            "$.invocations[0].workload.input_manifest.entries[0].relpath",
        ),
        (
            {
                "manifest_version": 1,
                "entries": [{"kind": "file", "relpath": "", "size_bytes": 1, "sha256": "ab" * 32}],
            },
            "$.invocations[0].workload.input_manifest.entries[0].relpath",
        ),
        (
            {
                "manifest_version": 1,
                "entries": [
                    {"kind": "file", "relpath": "a", "size_bytes": -1, "sha256": "ab" * 32}
                ],
            },
            "$.invocations[0].workload.input_manifest.entries[0].size_bytes",
        ),
        (
            {
                "manifest_version": 1,
                "entries": [{"kind": "file", "relpath": "a", "size_bytes": 1, "sha256": "zz"}],
            },
            "$.invocations[0].workload.input_manifest.entries[0].sha256",
        ),
        (
            {"manifest_version": 1, "entries": [{"kind": "literal", "name": "", "value": "v"}]},
            "$.invocations[0].workload.input_manifest.entries[0].name",
        ),
        (
            {
                "manifest_version": 1,
                "entries": [{"kind": "literal", "name": "n", "value": "héllo"}],
            },
            "$.invocations[0].workload.input_manifest.entries[0].value",
        ),
        (
            {"manifest_version": 1, "entries": [{"kind": "literal", "name": "n"}]},
            "$.invocations[0].workload.input_manifest.entries[0].value",
        ),
    ],
)
def test_manifest_rejects(manifest: Any, location: str) -> None:
    assert_fails(
        validate_campaign, _manifest_case(manifest), rule="V-B6", section="7.4", location=location
    )
