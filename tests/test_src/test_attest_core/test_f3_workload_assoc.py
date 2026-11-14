"""F3 workload association, proof boundaries, and P0–P3 regression."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from f3_fixtures import to_bytes, valid_attempt
from f3_identity_pkg import (
    INVOCATION_1,
    INVOCATION_2,
    attempt,
    campaign,
    env,
    total,
    valid_package,
    view,
)
from f3_input_pkg import (
    EMPTY_DIGEST,
    file_entry,
    literal_entry,
    manifest,
    stage,
    triples,
    validated_workload,
)
from f3_package import manifest_dict, record_entry, write_package

import attest_core.f3_input_digest as digest_mod
import attest_core.f3_input_files as files_mod
import attest_core.f3_input_manifest as manifest_mod
from attest_core import f3_digest, f3_paths
from attest_core.f3_errors import F3Error
from attest_core.f3_identity import check_identity
from attest_core.f3_input_digest import manifest_digest, verify_workload
from attest_core.f3_manifest import verify_manifest
from attest_core.f3_workload import validate_workload
from attest_sdk import canonical

DATA = b"assoc-bytes"


def _composed(tmp_path: Path, loaded: dict) -> tuple:
    root = str(tmp_path.resolve())
    fd = f3_paths.open_root(root)
    try:
        return verify_workload(loaded, root_fd=fd, root=root)
    finally:
        os.close(fd)


def test_composed_valid_workload(tmp_path: Path) -> None:
    stage(tmp_path, {"inputs/data.bin": DATA})
    loaded = validated_workload(
        manifest([file_entry("inputs/data.bin", DATA)]),
        manifest_digest(manifest([file_entry("inputs/data.bin", DATA)])),
    )
    assert _composed(tmp_path, loaded) == ()


def test_version_refusal_stops_everything(tmp_path: Path) -> None:
    loaded = validated_workload(manifest([], version=2), EMPTY_DIGEST)
    assert triples(_composed(tmp_path, loaded)) == [
        ("INVALID", "V-B13", "$.input_manifest.manifest_version")
    ]


def test_entry_digest_contradiction(tmp_path: Path) -> None:
    loaded = validated_workload(manifest([literal_entry()]), EMPTY_DIGEST)
    kinds = triples(_composed(tmp_path, loaded))
    assert ("INVALID", "V-B13", "$.input_digest") in kinds


def test_record_workload_mismatch_is_p3_rid11() -> None:
    """Echo association stays in P3; P4 does not duplicate R-ID11."""
    made = [attempt(INVOCATION_1, n) for n in (1, 2, 3)]
    made[0] = attempt(INVOCATION_1, 1, input_digest="ff" * 32)
    report = check_identity(view(campaign(), attempts=made, totals=[total()], envs=[env()]))
    assert ("INVALID", "R-ID11", "attempt[0]") in [
        (f.severity, f.rule, f.location) for f in report.findings
    ]
    assert report.severity == "INVALID"


def test_shared_workload_across_invocations(tmp_path: Path) -> None:
    """Reruns prove same-thing-measured by id-plus-digest equality."""
    stage(tmp_path, {"inputs/data.bin": DATA})
    body = manifest([file_entry("inputs/data.bin", DATA)])
    digest = manifest_digest(body)
    first = validated_workload(body, digest, INVOCATION_1)
    second = validated_workload(body, digest, INVOCATION_2)
    assert _composed(tmp_path, first) == ()
    assert _composed(tmp_path, second) == ()


def test_missing_file_composed_incomplete(tmp_path: Path) -> None:
    body = manifest([file_entry("inputs/gone.bin", DATA)])
    loaded = validated_workload(body, manifest_digest(body))
    kinds = triples(_composed(tmp_path, loaded))
    assert kinds == [("INCOMPLETE", "V-B13", "$.input_manifest.entries[0]")]


def test_no_consumption_or_verdict_claims(tmp_path: Path) -> None:
    """Valid verification must never imply consumption or a verdict."""
    stage(tmp_path, {"inputs/data.bin": DATA})
    body = manifest([file_entry("inputs/data.bin", DATA)])
    loaded = validated_workload(body, manifest_digest(body))
    assert _composed(tmp_path, loaded) == ()
    sources = [Path(m.__file__).read_text() for m in (digest_mod, files_mod, manifest_mod)]
    assert any("never" in text and "consum" in text for text in sources)
    for source in sources:
        assert "attest_core.verdicts" not in source
        assert "canonical_bytes" not in source
        assert "verdict" not in source.lower()


def test_p0_workload_strictness_inherited() -> None:
    """P4 inherits P0 shape strictness; it does not reimplement it."""
    good = {
        "workload_class": "Medium",
        "workload_id": "w-1",
        "input_digest": EMPTY_DIGEST,
        "input_manifest": manifest(),
    }
    validate_workload(dict(good), "7.4", "$")
    for bad_key, bad_value in (
        ("workload_id", ""),
        ("input_digest", "short"),
        ("workload_class", "Tiny"),
    ):
        bad = dict(good, **{bad_key: bad_value})
        with pytest.raises(F3Error) as caught:
            validate_workload(bad, "7.4", "$")
        assert caught.value.rule == "V-B6"
    with pytest.raises(F3Error) as caught:
        validate_workload({"workload_class": "Medium"}, "7.4", "$")
    assert caught.value.rule == "V-B6"


def test_regression_pins_and_p1_golden() -> None:
    assert (f3_digest.PROJECTION_NAME, f3_digest.PROJECTION_VERSION) == (
        "f3-digest-projection",
        1,
    )
    assert (f3_digest.CANONICAL_NAME, f3_digest.CANONICAL_VERSION) == (
        "attest-canonical-json",
        1,
    )
    here = Path(__file__).parent / "f3_vectors"
    record = canonical.parse_bytes((here / "v1_attempt.bin").read_bytes())
    listed = (here / "v1_attempt.sha").read_text().strip()
    check = f3_digest.verify_record_digest("attempt", record, listed)
    assert check.ok, check.reason


def test_regression_p2_and_p3(tmp_path: Path) -> None:
    assert check_identity(valid_package()).ok is True
    record = valid_attempt()
    packed = manifest_dict(records=[record_entry(record, "a.json")])
    root = write_package(tmp_path, packed, {"a.json": to_bytes(record)})
    assert verify_manifest(root).ok is True
