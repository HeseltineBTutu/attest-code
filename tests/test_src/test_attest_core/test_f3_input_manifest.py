"""F3 input-manifest value and digest checks (V-B13(a)(b))."""

from __future__ import annotations

from f3_input_pkg import (
    EMPTY_DIGEST,
    LITERAL_DIGEST,
    file_entry,
    literal_entry,
    manifest,
    workload,
)

from attest_core.f3_input_digest import manifest_digest, verify_workload_digest
from attest_core.f3_input_manifest import check_manifest_value

PIN = {"name": "attest-canonical-json", "version": 1}


def test_empty_manifest_valid() -> None:
    assert check_manifest_value(manifest()) == ()
    assert manifest_digest(manifest()) == EMPTY_DIGEST


def test_golden_literal_digest() -> None:
    assert manifest_digest(manifest([literal_entry()])) == LITERAL_DIGEST


def test_version_refused() -> None:
    for bad in (2, 0, "1", None):
        (finding,) = check_manifest_value(manifest([], version=bad))
        assert (finding.severity, finding.rule) == ("INVALID", "V-B13")
        assert finding.location == "$.manifest_version"
    (finding,) = check_manifest_value(["not", "an", "object"])
    assert (finding.severity, finding.rule) == ("INVALID", "V-B6")


def test_unsorted_entries_rejected() -> None:
    bad = manifest([file_entry("inputs/b.bin"), file_entry("inputs/a.bin")])
    (finding,) = check_manifest_value(bad)
    assert (finding.severity, finding.rule) == ("INVALID", "V-B13")
    assert "sorted byte-wise" in finding.reason


def test_duplicate_entries_rejected() -> None:
    bad = manifest([file_entry(), file_entry()])
    (finding,) = check_manifest_value(bad)
    assert (finding.severity, finding.rule) == ("INVALID", "V-B13")
    assert "entries[0]" in finding.reason and "duplicate" in finding.reason


def test_conflicting_entries_rejected() -> None:
    first = file_entry("inputs/x.bin", b"aaa")
    second = file_entry("inputs/x.bin", b"bbb")
    (finding,) = check_manifest_value(manifest([first, second]))
    assert finding.rule == "V-B13"


def test_cross_kind_order() -> None:
    bad = manifest([literal_entry(), file_entry()])
    (finding,) = check_manifest_value(bad)
    assert finding.rule == "V-B13"
    good = manifest([file_entry(), literal_entry()])
    assert check_manifest_value(good) == ()


def test_file_literal_same_name_ok() -> None:
    good = manifest([file_entry("seed"), literal_entry("seed")])
    assert check_manifest_value(good) == ()


def test_bad_relpaths_rejected() -> None:
    for bad_path in ("/abs/path", "../escape", "a//b", ""):
        (finding,) = check_manifest_value(manifest([file_entry(bad_path)]))
        assert (finding.severity, finding.rule) == ("INVALID", "V-P1")


def test_digest_mismatch() -> None:
    stated = workload(manifest([literal_entry(value="abc")]))
    tampered = dict(stated)
    tampered["input_manifest"] = manifest([literal_entry(value="abd")])
    (finding,) = verify_workload_digest(tampered)
    assert (finding.severity, finding.rule) == ("INVALID", "V-B13")
    assert finding.location == "$.input_digest"


def test_changed_entry_identity_mismatches() -> None:
    stated = workload(manifest([literal_entry("seed")]))
    tampered = dict(stated)
    tampered["input_manifest"] = manifest([literal_entry("seed2")])
    (finding,) = verify_workload_digest(tampered)
    assert finding.rule == "V-B13"


def test_reordered_entries_digest_differs() -> None:
    first = manifest([file_entry("inputs/a.bin"), file_entry("inputs/b.bin")])
    second = manifest([file_entry("inputs/b.bin"), file_entry("inputs/a.bin")])
    assert manifest_digest(first) != manifest_digest(second)


def test_equivalent_canonical_forms() -> None:
    ordered = {"manifest_version": 1, "entries": [{"kind": "literal", "name": "s", "value": "v"}]}
    shuffled = {"entries": [{"value": "v", "name": "s", "kind": "literal"}], "manifest_version": 1}
    assert manifest_digest(ordered) == manifest_digest(shuffled)


def test_malformed_declared_digest_mismatches() -> None:
    stated = workload(manifest(), digest="not-a-digest")
    (finding,) = verify_workload_digest(stated)
    assert (finding.severity, finding.rule) == ("INVALID", "V-B13")


def test_canonicalizer_pin() -> None:
    stated = workload(manifest())
    assert verify_workload_digest(stated, canonical_pin=PIN) == ()
    bad_pins = ({"name": "attest-canonical-json", "version": 2}, {"name": "other", "version": 1})
    for bad_pin in bad_pins:
        (finding,) = verify_workload_digest(stated, canonical_pin=bad_pin)
        assert (finding.severity, finding.rule) == ("INVALID", "V-B6")


def test_malformed_manifest_shapes() -> None:
    (finding,) = check_manifest_value({"manifest_version": 1})
    assert finding.rule == "V-B6"
    (finding,) = check_manifest_value(manifest(["nope"]))
    assert finding.rule == "V-B6"
    (finding,) = check_manifest_value(manifest([{"kind": "device"}]))
    assert finding.rule == "V-B6"
    assert verify_workload_digest(["nope"]) != ()
