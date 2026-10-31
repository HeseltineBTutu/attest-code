"""P1 unit tests: invariant schema, loading, and content digests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from attest_sdk import canonical, documents, schema
from attest_sdk.documents import Invariant
from attest_sdk.errors import (
    SchemaError,
    UnknownVerificationTypeError,
    UnsupportedSpecVersionError,
)

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "attest-spec" / "v1" / "vectors"
AUTH_INPUT = VECTORS / "canonical" / "auth-admin-001.input.json"
AUTH_DIGEST = "686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8"
AUTH_DOC_DIGEST = "219bf343a5a6b9e3127b812b7ddf8e917e6ad919674dacbbedfb6f513f92fa54"


def _minimal() -> dict[str, Any]:
    return {
        "spec_version": 1,
        "id": "X-001",
        "version": 1,
        "title": "T",
        "requirement": "R",
        "scope": ["/a"],
        "invariant_type": "security.access-control",
        "verification_type": "http-auth-probe/1",
    }


def test_minimal_and_auth_fixture_validate() -> None:
    schema.validate_document(_minimal())
    value = canonical.parse_bytes(AUTH_INPUT.read_bytes())
    assert isinstance(value, dict)
    schema.validate_document(value)


@pytest.mark.parametrize(
    "field",
    [
        "spec_version",
        "id",
        "version",
        "title",
        "requirement",
        "scope",
        "invariant_type",
        "verification_type",
    ],
)
def test_missing_required_field(field: str) -> None:
    value = _minimal()
    del value[field]
    with pytest.raises(SchemaError):
        schema.validate_document(value)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("id", 1),
        ("id", ""),
        ("title", None),
        ("version", "1"),
        ("version", 0),
        ("version", True),
        ("version", 1.5),
        ("scope", {}),
        ("scope", []),
        ("scope", [""]),
        ("scope", ["a", 1]),
        ("spec_version", "1"),
        ("spec_version", True),
        ("spec_version", None),
        ("description", 1),
        ("parameters", []),
        ("evidence_expectations", "x"),
        ("applicability", 5),
        ("publisher", 7),
        ("metadata", []),
        ("invariant_type", "Security"),
        ("invariant_type", "a..b"),
        ("invariant_type", ""),
        ("publisher", ""),
        ("publisher", "UPPER"),
        ("publisher", "a..b"),
    ],
)
def test_malformed_fields(field: str, bad: object) -> None:
    value = _minimal()
    value[field] = bad
    with pytest.raises(SchemaError):
        schema.validate_document(value)


def test_unsupported_spec_version() -> None:
    value = _minimal()
    value["spec_version"] = 2
    with pytest.raises(UnsupportedSpecVersionError):
        schema.validate_document(value)


@pytest.mark.parametrize("taxonomy", ["security", "a1.b-2.c3", "teapot.brewing"])
def test_unknown_wellformed_taxonomy_preserved(taxonomy: str) -> None:
    value = _minimal()
    value["invariant_type"] = taxonomy
    schema.validate_document(value)


@pytest.mark.parametrize("field", ["foo", "verifier_ref", "status", "approved", "approval"])
def test_rejected_fields(field: str) -> None:
    value = _minimal()
    value[field] = 1
    with pytest.raises(SchemaError):
        schema.validate_document(value)


def test_extension_fields_accepted() -> None:
    value = _minimal()
    value["x-custom"] = {"a": [1, "x", None, True]}
    schema.validate_document(value)


def test_verification_type_gate() -> None:
    value = _minimal()
    value["verification_type"] = "teapot.brew/9"
    schema.validate_document(value)
    loaded = documents.load_invariant(canonical.canonicalize(value))
    with pytest.raises(UnknownVerificationTypeError):
        documents.ensure_known_verification_type(loaded)
    known = documents.load_invariant(canonical.canonicalize(_minimal()))
    documents.ensure_known_verification_type(known)


def test_load_invariant_sources() -> None:
    from_bytes = documents.load_invariant(AUTH_INPUT.read_bytes())
    from_path = documents.load_invariant(AUTH_INPUT)
    assert from_bytes == from_path
    assert isinstance(from_bytes, Invariant)
    assert from_bytes.invariant_id == "AUTH-ADMIN-001"
    assert from_bytes.scope == ("/admin/users", "/admin/settings")
    yaml_text = (
        "spec_version: 1\nid: X-001\nversion: 1\ntitle: T\nrequirement: R\n"
        "scope: [/a]\ninvariant_type: security.access-control\n"
        "verification_type: http-auth-probe/1\n"
    )
    from_yaml = documents.load_invariant(yaml_text.encode(), source_format="yaml")
    assert from_yaml.invariant_id == "X-001"
    assert documents.invariant_digest(from_yaml) == _digest_of_doc(_minimal())
    with pytest.raises(ValueError, match="unsupported format"):
        documents.load_invariant(b"{}", source_format="toml")
    with pytest.raises(FileNotFoundError):
        documents.load_invariant(VECTORS / "nope.json")


def test_auth_content_digest_and_doc_digest() -> None:
    invariant = documents.load_invariant(AUTH_INPUT)
    assert documents.invariant_digest(invariant) == AUTH_DIGEST
    assert canonical.digest_bytes(AUTH_INPUT.read_bytes()) == AUTH_DOC_DIGEST


def _digest_of_doc(value: dict[str, Any]) -> str:
    loaded = documents.load_invariant(canonical.canonicalize(value))
    return documents.invariant_digest(loaded)


def test_digest_projection_excludes_publisher_and_metadata() -> None:
    base = _digest_of_doc(_minimal())
    assert base == _digest_of_doc(_minimal())
    changed_meta = _minimal()
    changed_meta["publisher"] = "someone.else"
    changed_meta["metadata"] = {"k": "v"}
    assert _digest_of_doc(changed_meta) == base
    changed_req = _minimal()
    changed_req["requirement"] = "different"
    assert _digest_of_doc(changed_req) != base


def test_absent_differs_from_empty_and_x_is_covered() -> None:
    base = _digest_of_doc(_minimal())
    empty_desc = _minimal()
    empty_desc["description"] = ""
    assert _digest_of_doc(empty_desc) != base
    extended = _minimal()
    extended["x-note"] = "n"
    assert _digest_of_doc(extended) != base
