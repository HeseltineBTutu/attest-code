"""P1 unit tests: YAML 1.2 core-schema conversion and bounded expansion."""

from __future__ import annotations

import pytest

from attest_sdk import canonical
from attest_sdk.errors import AttestError, LimitExceededError
from attest_sdk.yamlconv import yaml_to_value


@pytest.mark.parametrize(
    ("scalar", "want"),
    [
        ("yes", "yes"),
        ("Yes", "Yes"),
        ("on", "on"),
        ("true", True),
        ("True", True),
        ("FALSE", False),
        ("null", None),
        ("Null", None),
        ("~", None),
        ("12", 12),
        ("+4", 4),
        ("-0", 0),
        ("01", 1),
        ("0x1A", "0x1A"),
        ("0o17", "0o17"),
        ("1_000", "1_000"),
        ("2001-02-03", "2001-02-03"),
        ("1:2", "1:2"),
        ('"yes"', "yes"),
        ("'yes'", "yes"),
        ('"12"', "12"),
        ("!!str 123", "123"),
        ("!!int 12", 12),
        ("!!null ~", None),
    ],
)
def test_core_schema_scalars(scalar: str, want: object) -> None:
    assert yaml_to_value(f"k: {scalar}") == {"k": want}


def test_empty_value_is_null_and_blocks_are_strings() -> None:
    assert yaml_to_value("k:") == {"k": None}
    assert yaml_to_value("---\n") is None
    assert yaml_to_value("k: |\n  12\n") == {"k": "12\n"}
    assert yaml_to_value("k: >\n  a\n  b\n") == {"k": "a b\n"}


@pytest.mark.parametrize(
    ("scalar", "reason"),
    [
        ("1.5", "non-integer-number"),
        ("1e3", "non-integer-number"),
        (".inf", "non-integer-number"),
        (".nan", "non-integer-number"),
        ("!!bool yes", "invalid-scalar"),
        ("!!int 1.5", "invalid-scalar"),
        ("!foo bar", "unsupported-tag"),
        ("!!timestamp 2001-01-01", "unsupported-tag"),
    ],
)
def test_scalar_refusals(scalar: str, reason: str) -> None:
    with pytest.raises(AttestError) as err:
        yaml_to_value(f"k: {scalar}")
    assert err.value.reason_class == reason, scalar


def test_structures_and_aliases() -> None:
    assert yaml_to_value("12") == 12
    assert yaml_to_value("- 1\n- [2]\n") == [1, [2]]
    assert yaml_to_value("{a: 1, b: {c: [2]}}") == {"a": 1, "b": {"c": [2]}}
    assert yaml_to_value("- &a 1\n- *a\n") == [1, 1]
    assert yaml_to_value("x: &m {a: 1}\ny: *m\n") == {"x": {"a": 1}, "y": {"a": 1}}


def test_merge_key_has_no_special_meaning() -> None:
    value = yaml_to_value("base: &b {x: 1}\nchild: {<<: *b}\n")
    assert value == {"base": {"x": 1}, "child": {"<<": {"x": 1}}}


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("{a: 1, a: 2}", "duplicate-key"),
        ("a: 1\na: 2\n", "duplicate-key"),
        ("12: x", "non-string-key"),
        ("[a]: x", "non-scalar-key"),
        ("!foo [1]", "unsupported-tag"),
        ("!foo {a: 1}", "unsupported-tag"),
        ("- &a 1\n- &a 2\n", "malformed-yaml"),
        ("- *missing\n", "malformed-yaml"),
        ("- *later\n- &later 1\n", "malformed-yaml"),
        ("&a [*a]", "cyclic-alias"),
        ("k: &a [*a]", "cyclic-alias"),
        ("", "empty-document"),
        ("a: 1\n---\nb: 2\n", "multiple-documents"),
    ],
)
def test_structure_refusals(text: str, reason: str) -> None:
    with pytest.raises(AttestError) as err:
        yaml_to_value(text)
    assert err.value.reason_class == reason, text


def test_deep_yaml_refuses() -> None:
    yaml_to_value("[" * 32 + "0" + "]" * 32)
    with pytest.raises(LimitExceededError) as err:
        yaml_to_value("[" * 33 + "0" + "]" * 33)
    assert err.value.reason_class == "limit-depth"


def test_yaml_matches_json_canonical_bytes() -> None:
    doc = {"scope": ["/a"], "id": "X", "version": 2}
    from_json = canonical.canonicalize_bytes(b'{"id": "X", "version": 2, "scope": ["/a"]}')
    from_yaml = canonical.canonicalize_bytes(b"id: X\nversion: 2\nscope: [/a]\n", "yaml")
    assert from_json == from_yaml == canonical.canonicalize(doc)
