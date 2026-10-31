"""P1 unit tests: attest-canonical-json v1 value layer."""

from __future__ import annotations

import unicodedata

import pytest

from attest_sdk import canonical
from attest_sdk.errors import CanonicalizationError, LimitExceededError, ParseError

MAX_SAFE = 2**53 - 1
ASTRAL = "\U0001d11e"
BMP_E000 = "\ue000"
DECOMPOSED_E = "e\u0301"
COMPOSED_E = "\u00e9"


def test_compact_sorted_form() -> None:
    assert canonical.canonicalize({"b": 1, "a": [2, 1]}) == b'{"a":[2,1],"b":1}'


def test_scalar_literals() -> None:
    assert canonical.canonicalize(None) == b"null"
    assert canonical.canonicalize(True) == b"true"
    assert canonical.canonicalize(False) == b"false"
    assert canonical.canonicalize(0) == b"0"
    assert canonical.canonicalize(-7) == b"-7"


def test_utf16_key_order_astral_first() -> None:
    value = {BMP_E000: 0, ASTRAL: 1}
    assert canonical.canonicalize(value) == f'{{"{ASTRAL}":1,"{BMP_E000}":0}}'.encode()


def test_nfc_composes_decomposed_input() -> None:
    assert canonical.canonicalize(DECOMPOSED_E) == f'"{COMPOSED_E}"'.encode()


def test_nfc_key_collision_refuses() -> None:
    with pytest.raises(CanonicalizationError) as err:
        canonical.canonicalize({DECOMPOSED_E: 1, COMPOSED_E: 2})
    assert err.value.reason_class == "nfc-key-collision"


def test_escaping_short_and_unicode() -> None:
    assert canonical.canonicalize('a"\x01\\\x7f') == b'"a\\"\\u0001\\\\\x7f"'
    assert canonical.canonicalize("\b\f\n\r\t") == b'"\\b\\f\\n\\r\\t"'


@pytest.mark.parametrize("value", [MAX_SAFE, -MAX_SAFE])
def test_integer_bounds_accept(value: int) -> None:
    assert canonical.canonicalize(value) == str(value).encode()


@pytest.mark.parametrize("value", [MAX_SAFE + 1, -MAX_SAFE - 1])
def test_integer_bounds_refuse(value: int) -> None:
    with pytest.raises(CanonicalizationError) as err:
        canonical.canonicalize(value)
    assert err.value.reason_class == "integer-out-of-range"


@pytest.mark.parametrize("value", [1.5, 1.0, float("nan")])
def test_non_integer_numbers_refuse(value: float) -> None:
    with pytest.raises(CanonicalizationError) as err:
        canonical.canonicalize(value)
    assert err.value.reason_class == "non-integer-number"


def test_unsupported_values_refuse() -> None:
    with pytest.raises(CanonicalizationError) as err:
        canonical.canonicalize((1, 2))
    assert err.value.reason_class == "unsupported-value"
    with pytest.raises(CanonicalizationError) as err:
        canonical.canonicalize({1: "x"})
    assert err.value.reason_class == "unsupported-value"


def _nested(depth: int) -> object:
    value: object = 0
    for _ in range(depth):
        value = [value]
    return value


def test_depth_boundary() -> None:
    canonical.canonicalize(_nested(32))
    with pytest.raises(LimitExceededError) as err:
        canonical.canonicalize(_nested(33))
    assert err.value.reason_class == "limit-depth"
    assert err.value.limit == "depth"


def test_entries_boundary() -> None:
    canonical.canonicalize([0] * 4096)
    canonical.canonicalize({f"k{i}": 0 for i in range(4096)})
    with pytest.raises(LimitExceededError) as err:
        canonical.canonicalize([0] * 4097)
    assert err.value.reason_class == "limit-entries"


def test_string_boundary_counts_scalars() -> None:
    canonical.canonicalize("x" * 65536)
    canonical.canonicalize(ASTRAL * 65536)
    with pytest.raises(LimitExceededError) as err:
        canonical.canonicalize("x" * 65537)
    assert err.value.reason_class == "limit-string"


def test_output_boundary() -> None:
    canonical.canonicalize(["x" * 65536] * 120)
    with pytest.raises(LimitExceededError) as err:
        canonical.canonicalize(["x" * 65536] * 128)
    assert err.value.reason_class == "limit-output"


def test_source_size_boundary() -> None:
    canonical.check_source_size(bytes(1048576))
    with pytest.raises(LimitExceededError) as err:
        canonical.check_source_size(bytes(1048577))
    assert err.value.reason_class == "limit-source"


def test_decode_rejects_bom_and_bad_utf8() -> None:
    assert canonical.decode_source("á".encode()) == "á"
    with pytest.raises(ParseError) as err:
        canonical.decode_source(b"\xef\xbb\xbf{}")
    assert err.value.reason_class == "bom"
    with pytest.raises(ParseError) as err:
        canonical.decode_source(b'{"a": "\xff"}')
    assert err.value.reason_class == "invalid-utf8"


def test_digest_stable_and_absent_differs_from_empty() -> None:
    assert canonical.digest_of({"a": 1}) == canonical.digest_of({"a": 1})
    assert canonical.digest_of({"a": 1}) != canonical.digest_of({"a": 1, "b": {}})
    assert canonical.digest_of({"a": 1, "b": {}}) != canonical.digest_of({"a": 1, "b": ""})


def test_nfc_unavailable_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(canonical, "_NFC_OK", False)
    with pytest.raises(CanonicalizationError) as err:
        canonical.canonicalize("a")
    assert err.value.reason_class == "nfc-unavailable"


def test_unicode_version_declared() -> None:
    assert canonical.unicode_version() == (unicodedata.unidata_version or "unknown")


def test_parse_bytes_rejects_format() -> None:
    with pytest.raises(ValueError, match="unsupported format"):
        canonical.parse_bytes(b"{}", source_format="toml")
