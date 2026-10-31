"""attest-canonical-json v1: canonical bytes, digests, and limits."""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Any, Final, NoReturn

from attest_sdk.errors import CanonicalizationError, LimitExceededError, ParseError

MAX_SOURCE_BYTES: Final = 1048576
MAX_DEPTH: Final = 32
MAX_STRING_CHARS: Final = 65536
MAX_ENTRIES: Final = 4096
MAX_OUTPUT_BYTES: Final = 8388608
_SAFE_INTEGER: Final = 2**53 - 1
_UTF8_BOM: Final = b"\xef\xbb\xbf"
_SHORT_ESCAPES: Final = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _nfc_available() -> bool:
    try:
        return unicodedata.normalize("NFC", "é") == "é"
    except Exception:
        return False


_NFC_OK: Final = _nfc_available()
UNICODE_VERSION: Final = str(getattr(unicodedata, "unidata_version", "") or "unknown")


def unicode_version() -> str:
    """Declared Unicode version of this normalizer (or "unknown")."""
    return UNICODE_VERSION


def check_source_size(data: bytes) -> None:
    """Refuse source documents over the byte limit."""
    if len(data) > MAX_SOURCE_BYTES:
        raise LimitExceededError("source")


def decode_source(data: bytes) -> str:
    """Strict UTF-8 decode with BOM rejection."""
    if data.startswith(_UTF8_BOM):
        raise ParseError("byte-order mark rejected", reason_class="bom")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(f"not strict UTF-8: {exc}", reason_class="invalid-utf8") from exc


def nfc_normalize(text: str) -> str:
    """NFC-normalize, refusing when normalization is unavailable."""
    if not _NFC_OK:
        raise CanonicalizationError("NFC unavailable", reason_class="nfc-unavailable")
    return unicodedata.normalize("NFC", text)


def _utf16_units(text: str) -> tuple[int, ...]:
    units: list[int] = []
    for char in text:
        point = ord(char)
        if point < 0x10000:
            units.append(point)
        else:
            point -= 0x10000
            units.append(0xD800 + (point >> 10))
            units.append(0xDC00 + (point & 0x3FF))
    return tuple(units)


def escape_text(text: str) -> str:
    """Serialize one string as a canonical JSON literal, quotes included."""
    parts = ['"']
    for char in text:
        special = _SHORT_ESCAPES.get(char)
        if special is not None:
            parts.append(special)
        elif ord(char) < 0x20:
            parts.append(f"\\u{ord(char):04x}")
        else:
            parts.append(char)
    parts.append('"')
    return "".join(parts)


def _refuse(message: str, reason: str) -> NoReturn:
    raise CanonicalizationError(message, reason_class=reason)


def _serialize(value: object, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        raise LimitExceededError("depth")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > _SAFE_INTEGER:
            _refuse(f"integer out of range: {value}", "integer-out-of-range")
        return str(value)
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            raise LimitExceededError("string")
        return escape_text(nfc_normalize(value))
    if isinstance(value, list):
        if len(value) > MAX_ENTRIES:
            raise LimitExceededError("entries")
        return "[" + ",".join(_serialize(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        if len(value) > MAX_ENTRIES:
            raise LimitExceededError("entries")
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _refuse(f"non-string key: {key!r}", "unsupported-value")
            nfc_key = nfc_normalize(key)
            if nfc_key in normalized:
                _refuse(f"NFC key collision: {nfc_key!r}", "nfc-key-collision")
            normalized[nfc_key] = item
        parts = [
            f"{escape_text(key)}:{_serialize(normalized[key], depth + 1)}"
            for key in sorted(normalized, key=_utf16_units)
        ]
        return "{" + ",".join(parts) + "}"
    if isinstance(value, float):
        _refuse(f"non-integer number: {value!r}", "non-integer-number")
    _refuse(f"unsupported value: {type(value).__name__}", "unsupported-value")


def canonicalize(value: object) -> bytes:
    """Canonical bytes for a value-model object (no source limit applies)."""
    text = _serialize(value)
    try:
        out = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(
            f"unencodable string: {exc}", reason_class="unencodable-string"
        ) from exc
    if len(out) > MAX_OUTPUT_BYTES:
        raise LimitExceededError("output")
    return out


def parse_bytes(data: bytes, source_format: str = "json") -> Any:
    """Strict-parse source bytes into the value model (limits enforced)."""
    if source_format not in ("json", "yaml"):
        raise ValueError(f"unsupported format: {source_format!r}")
    check_source_size(data)
    text = decode_source(data)
    if source_format == "yaml":
        from attest_sdk import yamlconv

        return yamlconv.yaml_to_value(text)
    from attest_sdk import jsonparse

    return jsonparse.parse_json(text)


def canonicalize_bytes(data: bytes, source_format: str = "json") -> bytes:
    """Canonical bytes for source bytes in the given format."""
    return canonicalize(parse_bytes(data, source_format=source_format))


def digest_of(value: object) -> str:
    """SHA-256 hex over canonical bytes of a value."""
    return hashlib.sha256(canonicalize(value)).hexdigest()


def digest_bytes(data: bytes, source_format: str = "json") -> str:
    """SHA-256 hex over canonical bytes of source bytes."""
    return hashlib.sha256(canonicalize_bytes(data, source_format=source_format)).hexdigest()
