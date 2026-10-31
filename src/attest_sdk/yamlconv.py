"""YAML 1.2 core-schema authoring input with bounded alias expansion."""

from __future__ import annotations

import re
from typing import Any, Final

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from attest_sdk.canonical import MAX_DEPTH, MAX_OUTPUT_BYTES
from attest_sdk.errors import LimitExceededError, ParseError

_STR_TAG: Final = "tag:yaml.org,2002:str"
_NULL_TAG: Final = "tag:yaml.org,2002:null"
_BOOL_TAG: Final = "tag:yaml.org,2002:bool"
_INT_TAG: Final = "tag:yaml.org,2002:int"
_FLOAT_TAG: Final = "tag:yaml.org,2002:float"
_SEQ_TAG: Final = "tag:yaml.org,2002:seq"
_MAP_TAG: Final = "tag:yaml.org,2002:map"
_NULL_SRC: Final = r"~|null|Null|NULL"
_BOOL_SRC: Final = r"true|True|TRUE|false|False|FALSE"
_INT_SRC: Final = r"[-+]?[0-9]+"
_FLOAT_SRC: Final = (
    r"[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?"
    r"|[-+]?\.(inf|Inf|INF)|\.(nan|NaN|NAN)"
)
_CORE_RULES: Final = (
    (_NULL_TAG, _NULL_SRC, "~nN"),
    (_BOOL_TAG, _BOOL_SRC, "tTfF"),
    (_INT_TAG, _INT_SRC, "-+0123456789"),
    (_FLOAT_TAG, _FLOAT_SRC, "-+.0123456789"),
)
_NULL_RE: Final = re.compile(f"(?:{_NULL_SRC})?")
_BOOL_RE: Final = re.compile(_BOOL_SRC)
_INT_RE: Final = re.compile(_INT_SRC)
_FLOAT_RE: Final = re.compile(_FLOAT_SRC)


def _core_resolvers() -> dict[str, list[tuple[str, re.Pattern[str]]]]:
    """Build the first-character index of core implicit resolvers."""
    table: dict[str, list[tuple[str, re.Pattern[str]]]] = {"": [(_NULL_TAG, re.compile(r"\A\Z"))]}
    for tag, source, first in _CORE_RULES:
        pattern = re.compile(f"\\A(?:{source})\\Z")
        for char in first:
            table.setdefault(char, []).append((tag, pattern))
    return table


class _CoreLoader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2 core-schema implicit resolution."""


_CoreLoader.yaml_implicit_resolvers = _core_resolvers()


def _explicit_scalar(tag: str, value: str) -> Any:
    """Interpret one tagged scalar under core-schema lexical rules."""
    if tag == _STR_TAG:
        return value
    if tag == _NULL_TAG:
        if _NULL_RE.fullmatch(value) is None:
            raise ParseError(f"invalid null: {value!r}", reason_class="invalid-scalar")
        return None
    if tag == _BOOL_TAG:
        if _BOOL_RE.fullmatch(value) is None:
            raise ParseError(f"invalid bool: {value!r}", reason_class="invalid-scalar")
        return value.lower() == "true"
    if tag == _INT_TAG:
        if _INT_RE.fullmatch(value) is None:
            raise ParseError(f"invalid int: {value!r}", reason_class="invalid-scalar")
        return int(value, 10)
    if tag == _FLOAT_TAG:
        raise ParseError(f"non-integer scalar: {value!r}", reason_class="non-integer-number")
    raise ParseError(f"unsupported tag: {tag}", reason_class="unsupported-tag")


def _classify_scalar(tag: str, style: str | None, value: str) -> Any:
    """Interpret one scalar node (explicit tags, else core resolution)."""
    if tag not in ("?", "!"):
        return _explicit_scalar(tag, value)
    if tag == "!" or style:
        return value
    if _NULL_RE.fullmatch(value):
        return None
    if _BOOL_RE.fullmatch(value):
        return value.lower() == "true"
    if _INT_RE.fullmatch(value):
        return int(value, 10)
    if _FLOAT_RE.fullmatch(value):
        raise ParseError(f"non-integer scalar: {value!r}", reason_class="non-integer-number")
    return value


def _scalar_length(value: object) -> int:
    """Lower-bound canonical length of one scalar; the final check is exact."""
    if isinstance(value, str):
        return len(value) + 2
    if value is None:
        return 4
    if isinstance(value, bool):
        return 5 if value else 4
    if isinstance(value, int):
        return len(str(value))
    raise AssertionError("unreachable scalar")


def _expand(node: Node, active: frozenset[int], depth: int, budget: int) -> tuple[object, int]:
    """Expand one node, threading ancestor ids, depth, and output budget."""
    if depth > MAX_DEPTH:
        raise LimitExceededError("depth")
    if isinstance(node, ScalarNode):
        scalar = _classify_scalar(node.tag, node.style, node.value)
        return scalar, budget + _scalar_length(scalar)
    if id(node) in active:
        raise ParseError("cyclic alias", reason_class="cyclic-alias")
    active = active | {id(node)}
    if isinstance(node, SequenceNode):
        return _expand_sequence(node, active, depth, budget)
    if isinstance(node, MappingNode):
        return _expand_mapping(node, active, depth, budget)
    raise ParseError(f"unsupported node: {node.tag}", reason_class="unsupported-node")


def _expand_sequence(
    node: SequenceNode, active: frozenset[int], depth: int, budget: int
) -> tuple[list[object], int]:
    """Expand sequence items with exact structural accounting."""
    if node.tag != _SEQ_TAG:
        raise ParseError(f"unsupported tag: {node.tag}", reason_class="unsupported-tag")
    items: list[object] = []
    budget += 1
    for child in node.value:
        if items:
            budget += 1
        item, budget = _expand(child, active, depth + 1, budget)
        items.append(item)
        if budget > MAX_OUTPUT_BYTES:
            raise LimitExceededError("output")
    return items, budget + 1


def _expand_mapping(
    node: MappingNode, active: frozenset[int], depth: int, budget: int
) -> tuple[dict[str, object], int]:
    """Expand mapping pairs; duplicate or non-string keys refuse."""
    if node.tag != _MAP_TAG:
        raise ParseError(f"unsupported tag: {node.tag}", reason_class="unsupported-tag")
    obj: dict[str, object] = {}
    budget += 1
    for key_node, item_node in node.value:
        if not isinstance(key_node, ScalarNode):
            raise ParseError("non-scalar key", reason_class="non-scalar-key")
        key = _classify_scalar(key_node.tag, key_node.style, key_node.value)
        if not isinstance(key, str):
            raise ParseError("non-string key", reason_class="non-string-key")
        if key in obj:
            raise ParseError("duplicate key", reason_class="duplicate-key")
        if obj:
            budget += 1
        budget += len(key) + 3
        item, budget = _expand(item_node, active, depth + 1, budget)
        obj[key] = item
        if budget > MAX_OUTPUT_BYTES:
            raise LimitExceededError("output")
    return obj, budget + 1


def yaml_to_value(text: str) -> Any:
    """Parse one YAML 1.2 core-schema document into the value model."""
    loader = _CoreLoader(text)
    try:
        try:
            nodes = []
            while loader.check_node():
                nodes.append(loader.get_node())
        except yaml.YAMLError as exc:
            raise ParseError(f"invalid YAML: {exc}", reason_class="malformed-yaml") from exc
        except RecursionError:
            raise LimitExceededError("depth") from None
    finally:
        loader.dispose()
    if not nodes:
        raise ParseError("empty YAML document", reason_class="empty-document")
    if len(nodes) > 1:
        raise ParseError("multiple YAML documents", reason_class="multiple-documents")
    if nodes[0] is None:
        raise ParseError("empty YAML document", reason_class="empty-document")
    try:
        value, _size = _expand(nodes[0], frozenset(), 0, 0)
    except RecursionError:
        raise LimitExceededError("depth") from None
    return value
