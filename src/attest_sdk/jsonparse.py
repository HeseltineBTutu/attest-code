"""Strict JSON parser for the frozen canonical-JSON input domain."""

import re
from typing import Any, Final, NoReturn

from attest_sdk.canonical import MAX_DEPTH
from attest_sdk.errors import LimitExceededError, ParseError

_HEX: Final = re.compile(r"[0-9a-fA-F]{4}")
_ESCAPES: Final = {
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    '"': '"',
    "\\": "\\",
    "/": "/",
}
_LITERALS: Final = {"t": ("true", True), "f": ("false", False), "n": ("null", None)}


class _Scanner:
    """Single-pass scanner with explicit cursor; failures raise ParseError."""

    def __init__(self) -> None:
        self.text = ""
        self.length = 0
        self.pos = 0

    def parse_json(self, text: str) -> Any:
        """Parse one JSON value; trailing data refuses."""
        self.text = text
        self.length = len(text)
        self.pos = 0
        self._ws()
        if self.pos >= self.length:
            self._fail("empty document", "empty-document")
        value = self._value(0)
        self._ws()
        if self._peek() != "":
            self._fail("trailing data", "trailing-data")
        return value

    def _fail(self, message: str, reason: str) -> NoReturn:
        raise ParseError(f"{message} at offset {self.pos}", reason_class=reason)

    def _peek(self) -> str:
        return "" if self.pos >= self.length else self.text[self.pos]

    def _take(self) -> str:
        if self.pos >= self.length:
            self._fail("unexpected end of input", "unexpected-end")
        char = self.text[self.pos]
        self.pos += 1
        return char

    def _ws(self) -> None:
        while self._peek() in (" ", "\t", "\n", "\r"):
            self.pos += 1

    def _value(self, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise LimitExceededError("depth")
        char = self._peek()
        if char == "":
            self._fail("unexpected end of input", "unexpected-end")
        if char == "{":
            return self._object(depth)
        if char == "[":
            return self._array(depth)
        if char == '"':
            return self._string()
        if char in ("-", "+") or "0" <= char <= "9":
            return self._number()
        if char in _LITERALS:
            return self._literal(*_LITERALS[char])
        if "a" <= char <= "z" or "A" <= char <= "Z":
            self._fail("non-JSON constant", "non-json-constant")
        self._fail(f"unexpected value: {char!r}", "unexpected-value")

    def _object(self, depth: int) -> dict[str, Any]:
        self._take()  # opening brace
        obj: dict[str, Any] = {}
        self._ws()
        if self._peek() == "}":
            self._take()
            return obj
        while True:
            self._ws()
            key = self._string()
            if key in obj:
                self._fail("duplicate key", "duplicate-key")
            self._ws()
            if self._take() != ":":
                self._fail("expected ':'", "expected-colon")
            self._ws()
            obj[key] = self._value(depth + 1)
            self._ws()
            char = self._take()
            if char == "}":
                return obj
            if char != ",":
                self._fail("expected ',' or '}'", "expected-comma")

    def _array(self, depth: int) -> list[Any]:
        self._take()  # opening bracket
        items: list[Any] = []
        self._ws()
        if self._peek() == "]":
            self._take()
            return items
        while True:
            self._ws()
            items.append(self._value(depth + 1))
            self._ws()
            char = self._take()
            if char == "]":
                return items
            if char != ",":
                self._fail("expected ',' or ']'", "expected-comma")

    def _string(self) -> str:
        if self._take() != '"':
            self._fail("expected opening quote", "expected-quote")
        out: list[str] = []
        while True:
            if self.pos >= self.length:
                self._fail("unterminated string", "unterminated-string")
            char = self.text[self.pos]
            if char == '"':
                self.pos += 1
                return "".join(out)
            if char == "\\":
                self.pos += 1
                out.append(self._escape())
                continue
            if char < " ":
                self._fail("unescaped control", "unescaped-control")
            out.append(char)
            self.pos += 1

    def _escape(self) -> str:
        char = self._take()
        if char in _ESCAPES:
            return _ESCAPES[char]
        if char != "u":
            self._fail(f"bad escape: {char!r}", "bad-escape")
        return self._unicode_escape()

    def _unicode_escape(self) -> str:
        lead = self._hex4()
        if lead < 0xD800 or lead > 0xDFFF:
            return chr(lead)
        if lead >= 0xDC00:
            self._fail("lone low surrogate", "lone-surrogate")
        if self._take() != "\\" or self._take() != "u":
            self._fail("lone high surrogate", "lone-surrogate")
        trail = self._hex4()
        if trail < 0xDC00 or trail > 0xDFFF:
            self._fail("lone high surrogate", "lone-surrogate")
        return chr(0x10000 + ((lead - 0xD800) << 10) + (trail - 0xDC00))

    def _hex4(self) -> int:
        digits = self.text[self.pos : self.pos + 4]
        if _HEX.fullmatch(digits) is None:
            self._fail("bad unicode escape", "bad-escape")
        self.pos += 4
        return int(digits, 16)

    def _number(self) -> int:
        first = self._take()
        if first in ("-", "+") and self.text.startswith("Infinity", self.pos):
            self._fail("non-JSON constant", "non-json-constant")
        digits = [first]
        while "0" <= self._peek() <= "9":
            digits.append(self._take())
        if first == "+":
            self._fail("leading plus in number", "bad-number")
        text = "".join(digits)
        bare = text[1:] if first == "-" else text
        if not bare:
            self._fail("bad number", "bad-number")
        if len(bare) > 1 and bare.startswith("0"):
            self._fail("leading zero", "leading-zero")
        if self._peek() in (".", "e", "E"):
            self._fail("non-integer number", "non-integer-number")
        return int(text, 10)

    def _literal(self, word: str, value: object) -> object:
        for char in word:
            if self._take() != char:
                self._fail("bad literal", "bad-literal")
        return value


def parse_json(text: str) -> Any:
    """Parse one strict JSON value (no NaN/Infinity, no duplicates)."""
    return _Scanner().parse_json(text)
