"""F3 error model: structured rule/section/location diagnostics.

Every failure names the design rule, document section, and field
location so validators can report precisely. Pure data only.
"""

from __future__ import annotations


class F3Error(Exception):
    """Base F3 failure with design-traceable diagnostics."""

    def __init__(self, *, rule: str, section: str, location: str, reason: str) -> None:
        super().__init__(f"[{rule} §{section} {location}] {reason}")
        self.rule = rule
        self.section = section
        self.location = location
        self.reason = reason


class F3ParseError(F3Error):
    """Source bytes failed strict parsing (rule PARSE, §8.2)."""


class F3SchemaError(F3Error):
    """A parsed value violates its record schema (rule V-B6)."""


class F3IncompleteError(F3Error):
    """Evidence is missing or unobtainable: a gap, not a contradiction."""
