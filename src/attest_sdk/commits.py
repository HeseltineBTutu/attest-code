"""Structured immutable registry references (§11, O2).

A commit is identified by ``vcs`` plus a full-length lowercase
hex object id only. The optional ``ref`` hint is preserved and
MUST be ignored for resolution: branches and tags never resolve.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from typing import Any, Final

from attest_sdk.errors import AttestationError

_OID: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


@dataclasses.dataclass(frozen=True)
class RegistryCommit:
    """Structured immutable registry reference; ``ref`` never resolves."""

    vcs: str
    commit: str
    ref: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.vcs, str) or not self.vcs:
            raise AttestationError("registry_commit.vcs must be a non-empty string")
        if not isinstance(self.commit, str) or _OID.fullmatch(self.commit) is None:
            raise AttestationError("registry_commit.commit must be a 40- or 64-hex id")
        if self.ref is not None and (not isinstance(self.ref, str) or not self.ref):
            raise AttestationError("registry_commit.ref must be a non-empty string")

    @classmethod
    def from_wire(cls, value: object) -> RegistryCommit:
        """Parse a wire object; unknown vcs values are preserved, not refused."""
        if not isinstance(value, Mapping):
            raise AttestationError("registry_commit must be an object")
        unknown = set(value) - {"vcs", "commit", "ref"}
        if unknown:
            raise AttestationError(f"unknown registry_commit field: {sorted(unknown)[0]!r}")
        for field in ("vcs", "commit"):
            if field not in value:
                raise AttestationError(f"registry_commit missing field: {field}")
        return cls(vcs=value["vcs"], commit=value["commit"], ref=value.get("ref"))

    def to_wire(self) -> dict[str, Any]:
        """Serialize; ``ref`` is omitted when absent, never defaulted."""
        payload: dict[str, Any] = {"vcs": self.vcs, "commit": self.commit}
        if self.ref is not None:
            payload["ref"] = self.ref
        return payload
