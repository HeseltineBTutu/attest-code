"""Registry layout discovery, history folds, and joint eligibility."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, TypeVar

from attest_sdk import canonical, chains, events
from attest_sdk.errors import (
    AmbiguousHistoryError,
    AttestError,
    EligibilityError,
    NoApprovalError,
    RegistryError,
    RevokedApprovalError,
    SchemaError,
)
from attest_sdk.events import ApprovalEvent, LifecycleEvent

_EVENT_FILE_RE: Final = re.compile(r"[0-9a-f]{64}\.json")
_HEX64: Final = re.compile(r"[0-9a-f]{64}")
_TRANSITIONS: Final = {
    ("draft", "ACTIVATE"): "active",
    ("active", "DEPRECATE"): "deprecated",
    ("active", "SUPERSEDE"): "superseded",
    ("deprecated", "SUPERSEDE"): "superseded",
    ("active", "REVOKE_INVARIANT"): "revoked",
    ("deprecated", "REVOKE_INVARIANT"): "revoked",
}


@dataclasses.dataclass(frozen=True)
class ApprovalHistory:
    """Validated approval chain in oldest-first order plus stray reports."""

    events: tuple[ApprovalEvent, ...]
    reported: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class LifecycleHistory:
    """Validated lifecycle chain in oldest-first order plus stray reports."""

    events: tuple[LifecycleEvent, ...]
    reported: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Policy:
    """Evaluation policy: lifecycle strictness, digest requirements."""

    strict_deprecated: bool = False
    require_artifact_digest: bool = False

    def __post_init__(self) -> None:
        for field in ("strict_deprecated", "require_artifact_digest"):
            if not isinstance(getattr(self, field), bool):
                raise SchemaError(f"policy.{field} must be a boolean")


@dataclasses.dataclass(frozen=True)
class Eligibility:
    """Successful joint evaluation: approval id, state, warnings."""

    approval_event_id: str
    lifecycle_state: str
    warnings: tuple[str, ...] = ()


_DEFAULT_POLICY: Final = Policy()

_D = TypeVar("_D", ApprovalEvent, LifecycleEvent)


class Registry:
    """A registry rooted at one materialized state (path)."""

    def __init__(self, root: Path) -> None:
        if not root.is_dir():
            raise RegistryError(f"registry root is not a directory: {root}")
        self._root = root

    def _chain_dir(self, kind: str, invariant_id: str, version: int) -> Path:
        if not isinstance(invariant_id, str) or not invariant_id:
            raise ValueError("invariant_id must be a non-empty string")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValueError("version must be an integer >= 1")
        return self._root / "registry" / kind / invariant_id / str(version)

    def _read_file(self, path: Path) -> Any:
        try:
            return canonical.parse_bytes(path.read_bytes())
        except OSError as exc:
            raise RegistryError(f"cannot read registry file: {path}") from exc
        except AttestError as exc:
            raise AmbiguousHistoryError(str(exc), reason_class=exc.reason_class) from exc

    def _discover(
        self, chain_dir: Path, parse: Callable[[object], _D]
    ) -> tuple[list[_D], tuple[str, ...]]:
        """Parse event files; strays reported, subdirectories ignored."""
        if not chain_dir.exists():
            return [], ()
        try:
            names = sorted(entry.name for entry in chain_dir.iterdir() if entry.is_file())
        except OSError as exc:
            raise RegistryError(f"cannot list registry dir: {chain_dir}") from exc
        found: list[_D] = []
        strays: list[str] = []
        for name in names:
            if _EVENT_FILE_RE.fullmatch(name) is None:
                strays.append(name)
                continue
            event = parse(self._read_file(chain_dir / name))
            if event.event_id != name[:-5]:
                raise AmbiguousHistoryError(
                    "filename/event_id mismatch", reason_class="filename-mismatch"
                )
            found.append(event)
        return found, tuple(strays)

    def approval_chain(self, invariant_id: str, version: int) -> ApprovalHistory:
        """Load and validate one approval chain (oldest first)."""
        chain_dir = self._chain_dir("approvals", invariant_id, version)
        found, reported = self._discover(chain_dir, events.parse_approval_event)
        ordered = chains.order_chain(found, invariant_id=invariant_id, version=version)
        return ApprovalHistory(ordered, reported)

    def lifecycle_chain(self, invariant_id: str, version: int) -> LifecycleHistory:
        """Load and validate one lifecycle chain (oldest first)."""
        chain_dir = self._chain_dir("lifecycle", invariant_id, version)
        found, reported = self._discover(chain_dir, events.parse_lifecycle_event)
        ordered = chains.order_chain(found, invariant_id=invariant_id, version=version)
        return LifecycleHistory(ordered, reported)

    def effective_approval(
        self, invariant_id: str, version: int, definition_digest: str
    ) -> ApprovalEvent:
        """Fold to the effective APPROVE; raises when none applies."""
        if not isinstance(definition_digest, str) or _HEX64.fullmatch(definition_digest) is None:
            raise ValueError("definition_digest must be a 64-hex digest")
        candidate: ApprovalEvent | None = None
        saw_approve = False
        history = self.approval_chain(invariant_id, version)
        for event in history.events:
            if event.invariant_digest != definition_digest:
                continue
            if event.event_type == "APPROVE":
                candidate = event
                saw_approve = True
            elif event.event_type == "REVOKE_APPROVAL":
                candidate = None
        if candidate is not None:
            return candidate
        if saw_approve:
            raise RevokedApprovalError(
                f"approval withdrawn for {invariant_id}/{version}", reason_class="revoked-approval"
            )
        raise NoApprovalError(
            f"no approval for {invariant_id}/{version}", reason_class="no-approval"
        )

    def lifecycle_state(self, invariant_id: str, version: int) -> str:
        """Fold lifecycle transitions; empty history is draft."""
        history = self.lifecycle_chain(invariant_id, version)
        state = "draft"
        for event in history.events:
            key = (state, event.event_type)
            if key not in _TRANSITIONS:
                raise AmbiguousHistoryError("invalid transition", reason_class="invalid-transition")
            state = _TRANSITIONS[key]
        return state

    def check_eligible(
        self,
        invariant_id: str,
        version: int,
        definition_digest: str,
        policy: Policy = _DEFAULT_POLICY,
    ) -> Eligibility:
        """Joint approval+lifecycle evaluation; raises when not eligible."""
        state = self.lifecycle_state(invariant_id, version)
        if state in ("revoked", "draft", "superseded"):
            raise EligibilityError(
                f"{invariant_id}/{version} is {state}", reason_class=f"lifecycle-{state}"
            )
        approval = self.effective_approval(invariant_id, version, definition_digest)
        if state == "deprecated" and policy.strict_deprecated:
            raise EligibilityError(
                f"{invariant_id}/{version} is deprecated",
                reason_class="lifecycle-deprecated-strict",
            )
        warnings = ("deprecated",) if state == "deprecated" else ()
        return Eligibility(approval.event_id, state, warnings)
