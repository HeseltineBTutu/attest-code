"""P2 unit tests: registry discovery, folds, and joint eligibility."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attest_sdk import canonical
from attest_sdk.errors import (
    AmbiguousHistoryError,
    EligibilityError,
    NoApprovalError,
    RegistryError,
    RevokedApprovalError,
)
from attest_sdk.registry import Policy, Registry

DIGEST = "686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8"
OTHER = "0" * 64


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    inner = {key: item for key, item in payload.items() if key != "event_id"}
    payload["event_id"] = canonical.digest_of(inner)
    return payload


def _approve(seq: int, prev: str | None, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "seq": seq,
        "prev": prev,
        "invariant_id": "X",
        "invariant_version": 1,
        "invariant_digest": DIGEST,
        "event_type": "APPROVE",
        "approver": "A",
        "method": "cli-review",
        "timestamp": "2026-10-31T00:00:00+00:00",
    }
    base.update(over)
    return _seal(base)


def _life(seq: int, prev: str | None, event_type: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "seq": seq,
        "prev": prev,
        "invariant_id": "X",
        "invariant_version": 1,
        "event_type": event_type,
        "actor": "A",
        "timestamp": "2026-10-31T00:00:00+00:00",
    }
    base.update(over)
    return _seal(base)


def _write(root: Path, kind: str, files: dict[str, bytes]) -> Registry:
    chain_dir = root / "registry" / kind / "X" / "1"
    chain_dir.mkdir(parents=True)
    for name, data in files.items():
        (chain_dir / name).write_bytes(data)
    return Registry(root)


def _chain_bytes(*events: dict[str, Any]) -> dict[str, bytes]:
    return {f"{event['event_id']}.json": canonical.canonicalize(event) for event in events}


def test_root_and_argument_validation(tmp_path: Path) -> None:
    with pytest.raises(RegistryError):
        Registry(tmp_path / "missing")
    with pytest.raises(ValueError, match="version"):
        Registry(tmp_path).approval_chain("X", 0)
    with pytest.raises(ValueError, match="invariant_id"):
        Registry(tmp_path).approval_chain("", 1)
    with pytest.raises(ValueError, match="definition_digest"):
        Registry(tmp_path).effective_approval("X", 1, "zz")


def test_missing_dirs_are_empty_not_errors(tmp_path: Path) -> None:
    reg = Registry(tmp_path)
    assert reg.approval_chain("X", 1).events == ()
    assert reg.lifecycle_state("X", 1) == "draft"
    with pytest.raises(NoApprovalError) as err:
        reg.effective_approval("X", 1, DIGEST)
    assert err.value.reason_class == "no-approval"


def test_strays_reported_subdirs_ignored(tmp_path: Path) -> None:
    genesis = _approve(0, None)
    reg = _write(tmp_path, "approvals", {**_chain_bytes(genesis), "README.txt": b"hi"})
    sub = tmp_path / "registry" / "approvals" / "X" / "1" / "nested"
    sub.mkdir()
    (sub / f"{genesis['event_id']}.json").write_bytes(canonical.canonicalize(genesis))
    history = reg.approval_chain("X", 1)
    assert [event.seq for event in history.events] == [0]
    assert history.reported == ("README.txt",)
    upper = f"{genesis['event_id'].upper()}.json"
    reg2 = _write(tmp_path / "u", "approvals", {upper: canonical.canonicalize(genesis)})
    assert reg2.approval_chain("X", 1).events == ()
    assert reg2.approval_chain("X", 1).reported == (upper,)


def test_filename_mismatch_and_garbage_refuse(tmp_path: Path) -> None:
    genesis = _approve(0, None)
    reg = _write(tmp_path, "approvals", {f"{'0' * 64}.json": canonical.canonicalize(genesis)})
    with pytest.raises(AmbiguousHistoryError) as err:
        reg.approval_chain("X", 1)
    assert err.value.reason_class == "filename-mismatch"
    reg2 = _write(tmp_path / "g", "approvals", {f"{'0' * 64}.json": b"not json"})
    with pytest.raises(AmbiguousHistoryError):
        reg2.approval_chain("X", 1)


def test_pretty_bytes_with_correct_hash_valid(tmp_path: Path) -> None:
    genesis = _approve(0, None)
    pretty = json.dumps(genesis, indent=2).encode()
    assert pretty != canonical.canonicalize(genesis)
    reg = _write(tmp_path, "approvals", {f"{genesis['event_id']}.json": pretty})
    assert reg.effective_approval("X", 1, DIGEST).event_id == genesis["event_id"]


def test_approval_fold_reapprove_and_scoping(tmp_path: Path) -> None:
    first = _approve(0, None)
    revoke = _approve(1, first["event_id"], event_type="REVOKE_APPROVAL")
    second = _approve(2, revoke["event_id"])
    reg = _write(tmp_path, "approvals", _chain_bytes(first, revoke, second))
    assert reg.effective_approval("X", 1, DIGEST).event_id == second["event_id"]
    other = _approve(0, None, invariant_digest=OTHER)
    revoke_other = _approve(
        1, other["event_id"], event_type="REVOKE_APPROVAL", invariant_digest=OTHER
    )
    fresh = _approve(2, revoke_other["event_id"])
    reg2 = _write(tmp_path / "s", "approvals", _chain_bytes(other, revoke_other, fresh))
    with pytest.raises(RevokedApprovalError) as err:
        reg2.effective_approval("X", 1, OTHER)
    assert err.value.reason_class == "revoked-approval"
    assert reg2.effective_approval("X", 1, DIGEST).event_id == fresh["event_id"]


def test_note_only_chain_has_no_approval(tmp_path: Path) -> None:
    note = _approve(0, None, event_type="NOTE")
    reg = _write(tmp_path, "approvals", _chain_bytes(note))
    with pytest.raises(NoApprovalError):
        reg.effective_approval("X", 1, DIGEST)


def test_lifecycle_machine(tmp_path: Path) -> None:
    active = _life(0, None, "ACTIVATE")
    depr = _life(1, active["event_id"], "DEPRECATE")
    sup = _life(2, depr["event_id"], "SUPERSEDE", successor_version=2)
    reg = _write(tmp_path, "lifecycle", _chain_bytes(active, depr, sup))
    assert reg.lifecycle_state("X", 1) == "superseded"
    revoke = _life(1, active["event_id"], "REVOKE_INVARIANT")
    reg2 = _write(tmp_path / "r", "lifecycle", _chain_bytes(active, revoke))
    assert reg2.lifecycle_state("X", 1) == "revoked"
    again = _life(1, active["event_id"], "ACTIVATE")
    reg3 = _write(tmp_path / "b", "lifecycle", _chain_bytes(active, again))
    with pytest.raises(AmbiguousHistoryError) as err:
        reg3.lifecycle_state("X", 1)
    assert err.value.reason_class == "invalid-transition"
    late = _life(2, revoke["event_id"], "DEPRECATE")
    reg4 = _write(tmp_path / "c", "lifecycle", _chain_bytes(active, revoke, late))
    with pytest.raises(AmbiguousHistoryError) as err:
        reg4.lifecycle_state("X", 1)
    assert err.value.reason_class == "invalid-transition"


def test_joint_outcomes(tmp_path: Path) -> None:
    genesis = _approve(0, None)
    active = _life(0, None, "ACTIVATE")
    depr = _life(1, active["event_id"], "DEPRECATE")
    sup = _life(1, active["event_id"], "SUPERSEDE", successor_version=2)
    _write(tmp_path, "approvals", _chain_bytes(genesis))
    _write(tmp_path, "lifecycle", _chain_bytes(active, depr))
    reg = Registry(tmp_path)
    elig = reg.check_eligible("X", 1, DIGEST)
    assert (elig.approval_event_id, elig.lifecycle_state, elig.warnings) == (
        genesis["event_id"],
        "deprecated",
        ("deprecated",),
    )
    with pytest.raises(EligibilityError) as err:
        reg.check_eligible("X", 1, DIGEST, Policy(strict_deprecated=True))
    assert err.value.reason_class == "lifecycle-deprecated-strict"
    _write(tmp_path / "s", "approvals", _chain_bytes(genesis))
    _write(tmp_path / "s", "lifecycle", _chain_bytes(active, sup))
    with pytest.raises(EligibilityError) as err:
        Registry(tmp_path / "s").check_eligible("X", 1, DIGEST)
    assert err.value.reason_class == "lifecycle-superseded"
    with pytest.raises(NoApprovalError):
        reg.check_eligible("X", 1, OTHER)
