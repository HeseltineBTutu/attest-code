"""P2 conformance: every published chain fixture.

Chain fixtures are normative-outcome vectors (single-implementation
publication QA), not two-language conformance: this test asserts the
manifest's validity/outcome/state plus this implementation's
documented refusal reasons.
"""

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
    RevokedApprovalError,
)
from attest_sdk.registry import Registry

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "attest-spec" / "v1" / "vectors"
DIGEST = "686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8"
INVARIANT = "AUTH-ADMIN-001"
VERSION = 1


def _load_fixture(fixture_id: str) -> dict[str, Any]:
    raw = (VECTORS / "chains" / f"{fixture_id}.chain.json").read_bytes()
    fixture: dict[str, Any] = json.loads(raw)
    return fixture


def _materialize(fixture: dict[str, Any], root: Path) -> None:
    for entry in fixture["files"]:
        content = entry["content"]
        if isinstance(content, dict):
            data = canonical.canonicalize(content)
        else:
            data = str(content).encode()
        path = root / str(fixture["chain_dir"]) / entry["name"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _cases() -> list[dict[str, Any]]:
    manifest = json.loads((VECTORS / "manifest.json").read_bytes())
    return [fx for fx in manifest["fixtures"] if fx["kind"] == "chain"]


def _check_approval(fixture: dict[str, Any], root: Path) -> None:
    _materialize(fixture, root)
    expected = fixture["expect"]
    if expected["validity"] == "ambiguous":
        with pytest.raises(AmbiguousHistoryError) as err:
            Registry(root).approval_chain(INVARIANT, VERSION)
        assert err.value.reason_class == expected["reason_class"]
        return
    history = Registry(root).approval_chain(INVARIANT, VERSION)
    assert list(history.reported) == expected.get("reported", [])
    if expected["effective_approval"] is None:
        with pytest.raises((NoApprovalError, RevokedApprovalError)):
            Registry(root).effective_approval(INVARIANT, VERSION, DIGEST)
    else:
        approval = Registry(root).effective_approval(INVARIANT, VERSION, DIGEST)
        assert approval.event_id == expected["effective_approval"]


def _check_lifecycle(fixture: dict[str, Any], root: Path) -> None:
    _materialize(fixture, root)
    expected = fixture["expect"]
    if expected["validity"] == "ambiguous":
        with pytest.raises(AmbiguousHistoryError) as err:
            Registry(root).lifecycle_state(INVARIANT, VERSION)
        assert err.value.reason_class == expected["reason_class"]
    else:
        assert Registry(root).lifecycle_state(INVARIANT, VERSION) == expected["state"]


def _check_joint(fixture: dict[str, Any], root: Path) -> None:
    for entry in fixture["files"]:
        _materialize(_load_fixture(str(entry["content"])), root)
    expected = fixture["expect"]
    if expected["outcome"] == "eligible":
        result = Registry(root).check_eligible(INVARIANT, VERSION, DIGEST)
        assert result.lifecycle_state == "active"
        assert result.warnings == ()
    else:
        with pytest.raises((EligibilityError, NoApprovalError, RevokedApprovalError)):
            Registry(root).check_eligible(INVARIANT, VERSION, DIGEST)


@pytest.mark.parametrize("fx", _cases(), ids=lambda fx: str(fx["id"]))
def test_chain_vector(fx: dict[str, Any], tmp_path: Path) -> None:
    fixture = _load_fixture(str(fx["id"]))
    if fixture["kind"] == "approval":
        _check_approval(fixture, tmp_path)
    elif fixture["kind"] == "lifecycle":
        _check_lifecycle(fixture, tmp_path)
    else:
        _check_joint(fixture, tmp_path)
