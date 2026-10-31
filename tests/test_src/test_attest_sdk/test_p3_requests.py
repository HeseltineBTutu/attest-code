"""P3 unit tests: verification-request validation."""

from __future__ import annotations

from typing import Any

import pytest

from attest_sdk.errors import SchemaError, UnsupportedSpecVersionError
from attest_sdk.registry import Policy
from attest_sdk.requests import EXECUTION_PROFILES, VerificationRequest, parse_request
from attest_sdk.verifiers import ArtifactState, VerifierRef

DIGEST = "686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8"


def _ref(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": "http-auth-probe/1",
        "implementation": "impl",
        "version": "1.0.0",
        "artifact": {"status": "unavailable", "reason": "demo"},
    }
    base.update(over)
    return base


def _wire(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "invariant_id": "X",
        "invariant_version": 1,
        "spec_version": 1,
        "expected_content_digest": DIGEST,
        "approval_ref": "0" * 64,
        "repo": "example",
        "revision": "0" * 40,
        "verifier_ref": _ref(),
        "execution_profile": "standard",
    }
    base.update(over)
    return base


def _wire_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    return _wire(verifier_ref=_ref(artifact=artifact))


def test_valid_minimal_and_full() -> None:
    minimal = parse_request(_wire())
    assert minimal.timeout is None and minimal.policy is None
    full = parse_request(
        _wire(
            timeout=30,
            target_selector="t",
            client="c",
            policy={"strict_deprecated": True, "require_artifact_digest": True},
            request_metadata={"k": "v"},
            revision="0" * 64,
            execution_profile="hardened",
        )
    )
    assert full.policy == Policy(strict_deprecated=True, require_artifact_digest=True)
    assert full.request_metadata == {"k": "v"}


def test_profiles_accepted() -> None:
    for profile in ("standard", "contained", "hardened"):
        assert parse_request(_wire(execution_profile=profile)).execution_profile == profile


def test_profiles_match_legacy_set() -> None:
    from attest_core.exec_profile import PROFILES

    assert EXECUTION_PROFILES == PROFILES


@pytest.mark.parametrize(
    "data",
    [
        [],
        "x",
        {**_wire(), "bogus": 1},
        {k: v for k, v in _wire().items() if k != "repo"},
        _wire(invariant_id=""),
        _wire(invariant_id=1),
        _wire(invariant_version=0),
        _wire(invariant_version="1"),
        _wire(invariant_version=True),
        _wire(spec_version="1"),
        _wire(spec_version=True),
        _wire(expected_content_digest="0" * 63),
        _wire(approval_ref="G" * 64),
        _wire(repo=""),
        _wire(repo=5),
        _wire(revision="0" * 39),
        _wire(revision="0" * 41),
        _wire(revision="F" * 40),
        _wire(revision="zz"),
        _wire(execution_profile="fast"),
        _wire(execution_profile=""),
        _wire(verifier_ref=[]),
        _wire(verifier_ref={**_ref(), "bogus": 1}),
        _wire(verifier_ref={k: v for k, v in _ref().items() if k != "type"}),
        _wire(verifier_ref=_ref(type="")),
        _wire(verifier_ref=_ref(artifact=[])),
        _wire(verifier_ref=_ref(artifact={"status": "maybe"})),
        _wire(verifier_ref=_ref(artifact={"status": "available"})),
        _wire_artifact({"status": "available", "algorithm": "s", "value": "v", "reason": "r"}),
        _wire_artifact({"status": "unavailable"}),
        _wire_artifact({"status": "unavailable", "reason": "", "algorithm": "s"}),
        _wire(timeout=0),
        _wire(timeout=-1),
        _wire(timeout=True),
        _wire(timeout=1.5),
        _wire(target_selector=""),
        _wire(client=3),
        _wire(policy=[]),
        _wire(policy={"bogus": True}),
        _wire(policy={"strict_deprecated": "yes"}),
        _wire(request_metadata=[]),
    ],
)
def test_malformed_requests_refuse(data: Any) -> None:
    with pytest.raises(SchemaError):
        parse_request(data)


@pytest.mark.parametrize("spec", [0, 2, 99])
def test_unsupported_spec_version(spec: int) -> None:
    with pytest.raises(UnsupportedSpecVersionError):
        parse_request(_wire(spec_version=spec))


def test_available_artifact_shape() -> None:
    artifact = {"status": "available", "algorithm": "sha256", "value": "ab"}
    request = parse_request(_wire(verifier_ref=_ref(artifact=artifact)))
    assert request.verifier_ref.artifact.available is True


def test_policy_validation() -> None:
    assert Policy() == Policy(strict_deprecated=False, require_artifact_digest=False)
    with pytest.raises(SchemaError):
        Policy(strict_deprecated="yes")  # type: ignore[arg-type]
    with pytest.raises(SchemaError):
        Policy(require_artifact_digest=1)  # type: ignore[arg-type]


def test_direct_construction_validates() -> None:
    ref = VerifierRef(
        type="t", implementation="i", version="v", artifact=ArtifactState(False, reason="r")
    )
    with pytest.raises(SchemaError, match="revision"):
        VerificationRequest(
            invariant_id="X",
            invariant_version=1,
            spec_version=1,
            expected_content_digest=DIGEST,
            approval_ref="0" * 64,
            repo="r",
            revision="short",
            verifier_ref=ref,
            execution_profile="standard",
        )
