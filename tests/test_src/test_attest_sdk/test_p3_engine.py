"""P3 unit tests: pre-execution refusal gates (verifier never runs)."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest
from p3_fixtures import (
    DIGEST,
    FakeVerifier,
    load_auth_invariant,
    make_obs,
    make_registry,
    make_request,
)

from attest_sdk import documents, verify
from attest_sdk.errors import (
    AmbiguousHistoryError,
    EligibilityError,
    NoApprovalError,
    RevokedApprovalError,
    StaleApprovalError,
    UnknownVerificationTypeError,
    UnsupportedVerifierSpecError,
    VerifierError,
    VerifierParameterError,
    VerifierRefusedError,
)
from attest_sdk.requests import VerificationRequest
from attest_spec import AttemptOutcome


def _pinned_request(**over: Any) -> VerificationRequest:
    ref: dict[str, Any] = {
        "type": "http-auth-probe/1",
        "implementation": "fake",
        "version": "1.0.0",
        "artifact": {"status": "unavailable", "reason": "fake"},
    }
    ref.update(over.pop("verifier_ref", {}))
    return make_request(verifier_ref=ref, **over)


def test_stale_digest_refuses(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    fake = FakeVerifier([make_obs(AttemptOutcome.PASS)])
    with pytest.raises(StaleApprovalError):
        verify(make_request(expected_content_digest="0" * 64), load_auth_invariant(), fake, reg)
    assert fake.calls == 0


def test_stale_approval_ref_refuses(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    fake = FakeVerifier([make_obs(AttemptOutcome.PASS)])
    with pytest.raises(StaleApprovalError):
        verify(make_request(approval_ref="0" * 64), load_auth_invariant(), fake, reg)
    assert fake.calls == 0


def test_pin_type_mismatch_refuses(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    fake = FakeVerifier([make_obs(AttemptOutcome.PASS)])
    bad = _pinned_request(verifier_ref={"type": "other/1"})
    with pytest.raises(VerifierError):
        verify(bad, load_auth_invariant(), fake, reg)
    assert fake.calls == 0


def test_object_identity_mismatch_refuses(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")

    class Evil(FakeVerifier):
        implementation = "evil"

    class Future(FakeVerifier):
        spec_versions: tuple[int, ...] = (2,)

    class Vague(FakeVerifier):
        inventory_mechanism = ""

    for cls, exc in (
        (Evil, VerifierError),
        (Future, UnsupportedVerifierSpecError),
        (Vague, VerifierRefusedError),
    ):
        fake = cls([make_obs(AttemptOutcome.PASS)])
        with pytest.raises(exc):
            verify(make_request(), load_auth_invariant(), fake, reg)
        assert fake.calls == 0


def test_runnable_and_artifact_gates(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")

    class Broken:
        verification_type = "http-auth-probe/1"
        implementation = "fake"
        version = "1.0.0"
        spec_versions = (1,)
        inventory_mechanism = "x"
        run = None

    broken: Any = Broken()
    with pytest.raises(VerifierRefusedError):
        verify(make_request(), load_auth_invariant(), broken, reg)
    strict = make_request(policy={"require_artifact_digest": True})
    fake = FakeVerifier([make_obs(AttemptOutcome.PASS)])
    with pytest.raises(VerifierRefusedError):
        verify(strict, load_auth_invariant(), fake, reg)
    assert fake.calls == 0


def test_unknown_type_and_bad_params_refuse(tmp_path: Path) -> None:
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    unknown = dataclasses.replace(load_auth_invariant(), verification_type="nope/1")
    digest = documents.invariant_digest(unknown)
    fake = FakeVerifier([make_obs(AttemptOutcome.PASS)])
    with pytest.raises(UnknownVerificationTypeError):
        verify(make_request(expected_content_digest=digest), unknown, fake, reg)
    assert fake.calls == 0
    tuned = dataclasses.replace(load_auth_invariant(), parameters={"x": 1})
    tuned_digest = documents.invariant_digest(tuned)
    with pytest.raises(VerifierParameterError):
        verify(make_request(expected_content_digest=tuned_digest), tuned, fake, reg)
    assert fake.calls == 0


@pytest.mark.parametrize(
    ("approval_fx", "lifecycle_fx", "exc"),
    [
        ("approval-wrong-digest", "lifecycle-active", NoApprovalError),
        ("approval-revoked", "lifecycle-active", RevokedApprovalError),
        ("approval-valid", "lifecycle-revoked", EligibilityError),
        ("approval-valid", "lifecycle-empty", EligibilityError),
        ("approval-fork", "lifecycle-active", AmbiguousHistoryError),
        ("approval-valid", "lifecycle-transplant", AmbiguousHistoryError),
    ],
)
def test_registry_state_refusals(
    tmp_path: Path, approval_fx: str, lifecycle_fx: str, exc: Any
) -> None:
    reg = make_registry(tmp_path, approval_fx, lifecycle_fx)
    fake = FakeVerifier([make_obs(AttemptOutcome.PASS)])
    with pytest.raises(exc):
        verify(make_request(), load_auth_invariant(), fake, reg)
    assert fake.calls == 0


def test_absent_parameters_pass_params_gate(tmp_path: Path) -> None:
    bare = dataclasses.replace(load_auth_invariant(), parameters=None)
    digest = documents.invariant_digest(bare)
    assert digest != DIGEST
    reg = make_registry(tmp_path, "approval-valid", "lifecycle-active")
    fake = FakeVerifier([make_obs(AttemptOutcome.PASS)])
    with pytest.raises(NoApprovalError):
        verify(make_request(expected_content_digest=digest), bare, fake, reg)
    assert fake.calls == 0
