"""P3 end to end: frozen fixtures through the reference adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from p3_fixtures import APPROVAL, load_auth_invariant, make_registry, make_request

from apps.demo_api import (
    create_incomplete_repair_app,
    create_repaired_app,
    create_vulnerable_app,
)
from attest_sdk import verify
from attest_sdk.documents import Invariant
from attest_sdk.errors import EligibilityError, VerifierRefusedError
from attest_sdk.registry import Registry
from attest_sdk.requests import VerificationRequest
from attest_sdk.verifiers import AttemptObservation
from attest_spec import AttemptOutcome, Verdict
from examples.reference_adapter import ReferenceHttpAuthProbe


def _request(**over: Any) -> VerificationRequest:
    return make_request(implementation="attest-reference-adapter", version="0.1.0", **over)


def _registry(root: Path, lifecycle: str = "lifecycle-active") -> Registry:
    return make_registry(root, "approval-valid", lifecycle)


def _invariant() -> Invariant:
    return load_auth_invariant()


@pytest.mark.parametrize(
    ("make_app", "verdict"),
    [
        (create_repaired_app, Verdict.PASSED),
        (create_vulnerable_app, Verdict.FAILED),
        (create_incomplete_repair_app, Verdict.FAILED),
    ],
)
def test_demo_apps_end_to_end(tmp_path: Path, make_app: Any, verdict: Verdict) -> None:
    adapter = ReferenceHttpAuthProbe(make_app())
    report = verify(_request(), _invariant(), adapter, _registry(tmp_path))
    assert report.verdict is verdict
    assert len(report.attempts) == 3
    assert report.approval_event_id == APPROVAL
    assert report.warnings == ()


def test_scope_mismatch_is_inconclusive(tmp_path: Path) -> None:
    app = FastAPI()

    @app.get("/admin/users")
    def users() -> dict[str, str]:
        return {"ok": "yes"}

    report = verify(_request(), _invariant(), ReferenceHttpAuthProbe(app), _registry(tmp_path))
    assert report.verdict is Verdict.INCONCLUSIVE
    assert all(a.outcome is AttemptOutcome.INFRA_FAILURE for a in report.attempts)


def test_deprecated_lifecycle_warns(tmp_path: Path) -> None:
    adapter = ReferenceHttpAuthProbe(create_repaired_app())
    report = verify(_request(), _invariant(), adapter, _registry(tmp_path, "lifecycle-deprecated"))
    assert report.verdict is Verdict.PASSED
    assert report.warnings == ("deprecated",)
    strict = _request(policy={"strict_deprecated": True})
    with pytest.raises(EligibilityError):
        verify(strict, _invariant(), adapter, _registry(tmp_path))


def test_artifact_policy_end_to_end(tmp_path: Path) -> None:
    strict = _request(policy={"require_artifact_digest": True})
    adapter = ReferenceHttpAuthProbe(create_repaired_app())
    with pytest.raises(VerifierRefusedError):
        verify(strict, _invariant(), adapter, _registry(tmp_path))
    available = _request(
        verifier_ref={
            "type": "http-auth-probe/1",
            "implementation": "attest-reference-adapter",
            "version": "0.1.0",
            "artifact": {"status": "available", "algorithm": "sha256", "value": "ab"},
        },
        policy={"require_artifact_digest": True},
    )
    report = verify(available, _invariant(), adapter, _registry(tmp_path))
    assert report.verdict is Verdict.PASSED


def test_adapter_guards_params_and_ignores_target() -> None:
    adapter = ReferenceHttpAuthProbe(create_repaired_app())
    bad: AttemptObservation = adapter.run(("/a",), "weird-target", {"x": 1})
    assert bad.outcome is AttemptOutcome.INFRA_FAILURE
    good = adapter.run(("/admin/users", "/admin/settings"), "weird-target", {})
    assert good.outcome is AttemptOutcome.PASS


def test_e2e_determinism(tmp_path: Path) -> None:
    adapter = ReferenceHttpAuthProbe(create_repaired_app())
    first = verify(_request(), _invariant(), adapter, _registry(tmp_path))
    second = verify(_request(), _invariant(), adapter, _registry(tmp_path))
    assert (first.verdict, first.config_digest) == (second.verdict, second.config_digest)
    assert len(first.evidence) == 24
