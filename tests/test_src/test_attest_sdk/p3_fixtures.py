"""Shared P3 fixtures: frozen-registry builders and fake verifiers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attest_core.verification import CheckEvidence
from attest_sdk import canonical, documents, parse_request
from attest_sdk.documents import Invariant
from attest_sdk.registry import Registry
from attest_sdk.requests import VerificationRequest
from attest_sdk.verifiers import AttemptObservation
from attest_spec import AttemptOutcome

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "attest-spec" / "v1" / "vectors"
DIGEST = "686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8"
APPROVAL = "5e6885e518a7c1370ee65f82c2ba87b09e1b8a37835cbc81ce0317ff69ea6071"
SCOPE = ("/admin/users", "/admin/settings")


def materialize(fixture_id: str, root: Path) -> None:
    """Materialize one published chain fixture under a registry root."""
    fixture = json.loads((VECTORS / "chains" / f"{fixture_id}.chain.json").read_bytes())
    for entry in fixture["files"]:
        content = entry["content"]
        if isinstance(content, dict):
            data = canonical.canonicalize(content)
        else:
            data = str(content).encode()
        path = root / str(fixture["chain_dir"]) / entry["name"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def load_auth_invariant() -> Invariant:
    """Load AUTH-ADMIN-001 from its published canonical fixture."""
    return documents.load_invariant(VECTORS / "canonical" / "auth-admin-001.input.json")


def make_request(
    implementation: str = "fake", version: str = "1.0.0", **over: Any
) -> VerificationRequest:
    """Build a valid request against the AUTH-ADMIN-001 fixtures."""
    base: dict[str, Any] = {
        "invariant_id": "AUTH-ADMIN-001",
        "invariant_version": 1,
        "spec_version": 1,
        "expected_content_digest": DIGEST,
        "approval_ref": APPROVAL,
        "repo": "demo",
        "revision": "0" * 40,
        "verifier_ref": {
            "type": "http-auth-probe/1",
            "implementation": implementation,
            "version": version,
            "artifact": {"status": "unavailable", "reason": "test"},
        },
        "execution_profile": "standard",
    }
    base.update(over)
    return parse_request(base)


def make_registry(root: Path, approval: str, lifecycle: str) -> Registry:
    """Materialize two chain fixtures and open a registry over them."""
    materialize(approval, root)
    materialize(lifecycle, root)
    return Registry(root)


class FakeVerifier:
    """Scripted verifier with a run counter."""

    verification_type = "http-auth-probe/1"
    implementation = "fake"
    version = "1.0.0"
    spec_versions: tuple[int, ...] = (1,)
    inventory_mechanism = "fake inventory, sorted"

    def __init__(self, script: list[Any]) -> None:
        self._script = script
        self.calls = 0

    def run(
        self, scope: tuple[str, ...], target: str | None, params: dict[str, Any]
    ) -> AttemptObservation:
        self.calls += 1
        assert set(scope) == set(SCOPE), scope
        assert params == {}, params
        step = self._script[min(self.calls - 1, len(self._script) - 1)]
        if isinstance(step, Exception):
            raise step
        observation: AttemptObservation = step
        return observation


def make_check(check_id: str, target: str, passed: bool) -> CheckEvidence:
    """Build one probe record in §10 detail format."""
    return CheckEvidence(check_id, target, passed, "ctx: expected E, got A")


def make_matrix(passed: bool) -> list[CheckEvidence]:
    """Coverage plus the full 3-probe matrix over SCOPE."""
    checks = [make_check("scope-coverage", ",".join(SCOPE), True)]
    for endpoint in SCOPE:
        for probe in ("unauthenticated-rejected", "non-admin-denied", "admin-allowed"):
            checks.append(make_check(probe, endpoint, passed))
    return checks


def make_obs(outcome: AttemptOutcome, passed: bool = True) -> AttemptObservation:
    """Build one coherent observation with a full probe matrix."""
    return AttemptObservation(outcome, tuple(make_matrix(passed)), "d")
