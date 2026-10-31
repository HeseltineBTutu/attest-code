"""Reference adapter: http-auth-probe/1 over the demo checks.

Isolated from SDK core: this module imports the SDK, never the
reverse. It demonstrates the frozen verifier contract (§10) and
carries no authority beyond reporting observations; the parent
engine validates every observation and alone classifies verdicts.
Fixture apps come from the caller; demo fixture names stay out.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from attest_sdk.verifiers import AttemptObservation, Verifier
from attest_spec import AttemptOutcome
from examples.admin_authorization import run_admin_checks


class ReferenceHttpAuthProbe(Verifier):
    """Reference http-auth-probe/1 implementation for one demo app."""

    verification_type = "http-auth-probe/1"
    implementation = "attest-reference-adapter"
    version = "0.1.0"
    spec_versions: tuple[int, ...] = (1,)
    inventory_mechanism = (
        "registered FastAPI routes under /admin via apps.demo_api.admin_route_paths, sorted"
    )

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    def run(
        self, scope: tuple[str, ...], target: str | None, params: dict[str, Any]
    ) -> AttemptObservation:
        """Probe the app; target is accepted and ignored (app is fixed)."""
        if params != {}:
            return AttemptObservation(AttemptOutcome.INFRA_FAILURE, (), "parameters must be {}")
        report = run_admin_checks(self._app, scope)
        return AttemptObservation(report.outcome, tuple(report.checks), report.detail)
