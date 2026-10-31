"""P0 scaffolding: package surface, versioning, and import hygiene."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import attest_sdk
from attest_sdk import errors

ROOT = Path(__file__).resolve().parents[3]
BANNED_TOP_LEVELS = frozenset(
    {"apps", "attest_core", "examples", "fastapi", "httpx", "integrations", "yaml"}
)


def test_all_exports_are_sorted_and_resolve() -> None:
    assert attest_sdk.__all__ == sorted(attest_sdk.__all__)
    for name in attest_sdk.__all__:
        assert hasattr(attest_sdk, name), name


def test_version_metadata() -> None:
    assert isinstance(attest_sdk.__version__, str)
    assert attest_sdk.__version__
    assert attest_sdk.SUPPORTED_SPEC_VERSIONS == (1,)


def test_error_hierarchy() -> None:
    children = {
        errors.ParseError: errors.AttestError,
        errors.SchemaError: errors.AttestError,
        errors.CanonicalizationError: errors.AttestError,
        errors.LimitExceededError: errors.CanonicalizationError,
        errors.UnsupportedSpecVersionError: errors.AttestError,
        errors.RegistryError: errors.AttestError,
        errors.AmbiguousHistoryError: errors.RegistryError,
        errors.ApprovalError: errors.AttestError,
        errors.NoApprovalError: errors.ApprovalError,
        errors.StaleApprovalError: errors.ApprovalError,
        errors.RevokedApprovalError: errors.ApprovalError,
        errors.EligibilityError: errors.AttestError,
        errors.VerifierError: errors.AttestError,
        errors.UnknownVerificationTypeError: errors.VerifierError,
        errors.UnsupportedVerifierSpecError: errors.VerifierError,
        errors.VerifierRefusedError: errors.VerifierError,
        errors.VerifierParameterError: errors.VerifierError,
        errors.AttestationError: errors.AttestError,
        errors.HistoryUnavailableError: errors.AttestError,
    }
    for child, parent in children.items():
        assert issubclass(child, parent)
        assert issubclass(child, errors.AttestError)
        assert issubclass(child, Exception)


def test_import_stays_light() -> None:
    probe = (
        "import sys, attest_sdk; "
        "banned = sorted(m for m in sys.modules "
        "if m.split('.')[0] in "
        "{'apps', 'attest_core', 'examples', 'fastapi', 'httpx', "
        "'integrations', 'yaml'}); "
        "print(','.join(banned)); "
        "raise SystemExit(1 if banned else 0)"
    )
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, (
        f"heavy imports pulled: {completed.stdout.strip()} {completed.stderr.strip()}".rstrip()
    )
