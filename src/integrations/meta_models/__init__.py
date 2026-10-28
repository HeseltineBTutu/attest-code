"""Isolated Meta Model API client: diagnose failures, propose patches.

The model may explain a FAILED verification and propose a unified diff
for human review. It never verdicts, never approves invariants, never
writes the repository, and never applies patches. A proposal becomes a
repair only after a human commits it as a new revision that Attest Code
independently verifies.
"""

from __future__ import annotations

from integrations.meta_models.client import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    ENV_API_KEY,
    MetaModelsClient,
)
from integrations.meta_models.diagnose import (
    Diagnosis,
    DiagnosisError,
    FailedSummary,
    build_verdict_summary,
    diagnose,
    render_for_review,
    summarize_failed_report,
)
from integrations.meta_models.errors import (
    MetaModelsAuthError,
    MetaModelsConfigError,
    MetaModelsError,
    MetaModelsRateLimitError,
    MetaModelsRequestError,
    MetaModelsResponseError,
    MetaModelsServerError,
    MetaModelsTimeoutError,
)
from integrations.meta_models.protocol import (
    ALLOWED_DIFF_PREFIXES,
    MAX_CODE_EXCERPT,
    MAX_DIFF_CHARS,
    MAX_VERDICT_SUMMARY,
)

__all__ = [
    "ALLOWED_DIFF_PREFIXES",
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL",
    "ENV_API_KEY",
    "MAX_CODE_EXCERPT",
    "MAX_DIFF_CHARS",
    "MAX_VERDICT_SUMMARY",
    "Diagnosis",
    "DiagnosisError",
    "FailedSummary",
    "MetaModelsAuthError",
    "MetaModelsClient",
    "MetaModelsConfigError",
    "MetaModelsError",
    "MetaModelsRateLimitError",
    "MetaModelsRequestError",
    "MetaModelsResponseError",
    "MetaModelsServerError",
    "MetaModelsTimeoutError",
    "build_verdict_summary",
    "diagnose",
    "render_for_review",
    "summarize_failed_report",
]
