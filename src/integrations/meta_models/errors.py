"""Error taxonomy for the Meta Model API boundary.

Every error is sanitized at construction: messages never carry the API
key, prompts, or code excerpts. Permanent failures (auth, invalid
request) are distinct types from retryable ones so callers — and the
transport's own retry loop — never retry what cannot succeed.
"""

from __future__ import annotations


class MetaModelsError(Exception):
    """Base error for Meta Model API failures (never carries secrets)."""


class MetaModelsConfigError(MetaModelsError):
    """Missing key, bad model name, or other client-side misconfiguration."""


class MetaModelsAuthError(MetaModelsError):
    """Authentication or permission failure (HTTP 401/403, never retried)."""


class MetaModelsRequestError(MetaModelsError):
    """Permanent request failure (other 4xx, never retried)."""


class MetaModelsRateLimitError(MetaModelsError):
    """Rate limiting persisted past the retry budget (HTTP 429)."""


class MetaModelsServerError(MetaModelsError):
    """Transient server or network failure persisted past the retry budget."""


class MetaModelsTimeoutError(MetaModelsError):
    """The request timed out on every attempt."""


class MetaModelsResponseError(MetaModelsError):
    """The response was malformed, truncated, or oversized."""
