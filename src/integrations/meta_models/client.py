"""HTTP transport for the Meta Model API.

This module only moves bytes: authentication, explicit timeouts, bounded
retries, and size limits. Payload shaping and response-shape validation
live in :mod:`protocol`; verdicts, approvals, and evidence are never
interpreted here. Nothing is logged: no credentials, prompts, or excerpts.

Only documented request fields are sent: ``model`` and ``messages`` for
chat completions (see https://dev.meta.ai/docs/quickstart). Optional
parameters such as ``response_format`` are deliberately omitted until
their support is verified against the live API.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from integrations.meta_models.errors import (
    MetaModelsAuthError,
    MetaModelsConfigError,
    MetaModelsRateLimitError,
    MetaModelsRequestError,
    MetaModelsResponseError,
    MetaModelsServerError,
    MetaModelsTimeoutError,
)
from integrations.meta_models.protocol import parse_completion, parse_model_list

DEFAULT_BASE_URL = "https://api.meta.ai/v1"
"""Documented Meta Model API base URL."""

DEFAULT_MODEL = "muse-spark-1.3"
"""Standard (non-contributor) model confirmed listed on 2026-10-28."""

ENV_API_KEY = "MODEL_API_KEY"
"""Environment variable the API key is read from at runtime."""

CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 120.0
WRITE_TIMEOUT = 30.0
POOL_TIMEOUT = 10.0

MAX_ATTEMPTS = 3
"""Total tries per request, including the first attempt."""

BACKOFF_BASE_SECONDS = 0.5
MAX_RETRY_AFTER_SECONDS = 60.0
MAX_RESPONSE_BYTES = 131072
MAX_REQUEST_BYTES = 262144
MAX_ERROR_BODY_BYTES = 4096
MAX_ERROR_DETAIL_CHARS = 300
REDACTED = "[REDACTED]"

_CONTRIBUTOR_MARKER = "contributor"
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504, 529})
_PERMANENT_ERRORS = (
    MetaModelsAuthError,
    MetaModelsRequestError,
    MetaModelsResponseError,
    MetaModelsRateLimitError,
)


def _retry_after_seconds(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        delay = float(raw.strip())
    except ValueError:
        return None
    if delay < 0:
        return None
    return min(delay, MAX_RETRY_AFTER_SECONDS)


def _read_capped(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > limit:
            raise MetaModelsResponseError(f"response exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


class MetaModelsClient:
    """Minimal authenticated client for listing models and completions."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        transport: httpx.BaseTransport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        """Bind credentials, model, and endpoint.

        ``transport`` accepts an ``httpx.MockTransport`` for deterministic
        unit tests; ``sleeper`` is likewise injectable so retry tests do
        not wait on real backoff delays.
        """
        resolved = api_key if api_key is not None else os.environ.get(ENV_API_KEY, "")
        if not resolved.strip():
            raise MetaModelsConfigError(f"{ENV_API_KEY} is not configured")
        name = model.strip()
        if not name:
            raise MetaModelsConfigError("model must be non-empty")
        if _CONTRIBUTOR_MARKER in name.lower():
            raise MetaModelsConfigError(
                "refusing contributor-mode model (prompts may train future models)"
            )
        self._api_key = resolved
        self._model = name
        self._sleeper = sleeper
        self._http = httpx.Client(
            base_url=base_url.strip().rstrip("/"),
            headers={"Authorization": f"Bearer {resolved}"},
            timeout=httpx.Timeout(
                connect=CONNECT_TIMEOUT,
                read=READ_TIMEOUT,
                write=WRITE_TIMEOUT,
                pool=POOL_TIMEOUT,
            ),
            follow_redirects=True,
            transport=transport,
        )

    @property
    def model(self) -> str:
        """The model every completion request is pinned to."""
        return self._model

    def _safe(self, text: str) -> str:
        return text.replace(self._api_key, REDACTED)

    def _error_detail(self, response: httpx.Response) -> str:
        try:
            raw = _read_capped(response, MAX_ERROR_BODY_BYTES)
        except MetaModelsResponseError:
            return f"http {response.status_code}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except ValueError:
            return f"http {response.status_code}"
        if not isinstance(payload, dict) or not isinstance(payload.get("error"), dict):
            return f"http {response.status_code}"
        err = payload["error"]
        detail = f"http {response.status_code} {err.get('type', 'error')}: {err.get('message', '')}"
        return self._safe(detail[:MAX_ERROR_DETAIL_CHARS])

    def _encode(self, payload: Mapping[str, Any] | None) -> bytes | None:
        if payload is None:
            return None
        body = json.dumps(payload).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise MetaModelsRequestError(f"request payload exceeds {MAX_REQUEST_BYTES} bytes")
        return body

    def _request_json(self, method: str, path: str, payload: Mapping[str, Any] | None) -> Any:
        body = self._encode(payload)
        headers = {"Content-Type": "application/json"} if body is not None else None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                with self._http.stream(method, path, content=body, headers=headers) as response:
                    status = response.status_code
                    if status == 200:
                        raw = _read_capped(response, MAX_RESPONSE_BYTES)
                        try:
                            return json.loads(raw.decode("utf-8"))
                        except ValueError as exc:
                            raise MetaModelsResponseError("response is not valid JSON") from exc
                    if status in (401, 403):
                        raise MetaModelsAuthError(self._error_detail(response))
                    if status in _RETRYABLE_STATUS:
                        detail = self._error_detail(response)
                        if status == 429:
                            error: MetaModelsServerError | MetaModelsRateLimitError = (
                                MetaModelsRateLimitError(detail)
                            )
                        else:
                            error = MetaModelsServerError(detail)
                        if attempt < MAX_ATTEMPTS:
                            delay = _retry_after_seconds(response) if status == 429 else None
                            if delay is None:
                                delay = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                            self._sleeper(delay)
                            continue
                        raise error
                    if 400 <= status < 500:
                        raise MetaModelsRequestError(self._error_detail(response))
                    raise MetaModelsServerError(self._error_detail(response))
            except _PERMANENT_ERRORS:
                raise
            except (MetaModelsServerError, httpx.TimeoutException, httpx.TransportError) as exc:
                transient = self._transient_error(exc)
                if attempt < MAX_ATTEMPTS:
                    self._sleeper(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))
                    continue
                raise transient from exc
        raise MetaModelsServerError("request failed without a recorded error")

    def _transient_error(
        self, exc: MetaModelsServerError | httpx.TimeoutException | httpx.TransportError
    ) -> MetaModelsServerError | MetaModelsTimeoutError:
        if isinstance(exc, MetaModelsServerError):
            return exc
        if isinstance(exc, httpx.TimeoutException):
            return MetaModelsTimeoutError(f"request timed out: {exc.__class__.__name__}")
        return MetaModelsServerError(self._safe(f"transport failure: {exc.__class__.__name__}"))

    def list_models(self) -> list[str]:
        """Return the model identifiers available to this account."""
        return parse_model_list(self._request_json("GET", "/models", None))

    def complete(self, payload: Mapping[str, Any]) -> str:
        """Run one chat completion; return the assistant message content.

        The payload model is overridden with this client's pinned model so
        callers cannot accidentally address an unverified model.
        """
        data = self._request_json("POST", "/chat/completions", {**payload, "model": self._model})
        return parse_completion(data)
