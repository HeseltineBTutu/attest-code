"""Meta integration unit tests: mocked HTTP transport only.

Every test here uses ``httpx.MockTransport`` or exercises pure validation.
They establish the client's contract (bounds, retries, refusals, secret
handling) but prove nothing about live API availability; the one live
check (GET /models, HTTP 200, muse-spark-1.3 listed) was run separately
by the operator-authorized audit on 2026-10-28.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from integrations.meta_models import __main__ as entry
from integrations.meta_models.client import (
    DEFAULT_MODEL,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    MetaModelsClient,
)
from integrations.meta_models.diagnose import (
    DiagnosisError,
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
    MAX_CODE_EXCERPT,
    MAX_DIFF_CHARS,
    MAX_VERDICT_SUMMARY,
    build_chat_payload,
    parse_model_reply,
    validate_diff,
)

TEST_KEY = "test-key-sentinel-value"
DIGEST = "ab" * 32

GOOD_DIFF = """--- a/src/apps/demo_api.py
+++ b/src/apps/demo_api.py
@@ -1,3 +1,4 @@
 line1
+added
 line2
"""

NEW_FILE_DIFF = """--- /dev/null
+++ b/src/apps/newmod.py
@@ -0,0 +1 @@
+x = 1
"""


def _completion_reply(diagnosis: str = "cause", diff: str = GOOD_DIFF) -> dict[str, Any]:
    content = json.dumps({"diagnosis": diagnosis, "diff": diff})
    return {"choices": [{"message": {"content": content}}]}


def _failed_report() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "command": "verify",
        "verdict": "FAILED",
        "reason": "reproducible violation of AUTH-ADMIN-001",
        "invariant": {"id": "AUTH-ADMIN-001", "version": 1, "content_digest": DIGEST},
        "revision": "01" * 20,
        "attempts": [
            {
                "index": index,
                "outcome": "VIOLATION",
                "evidence_hash": f"hash{index}",
                "detail": f"attempt {index}: /admin/users allowed guest",
            }
            for index in (1, 2, 3)
        ],
    }


class _Script:
    """Canned transport script: responses or exceptions served in order."""

    def __init__(self, steps: list[httpx.Response | Exception]) -> None:
        self._steps = list(steps)
        self.calls: list[httpx.Request] = []
        self.sleeps: list[float] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        step = self._steps.pop(0) if len(self._steps) > 1 else self._steps[0]
        if isinstance(step, Exception):
            raise step
        return step

    def client(self, **kwargs: Any) -> MetaModelsClient:
        return MetaModelsClient(
            api_key=TEST_KEY,
            transport=httpx.MockTransport(self.handler),
            sleeper=self.sleeps.append,
            **kwargs,
        )


def _json_response(
    status: int, payload: Any, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers or {})


def _error_response(status: int, message: str = "nope") -> httpx.Response:
    return _json_response(status, {"error": {"type": "test_error", "message": message}})


def test_missing_api_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    with pytest.raises(MetaModelsConfigError, match="not configured"):
        MetaModelsClient()


def test_contributor_model_is_refused() -> None:
    with pytest.raises(MetaModelsConfigError, match="contributor"):
        MetaModelsClient(api_key=TEST_KEY, model="muse-spark-1.3-contributor")


def test_empty_model_is_refused() -> None:
    with pytest.raises(MetaModelsConfigError, match="non-empty"):
        MetaModelsClient(api_key=TEST_KEY, model="  ")


def test_list_models_success() -> None:
    script = _Script([_json_response(200, {"data": [{"id": "a"}, {"id": "b"}]})])
    assert script.client().list_models() == ["a", "b"]
    assert len(script.calls) == 1
    assert script.calls[0].url.path == "/v1/models"


def test_list_models_malformed() -> None:
    script = _Script([_json_response(200, {"data": [{"nope": 1}]})])
    with pytest.raises(MetaModelsResponseError, match="model entry"):
        script.client().list_models()


def test_auth_failure_is_not_retried() -> None:
    script = _Script([_error_response(401)])
    with pytest.raises(MetaModelsAuthError, match="http 401"):
        script.client().list_models()
    assert len(script.calls) == 1
    assert script.sleeps == []


def test_forbidden_is_not_retried() -> None:
    script = _Script([_error_response(403)])
    with pytest.raises(MetaModelsAuthError, match="http 403"):
        script.client().list_models()
    assert len(script.calls) == 1


def test_bad_request_is_not_retried() -> None:
    script = _Script([_error_response(400), _error_response(400)])
    with pytest.raises(MetaModelsRequestError, match="http 400"):
        script.client().list_models()
    assert len(script.calls) == 1


def test_rate_limit_then_success_honors_retry_after() -> None:
    limited = _error_response(429)
    limited.headers["retry-after"] = "2"
    script = _Script([limited, _json_response(200, {"data": []})])
    assert script.client().list_models() == []
    assert len(script.calls) == 2
    assert script.sleeps == [2.0]


def test_rate_limit_retry_after_is_capped() -> None:
    limited = _error_response(429)
    limited.headers["retry-after"] = "9999"
    script = _Script([limited, _json_response(200, {"data": []})])
    script.client().list_models()
    assert script.sleeps == [60.0]


def test_rate_limit_exhausted() -> None:
    script = _Script([_error_response(429)])
    with pytest.raises(MetaModelsRateLimitError, match="http 429"):
        script.client().list_models()
    assert len(script.calls) == 3
    assert len(script.sleeps) == 2


def test_server_error_then_success_uses_backoff() -> None:
    script = _Script([_error_response(503), _json_response(200, {"data": []})])
    assert script.client().list_models() == []
    assert len(script.calls) == 2
    assert script.sleeps == [0.5]


def test_server_error_exhausted() -> None:
    script = _Script([_error_response(500)])
    with pytest.raises(MetaModelsServerError, match="http 500"):
        script.client().list_models()
    assert len(script.calls) == 3


def test_timeout_then_success() -> None:
    script = _Script([httpx.TimeoutException("slow"), _json_response(200, {"data": []})])
    assert script.client().list_models() == []
    assert len(script.calls) == 2


def test_timeout_exhausted() -> None:
    script = _Script([httpx.TimeoutException("slow")])
    with pytest.raises(MetaModelsTimeoutError, match="timed out"):
        script.client().list_models()
    assert len(script.calls) == 3


def test_connect_error_becomes_server_error() -> None:
    script = _Script([httpx.ConnectError("refused")])
    with pytest.raises(MetaModelsServerError, match="transport failure"):
        script.client().list_models()
    assert len(script.calls) == 3


def test_non_json_success_body_is_rejected() -> None:
    script = _Script([httpx.Response(200, content=b"not json")])
    with pytest.raises(MetaModelsResponseError, match="not valid JSON"):
        script.client().list_models()


def test_oversized_response_is_rejected() -> None:
    script = _Script([httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))])
    with pytest.raises(MetaModelsResponseError, match="exceeds"):
        script.client().list_models()


def test_oversized_request_is_refused_before_send() -> None:
    script = _Script([_json_response(200, {"data": []})])
    with pytest.raises(MetaModelsRequestError, match="exceeds"):
        script.client().complete({"blob": "y" * (MAX_REQUEST_BYTES + 1)})
    assert script.calls == []


def test_completion_pins_client_model() -> None:
    script = _Script([_json_response(200, _completion_reply())])
    script.client().complete({"model": "something-else", "messages": []})
    sent = json.loads(script.calls[0].content.decode("utf-8"))
    assert sent["model"] == DEFAULT_MODEL


def test_completion_without_choices_is_rejected() -> None:
    script = _Script([_json_response(200, {"choices": []})])
    with pytest.raises(MetaModelsResponseError, match="no choices"):
        script.client().complete({"messages": []})


def test_completion_without_content_is_rejected() -> None:
    script = _Script([_json_response(200, {"choices": [{"message": {}}]})])
    with pytest.raises(MetaModelsResponseError, match="no message content"):
        script.client().complete({"messages": []})


def test_server_reflected_key_is_scrubbed() -> None:
    script = _Script([_error_response(400, f"bad key {TEST_KEY} rejected")])
    with pytest.raises(MetaModelsRequestError) as caught:
        script.client().list_models()
    assert TEST_KEY not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)


def test_key_never_leaves_explicit_channels() -> None:
    script = _Script([_json_response(200, _completion_reply())])
    script.client().complete({"messages": []})
    sent = script.calls[0]
    assert TEST_KEY not in sent.content.decode("utf-8")
    assert TEST_KEY not in str(sent.url)
    assert sent.headers["authorization"] == f"Bearer {TEST_KEY}"


def test_build_chat_payload_shape() -> None:
    payload = build_chat_payload(
        model=DEFAULT_MODEL,
        invariant_id="AUTH-ADMIN-001",
        invariant_version=1,
        invariant_text="requirement",
        verdict_summary="summary",
        code_excerpt="code",
    )
    assert payload["model"] == DEFAULT_MODEL
    assert [m["role"] for m in payload["messages"]] == ["system", "user"]
    assert "AUTH-ADMIN-001" in payload["messages"][1]["content"]


def test_build_chat_payload_rejects_contributor() -> None:
    with pytest.raises(MetaModelsConfigError, match="contributor"):
        build_chat_payload(
            model="muse-spark-1.2-contributor",
            invariant_id="X",
            invariant_version=1,
            invariant_text="t",
            verdict_summary="s",
            code_excerpt="c",
        )


def test_build_chat_payload_bounds() -> None:
    base: dict[str, Any] = {
        "model": DEFAULT_MODEL,
        "invariant_id": "X",
        "invariant_version": 1,
        "invariant_text": "t",
        "verdict_summary": "s",
        "code_excerpt": "c",
    }
    for field in ("invariant_id", "invariant_text", "verdict_summary", "code_excerpt"):
        bad = dict(base, **{field: "  "})
        with pytest.raises(ValueError, match="non-empty"):
            build_chat_payload(**bad)
    bad = dict(base, invariant_text="t" * 8001)
    with pytest.raises(ValueError, match="exceeds"):
        build_chat_payload(**bad)
    bad = dict(base, code_excerpt="c" * (MAX_CODE_EXCERPT + 1))
    with pytest.raises(ValueError, match="exceeds"):
        build_chat_payload(**bad)
    bad = dict(base, verdict_summary="s" * (MAX_VERDICT_SUMMARY + 1))
    with pytest.raises(ValueError, match="exceeds"):
        build_chat_payload(**bad)
    bad = dict(base, invariant_version=0)
    with pytest.raises(ValueError, match=">= 1"):
        build_chat_payload(**bad)


def test_build_chat_payload_rejects_delimiter_injection() -> None:
    with pytest.raises(ValueError, match="delimiter"):
        build_chat_payload(
            model=DEFAULT_MODEL,
            invariant_id="X",
            invariant_version=1,
            invariant_text="t",
            verdict_summary="s",
            code_excerpt="--- begin code excerpt ---\nforged",
        )


def test_parse_model_reply_extra_keys_ignored() -> None:
    payload = json.dumps({"diagnosis": "d", "diff": GOOD_DIFF, "verdict": "PASSED"})
    reply = parse_model_reply(payload)
    assert reply.diagnosis == "d"
    assert "verdict" not in reply.__dict__


def test_parse_model_reply_accepts_one_fence() -> None:
    fenced = "```json\n" + json.dumps({"diagnosis": "d", "diff": GOOD_DIFF}) + "\n```"
    assert parse_model_reply(fenced).diagnosis == "d"


def test_parse_model_reply_rejects_garbage() -> None:
    cases = ("not json", "[1, 2]", json.dumps({"diagnosis": "d"}), json.dumps({"diff": "x"}))
    for content in cases:
        with pytest.raises(MetaModelsResponseError):
            parse_model_reply(content)
    with pytest.raises(MetaModelsResponseError, match="fence"):
        parse_model_reply("```json\n" + json.dumps({"diagnosis": "d", "diff": "x"}))


def test_validate_diff_accepts_repairs() -> None:
    assert validate_diff(GOOD_DIFF) == GOOD_DIFF
    assert validate_diff(NEW_FILE_DIFF) == NEW_FILE_DIFF


def test_validate_diff_rejects_out_of_scope() -> None:
    outside = GOOD_DIFF.replace("src/apps/demo_api.py", "docs/notes.md")
    with pytest.raises(MetaModelsResponseError, match="outside the allowed scope"):
        validate_diff(outside)
    absolute = GOOD_DIFF.replace("a/src/apps/demo_api.py", "a//etc/passwd")
    with pytest.raises(MetaModelsResponseError, match="escapes"):
        validate_diff(absolute)
    traversal = GOOD_DIFF.replace("a/src/apps/demo_api.py", "a/src/../secret.txt")
    with pytest.raises(MetaModelsResponseError, match="escapes"):
        validate_diff(traversal)


def test_validate_diff_rejects_malformed() -> None:
    with pytest.raises(MetaModelsResponseError, match="no files"):
        validate_diff("just prose, no diff\n")
    with pytest.raises(MetaModelsResponseError, match="no hunks"):
        validate_diff("--- a/src/x.py\n+++ b/src/x.py\n")
    with pytest.raises(MetaModelsResponseError, match="without its --- header"):
        validate_diff("+++ b/src/x.py\n@@ -1 +1 @@\n+x\n")
    with pytest.raises(MetaModelsResponseError, match="outside a file body"):
        validate_diff("@@ -1 +1 @@\n+x\n")
    with pytest.raises(MetaModelsResponseError, match="not unified-diff content"):
        validate_diff("--- a/src/x.py\n+++ b/src/x.py\n@@ -1 +1 @@\nprose line\n")
    with pytest.raises(MetaModelsResponseError, match="exceeds"):
        validate_diff("x" * (MAX_DIFF_CHARS + 1))


def test_summarize_failed_report() -> None:
    summary = summarize_failed_report(_failed_report())
    assert summary.invariant_id == "AUTH-ADMIN-001"
    assert summary.invariant_version == 1
    assert summary.invariant_digest == DIGEST
    assert len(summary.failing_details) == 3
    text = build_verdict_summary(summary)
    assert "FAILED" in text and DIGEST in text and len(text) <= MAX_VERDICT_SUMMARY


def test_inconclusive_is_never_diagnosed() -> None:
    report = _failed_report()
    report["verdict"] = "INCONCLUSIVE"
    with pytest.raises(DiagnosisError, match="INCONCLUSIVE"):
        summarize_failed_report(report)


def test_passed_is_never_diagnosed() -> None:
    report = _failed_report()
    report["verdict"] = "PASSED"
    with pytest.raises(DiagnosisError, match="PASSED"):
        summarize_failed_report(report)


def test_forged_or_mismatched_reports_are_refused() -> None:
    bad_schema = _failed_report()
    bad_schema["schema_version"] = 99
    with pytest.raises(DiagnosisError, match="schema_version"):
        summarize_failed_report(bad_schema)
    bad_command = _failed_report()
    bad_command["command"] = "review"
    with pytest.raises(DiagnosisError, match="command"):
        summarize_failed_report(bad_command)
    bad_digest = _failed_report()
    assert isinstance(bad_digest["invariant"], dict)
    bad_digest["invariant"]["content_digest"] = "not-a-digest"
    with pytest.raises(DiagnosisError, match="content_digest"):
        summarize_failed_report(bad_digest)
    no_violations = _failed_report()
    no_violations["attempts"] = [
        {"index": 1, "outcome": "PASS", "evidence_hash": "h", "detail": ""}
    ]
    with pytest.raises(DiagnosisError, match="no violations"):
        summarize_failed_report(no_violations)


def test_diagnose_round_trip() -> None:
    script = _Script([_json_response(200, _completion_reply("root cause", GOOD_DIFF))])
    result = diagnose(
        script.client(),
        invariant_id="AUTH-ADMIN-001",
        invariant_version=1,
        invariant_text="requirement",
        verdict_summary="summary",
        code_excerpt="code",
    )
    assert result.diagnosis == "root cause"
    assert result.diff == GOOD_DIFF.strip("\n") + "\n"
    assert result.model == DEFAULT_MODEL
    sent = json.loads(script.calls[0].content.decode("utf-8"))
    assert TEST_KEY not in script.calls[0].content.decode("utf-8")
    assert "requirement" in sent["messages"][1]["content"]


def test_diagnose_rejects_bad_model_diff() -> None:
    script = _Script([_json_response(200, _completion_reply("d", "not a diff"))])
    with pytest.raises(MetaModelsResponseError, match="no files"):
        diagnose(
            script.client(),
            invariant_id="X",
            invariant_version=1,
            invariant_text="t",
            verdict_summary="s",
            code_excerpt="c",
        )


def test_render_marks_proposal_unverified() -> None:
    script = _Script([_json_response(200, _completion_reply())])
    result = diagnose(
        script.client(),
        invariant_id="X",
        invariant_version=1,
        invariant_text="t",
        verdict_summary="s",
        code_excerpt="c",
    )
    rendered = render_for_review(result)
    assert "UNVERIFIED MODEL PROPOSAL" in rendered
    assert "NOT A REPAIR" in rendered
    assert "independently verifies" in rendered
    assert TEST_KEY not in rendered


def test_error_strings_never_carry_the_key() -> None:
    cases: list[tuple[list[httpx.Response | Exception], type[MetaModelsError]]] = [
        ([_error_response(401, f"key {TEST_KEY} bad")], MetaModelsAuthError),
        ([_error_response(500, f"key {TEST_KEY} bad")], MetaModelsServerError),
        ([httpx.TimeoutException("slow")], MetaModelsTimeoutError),
    ]
    seen: list[str] = []
    for steps, error in cases:
        with pytest.raises(error) as caught:
            _Script(steps).client().list_models()
        seen.append(str(caught.value))
    with pytest.raises(MetaModelsRequestError) as caught:
        _Script([_json_response(200, {"data": []})]).client().complete(
            {"blob": "y" * (MAX_REQUEST_BYTES + 1)}
        )
    seen.append(str(caught.value))
    assert seen and all(TEST_KEY not in text for text in seen)


INVARIANT_YAML = """\
- id: AUTH-ADMIN-001
  version: 1
  title: t
  requirement: Every endpoint in scope must reject unauthenticated requests.
  scope:
    - /admin/users
"""


def _write_case(tmp_path: Path, verdict: str) -> tuple[Path, Path, Path]:
    report = _failed_report()
    report["verdict"] = verdict
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    invariant_path = tmp_path / "inv.yaml"
    invariant_path.write_text(INVARIANT_YAML, encoding="utf-8")
    excerpt_path = tmp_path / "excerpt.py"
    excerpt_path.write_text("code\n", encoding="utf-8")
    return report_path, invariant_path, excerpt_path


def test_entry_missing_key_exits_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    assert entry.main(["list-models"]) == entry.EXIT_ERROR
    assert "not configured" in capsys.readouterr().err


def test_entry_refuses_inconclusive_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MODEL_API_KEY", TEST_KEY)
    report, invariant, excerpt = _write_case(tmp_path, "INCONCLUSIVE")
    code = entry.main(
        [
            "diagnose",
            "--report",
            str(report),
            "--invariant-file",
            str(invariant),
            "--excerpt",
            str(excerpt),
        ]
    )
    assert code == entry.EXIT_ERROR
    assert "INCONCLUSIVE" in capsys.readouterr().err


def test_entry_maps_oversized_summary_to_exit_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MODEL_API_KEY", TEST_KEY)
    report = _failed_report()
    report["attempts"] = [
        {"index": i, "outcome": "VIOLATION", "evidence_hash": "h", "detail": "D" * 1000}
        for i in range(12)
    ]
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    invariant_path = tmp_path / "inv.yaml"
    invariant_path.write_text(INVARIANT_YAML, encoding="utf-8")
    excerpt_path = tmp_path / "excerpt.py"
    excerpt_path.write_text("code\n", encoding="utf-8")
    code = entry.main(
        [
            "diagnose",
            "--report",
            str(report_path),
            "--invariant-file",
            str(invariant_path),
            "--excerpt",
            str(excerpt_path),
        ]
    )
    assert code == entry.EXIT_ERROR
    assert "exceeds" in capsys.readouterr().err


def test_entry_refuses_version_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MODEL_API_KEY", TEST_KEY)
    report, invariant, excerpt = _write_case(tmp_path, "FAILED")
    invariant.write_text(INVARIANT_YAML.replace("version: 1", "version: 2"), encoding="utf-8")
    code = entry.main(
        [
            "diagnose",
            "--report",
            str(report),
            "--invariant-file",
            str(invariant),
            "--excerpt",
            str(excerpt),
        ]
    )
    assert code == entry.EXIT_ERROR
    err = capsys.readouterr().err
    assert "v2" in err and "v1" in err
