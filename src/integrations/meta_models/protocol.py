"""Diagnose-only request/response contract for the Meta Model API.

Builds bounded chat-completion payloads from operator-selected inputs and
validates untrusted model output. Nothing here touches verdicts,
approvals, evidence, or the repository.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from integrations.meta_models.errors import MetaModelsConfigError, MetaModelsResponseError

MAX_INVARIANT_ID = 128
MAX_INVARIANT_TEXT = 8000
MAX_VERDICT_SUMMARY = 8000
MAX_CODE_EXCERPT = 16000
MAX_DIAGNOSIS_CHARS = 32000
MAX_DIFF_CHARS = 65536
ALLOWED_DIFF_PREFIXES = ("src/", "tests/")
"""Diff paths must be relative and stay under these repository prefixes."""

_EXCERPT_BEGIN = "--- begin code excerpt ---"
_EXCERPT_END = "--- end code excerpt ---"

SYSTEM_PROMPT = """\
You diagnose one failed invariant verification for Attest Code, an \
independent verification layer. The verifier's verdict stands; you only \
explain the failure and propose a repair for human review.

Reply with exactly one JSON object and nothing else:
{"diagnosis": "<root-cause explanation>", "diff": "<unified diff>"}.

Rules for "diff": a unified diff with ---/+++ file headers and @@ hunks
that repairs the excerpt. Touch only files under src/ or tests/. Never \
include verdicts, approvals, credentials, or unrelated changes.\
"""


def require_text(value: str, *, name: str, maximum: int) -> str:
    """Reject empty or oversized required input (lengths only, never echoed)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters ({len(value)})")
    return value


def _check_delimiters(value: str, name: str) -> None:
    for marker in (_EXCERPT_BEGIN, _EXCERPT_END):
        if marker in value:
            raise ValueError(f"{name} must not contain the delimiter line {marker!r}")


def build_chat_payload(
    *,
    model: str,
    invariant_id: str,
    invariant_version: int,
    invariant_text: str,
    verdict_summary: str,
    code_excerpt: str,
) -> dict[str, Any]:
    """Build the bounded chat-completion payload for one diagnosis."""
    name = model.strip()
    if not name:
        raise MetaModelsConfigError("model must be non-empty")
    if "contributor" in name.lower():
        raise MetaModelsConfigError("refusing contributor-mode model")
    if isinstance(invariant_version, bool) or not isinstance(invariant_version, int):
        raise ValueError("invariant_version must be an integer")
    if invariant_version < 1:
        raise ValueError("invariant_version must be >= 1")
    ident = require_text(invariant_id, name="invariant_id", maximum=MAX_INVARIANT_ID)
    requirement = require_text(invariant_text, name="invariant_text", maximum=MAX_INVARIANT_TEXT)
    summary = require_text(verdict_summary, name="verdict_summary", maximum=MAX_VERDICT_SUMMARY)
    excerpt = require_text(code_excerpt, name="code_excerpt", maximum=MAX_CODE_EXCERPT)
    for field, label in (
        (requirement, "invariant_text"),
        (summary, "verdict_summary"),
        (excerpt, "code_excerpt"),
    ):
        _check_delimiters(field, label)
    user_message = (
        f"Invariant: {ident.strip()} v{invariant_version}\n"
        f"Requirement: {requirement.strip()}\n"
        "\nVerification summary:\n"
        f"{summary.strip()}\n"
        f"\n{_EXCERPT_BEGIN}\n{excerpt.strip()}\n{_EXCERPT_END}\n"
        '\nReply with exactly one JSON object: {"diagnosis": "...", "diff": "..."}.'
    )
    return {
        "model": name,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    }


def parse_model_list(data: Any) -> list[str]:
    """Extract model identifiers from a GET /models response body."""
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise MetaModelsResponseError("malformed model list response")
    models: list[str] = []
    for entry in data["data"]:
        if not isinstance(entry, dict):
            raise MetaModelsResponseError("malformed model entry in list response")
        ident = entry.get("id")
        if not isinstance(ident, str) or not ident.strip():
            raise MetaModelsResponseError("malformed model entry in list response")
        models.append(ident)
    return models


def parse_completion(data: Any) -> str:
    """Extract assistant content from a chat-completion response body."""
    if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
        raise MetaModelsResponseError("malformed completion response")
    choices = data["choices"]
    if not choices or not isinstance(choices[0], dict):
        raise MetaModelsResponseError("completion response has no choices")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise MetaModelsResponseError("completion choice has no message content")
    content = message.get("content")
    if not isinstance(content, str):
        raise MetaModelsResponseError("completion choice has no message content")
    if not content.strip():
        raise MetaModelsResponseError("completion choice content is empty")
    return content


@dataclasses.dataclass(frozen=True)
class ModelReply:
    """Validated model output: an explanation plus a proposed (unapplied) diff."""

    diagnosis: str
    diff: str


def parse_model_reply(content: str) -> ModelReply:
    """Parse the assistant message as {"diagnosis": str, "diff": str}.

    One surrounding Markdown fence is tolerated; anything else must be
    the bare JSON object. Extra keys are ignored. The diff is returned
    unstripped of structure but normalized to end with one newline.
    """
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) < 3 or lines[-1].strip() != "```":
            raise MetaModelsResponseError("model reply has an unterminated code fence")
        text = "\n".join(lines[1:-1])
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MetaModelsResponseError(f"model reply is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise MetaModelsResponseError("model reply must be a JSON object")
    diagnosis = data.get("diagnosis")
    diff = data.get("diff")
    if not isinstance(diagnosis, str) or not diagnosis.strip():
        raise MetaModelsResponseError("model reply has no usable diagnosis")
    if not isinstance(diff, str) or not diff.strip():
        raise MetaModelsResponseError("model reply has no usable diff")
    if len(diagnosis) > MAX_DIAGNOSIS_CHARS:
        raise MetaModelsResponseError(f"diagnosis exceeds {MAX_DIAGNOSIS_CHARS} characters")
    if len(diff) > MAX_DIFF_CHARS:
        raise MetaModelsResponseError(f"diff exceeds {MAX_DIFF_CHARS} characters")
    return ModelReply(diagnosis=diagnosis.strip(), diff=diff.strip("\n") + "\n")


def _diff_side(text: str) -> str:
    return text.split("\t")[0].strip()


def _validate_diff_path(side: str, *, allowed_prefixes: tuple[str, ...]) -> str | None:
    if side == "/dev/null":
        return None
    path = side[2:] if side.startswith(("a/", "b/")) else side
    if not path or path.startswith("/") or "\\" in path or ".." in path.split("/"):
        raise MetaModelsResponseError(f"diff path escapes its scope: {side!r}")
    if not path.startswith(allowed_prefixes):
        raise MetaModelsResponseError(f"diff path is outside the allowed scope: {side!r}")
    return path


def validate_diff(diff: str, *, allowed_prefixes: tuple[str, ...] = ALLOWED_DIFF_PREFIXES) -> str:
    """Validate unified-diff structure and confine every path to the scope.

    Requires at least one file with ---/+++ headers and one @@ hunk.
    Accepts /dev/null on either side (addition/deletion). Body lines must
    look like unified-diff content. Returns the unchanged diff on success.
    """
    if not isinstance(diff, str) or not diff.strip():
        raise MetaModelsResponseError("model reply diff is empty")
    if len(diff) > MAX_DIFF_CHARS:
        raise MetaModelsResponseError(f"diff exceeds {MAX_DIFF_CHARS} characters")
    if not allowed_prefixes:
        raise ValueError("allowed_prefixes must list at least one prefix")
    files = 0
    hunks = 0
    old: str | None = None
    in_body = False
    for raw in diff.strip("\n").splitlines():
        line = raw.rstrip("\r")
        if line.startswith(("diff --git ", "Index: ", "index ")) or line.startswith(
            ("new file", "deleted file", "old mode", "new mode")
        ):
            continue
        if line.startswith("--- "):
            if old is not None:
                raise MetaModelsResponseError("diff has a --- header without its +++ header")
            old = _diff_side(line[4:])
            in_body = False
            continue
        if line.startswith("+++ "):
            if old is None:
                raise MetaModelsResponseError("diff has a +++ header without its --- header")
            new = _diff_side(line[4:])
            old_path = _validate_diff_path(old, allowed_prefixes=allowed_prefixes)
            new_path = _validate_diff_path(new, allowed_prefixes=allowed_prefixes)
            if old_path is None and new_path is None:
                raise MetaModelsResponseError("diff file has no usable path")
            old = None
            files += 1
            in_body = True
            continue
        if line.startswith("@@ "):
            if not in_body:
                raise MetaModelsResponseError("diff hunk appears outside a file body")
            hunks += 1
            continue
        if in_body and line != "" and not line.startswith((" ", "+", "-", "\\")):
            raise MetaModelsResponseError(f"diff body line is not unified-diff content: {line!r}")
    if old is not None:
        raise MetaModelsResponseError("diff ends with a --- header without its +++ header")
    if files == 0:
        raise MetaModelsResponseError("diff contains no files")
    if hunks == 0:
        raise MetaModelsResponseError("diff contains no hunks")
    return diff
