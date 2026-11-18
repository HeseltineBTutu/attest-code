"""F3 legacy adapter: sidecars to explicit compat views (§12, library-only)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn

from attest_core.f3_errors import F3Error, F3ParseError, F3SchemaError
from attest_sdk import canonical
from attest_sdk.errors import AttestError

FORMAT_TAG = "legacy-v1-sidecar"
QUORUM_BASIS = "attempt-pool-pre-f3-convention (descriptive only; not a policy invocation quorum)"
WARMUP_NOTE = "no warm-up marking existed; cold-start effects included."
ROLE_ORDER = ("timing", "env", "s3", "stderr")
COMPLETION_FIELDS = (
    "distribution",
    "logical_processor_count",
    "memory_available_bytes",
    "cgroup_limits",
    "container_runtime",
    "runner_settings",
    "interference",
)
_IDENTITY_KEYS = ("campaign_id", "invocation_id", "record_id")
_WORKLOAD_KEYS = ("workload_class", "workload_id", "input_digest")
R = {
    "identity": "pre-identity-contract",
    "target": "no-structured-target-in-legacy-source",
    "workload": "no-workload-declaration-in-legacy-source",
    "warmup": "no-warm-up-marking-existed",
    "pid": "pid-not-captured-in-legacy-collection",
    "digest": "post-hoc-digests-deferred",
    "env": "not-collected-in-legacy-run",
    "manifest": "no-legacy-input-manifest",
    "line_json": "no-line-addressing-in-json-document",
    "line_text": "opaque-text-no-record-lines",
    "attempt_total": "total-carries-no-attempt-number",
    "attempt_kind": "no-attempt-association-for-this-record-kind",
}


def _refuse(cls: type[F3Error], rule: str, section: str, loc: str, reason: str) -> NoReturn:
    """Raise a fail-closed F3 diagnostic (caller passes the exact rule)."""
    raise cls(rule=rule, section=section, location=loc, reason=reason)


def _prov(path: Any, line: Any, attempt: Any) -> dict[str, Any]:
    """Provenance object; path must be str, line/attempt observed or marked."""
    if not isinstance(path, str):
        _refuse(F3SchemaError, "LEGACY", "12", "$.provenance", "source path must be str")
    return {"source_path": path, "line": line, "attempt": attempt}


def _base(path: str, line: Any, attempt: Any) -> dict[str, Any]:
    """View skeleton: tag, provenance, compat stem, and unavailable markers."""
    prov = _prov(path, line, attempt)
    stem = path.rsplit("/", 1)[-1].split(".", 1)[0]
    return {
        "format": FORMAT_TAG,
        "provenance": prov,
        "compat": {"putative_target": stem},
        "identity": {k: {"unavailable": R["identity"]} for k in _IDENTITY_KEYS},
        "target": {"unavailable": R["target"]},
        "workload": {k: {"unavailable": R["workload"]} for k in _WORKLOAD_KEYS},
        "input_manifest": {"unavailable": R["manifest"]},
        "sample_class": {"unavailable": R["warmup"]},
        "record_digest": {"unavailable": R["digest"]},
    }


def _parse_object(data: bytes, *, location: str) -> dict[str, Any]:
    """Strict-parse one JSON document; byte/shape failures fail closed."""
    if not isinstance(data, bytes):
        _refuse(F3ParseError, "PARSE", "8.2", location, "input must be bytes")
    try:
        value = canonical.parse_bytes(data)
    except AttestError as exc:
        _refuse(F3ParseError, "PARSE", "8.2", location, f"{exc.reason_class}: {exc}")
    if not isinstance(value, dict):
        _refuse(F3SchemaError, "LEGACY", "12", location, "top-level JSON value must be an object")
    return value


def _split_lines(data: bytes) -> list[tuple[int, bytes]]:
    """1-based physical lines; empty input and blank lines fail closed."""
    parts = data.split(b"\n")
    if parts and parts[-1] == b"":
        parts.pop()
    if not parts:
        _refuse(F3ParseError, "PARSE", "8.2", "$", "empty timing input")
    if any(raw == b"" for raw in parts):
        _refuse(F3ParseError, "PARSE", "8.2", "$", "blank line in timing input")
    return list(enumerate(parts, 1))


def adapt_timing(data: bytes, *, source_path: str) -> list[dict[str, Any]]:
    """Adapt one timing JSONL document to per-line attempt/total views."""
    if not isinstance(data, bytes):
        _refuse(F3ParseError, "PARSE", "8.2", "$", "input must be bytes")
    views: list[dict[str, Any]] = []
    for lineno, raw in _split_lines(data):
        loc = f"$.line[{lineno}]"
        obj = _parse_object(raw, location=loc)
        kind = obj.get("record_type")
        if kind == "attempt":
            if type(obj.get("attempt")) is not int:
                _refuse(F3SchemaError, "LEGACY", "12", loc, "attempt line needs int attempt")
            view = _base(source_path, lineno, obj["attempt"])
            view["source"] = obj
            view["pid"] = {"unavailable": R["pid"]}
        elif kind == "total":
            view = _base(source_path, lineno, {"unavailable": R["attempt_total"]})
            view["source"] = obj
            view["verdict"] = None
            view["attempts_completed"] = None
            view["unavailable"] = R["identity"]
        else:
            _refuse(F3SchemaError, "LEGACY", "12", loc, f"bad record_type: {kind!r}")
        views.append(view)
    return views


def adapt_env(data: bytes, *, source_path: str) -> dict[str, Any]:
    """Adapt one legacy environment JSON document (keys verbatim)."""
    view = _base(source_path, {"unavailable": R["line_json"]}, {"unavailable": R["attempt_kind"]})
    view["source"] = _parse_object(data, location="$")
    view["completion"] = {key: {"unavailable": R["env"]} for key in COMPLETION_FIELDS}
    return view


def adapt_s3(data: bytes, *, source_path: str) -> dict[str, Any]:
    """Adapt one S3 report JSON document: parsed values pass through opaquely."""
    view = _base(source_path, {"unavailable": R["line_json"]}, {"unavailable": R["attempt_kind"]})
    view["source"] = _parse_object(data, location="$")
    return view


def adapt_stderr(data: bytes, *, source_path: str) -> dict[str, Any]:
    """Adapt opaque stderr bytes; empty content is valid, never missing."""
    if not isinstance(data, bytes):
        _refuse(F3ParseError, "PARSE", "8.2", "$", "input must be bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        _refuse(F3ParseError, "PARSE", "8.2", "$", f"invalid-utf8: {exc}")
    view = _base(source_path, {"unavailable": R["line_text"]}, {"unavailable": R["attempt_kind"]})
    view["source"] = {"content": text, "byte_length": len(data)}
    return view


def adapt_summary(data: bytes, *, source_path: str) -> dict[str, Any]:
    """Adapt one legacy summary document with the descriptive quorum basis."""
    view = _base(source_path, {"unavailable": R["line_json"]}, {"unavailable": R["attempt_kind"]})
    view["source"] = _parse_object(data, location="$")
    view["quorum_basis"] = QUORUM_BASIS
    view["warmup_invocations"] = []
    view["warmup_note"] = WARMUP_NOTE
    return view


_ADAPT = {"timing": adapt_timing, "env": adapt_env, "s3": adapt_s3, "stderr": adapt_stderr}


def adapt_slot(artifacts: Mapping[str, tuple[bytes, str] | None], *, slot: str) -> dict[str, Any]:
    """Adapt one slot's available artifacts; missing roles named, never padded."""
    if not isinstance(slot, str):
        _refuse(F3SchemaError, "LEGACY", "12", "$.slot", "slot must be str")
    if not isinstance(artifacts, Mapping):
        _refuse(F3SchemaError, "LEGACY", "12", "$", "artifacts must be a role mapping")
    unknown = sorted(set(artifacts) - set(ROLE_ORDER))
    if unknown:
        _refuse(F3SchemaError, "LEGACY", "12", "$", f"unknown artifact roles: {unknown}")
    views: dict[str, Any] = {}
    missing: list[str] = []
    for role in ROLE_ORDER:
        item = artifacts.get(role)
        if item is None:
            missing.append(role)
            continue
        if not (isinstance(item, tuple) and len(item) == 2):
            _refuse(F3SchemaError, "LEGACY", "12", f"$.{role}", "role value must be (bytes, path)")
        data, path = item
        views[role] = _ADAPT[role](data, source_path=path)
    return {
        "format": FORMAT_TAG,
        "slot": slot,
        "compat": {"slot_ref": slot},
        "artifacts": views,
        "missing": missing,
    }


def to_canonical_bytes(view: Any) -> bytes:
    """Serialize a view deterministically: canonical JSON plus newline."""
    return canonical.canonicalize(view) + b"\n"
