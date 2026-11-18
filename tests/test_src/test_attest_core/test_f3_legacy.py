"""P10 adapter behavior: provenance, markers, malformed input, isolation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from apps.cli import main as cli_main
from attest_core import f3_legacy as leg
from attest_core.f3_errors import F3Error, F3ParseError, F3SchemaError
from attest_core.f3_parse import parse_record_bytes
from attest_core.f3_records import validate_attempt
from attest_core.f3_validate import validate_package

VECTORS = Path(__file__).resolve().parent / "f3_legacy_vectors"
C = "campaign04"
MALFORMED: list[tuple[str, Any, Any, type[F3Error], str, str]] = [
    ("env", b"{oops", "e", F3ParseError, "PARSE", "8.2"),
    ("env", b"[1]", "e", F3SchemaError, "LEGACY", "12"),
    ("env", b'{"a": 1, "a": 2}', "e", F3ParseError, "PARSE", "8.2"),
    ("env", b'{"a": 1.5}', "e", F3ParseError, "PARSE", "8.2"),
    ("env", b"{} trailing", "e", F3ParseError, "PARSE", "8.2"),
    ("env", b"", "e", F3ParseError, "PARSE", "8.2"),
    ("env", "{}", "e", F3ParseError, "PARSE", "8.2"),
    ("env", b"{}", 7, F3SchemaError, "LEGACY", "12"),
    ("timing", b"", "t", F3ParseError, "PARSE", "8.2"),
    ("timing", "x", "t", F3ParseError, "PARSE", "8.2"),
    ("timing", b'{"record_type": "x"}\n\n', "t", F3ParseError, "PARSE", "8.2"),
    ("timing", b'{"record_type": "nope"}\n', "t", F3SchemaError, "LEGACY", "12"),
    ("timing", b'{"attempt": 1}\n', "t", F3SchemaError, "LEGACY", "12"),
    ("timing", b'{"record_type": "attempt", "attempt": "1"}', "t", F3SchemaError, "LEGACY", "12"),
    ("timing", b'{"record_type": "attempt", "attempt": true}', "t", F3SchemaError, "LEGACY", "12"),
    ("stderr", b"\xff\xfe", "s", F3ParseError, "PARSE", "8.2"),
]
_SUFFIX = {"timing": ".timing.jsonl", "env": ".env.json", "s3": ".json", "stderr": ".stderr.log"}


def _m(reason: str) -> dict[str, str]:
    return {"unavailable": reason}


def _bytes(rel: str) -> bytes:
    return (VECTORS / rel).read_bytes()


def _slot(stem: str) -> dict[str, tuple[bytes, str] | None]:
    out: dict[str, tuple[bytes, str] | None] = {}
    for role, suffix in _SUFFIX.items():
        path = VECTORS / "campaign04" / f"{stem}{suffix}"
        out[role] = (path.read_bytes(), f"{stem}{suffix}") if path.exists() else None
    return out


def _adapt(kind: str, payload: Any, path: Any) -> Any:
    return getattr(leg, f"adapt_{kind}")(payload, source_path=path)


def test_provenance_and_markers() -> None:
    timed = leg.adapt_timing(_bytes(f"{C}/repaired-1.timing.jsonl"), source_path="t")
    triples = [(v["provenance"]["line"], v["provenance"]["attempt"]) for v in timed[:3]]
    assert triples == [(1, 1), (2, 2), (3, 3)]
    total = timed[3]
    assert total["provenance"]["line"] == 4
    assert total["provenance"]["attempt"] == _m("total-carries-no-attempt-number")
    assert total["verdict"] is None and total["attempts_completed"] is None
    assert total["unavailable"] == "pre-identity-contract"
    first = timed[0]
    assert first["identity"]["campaign_id"] == _m("pre-identity-contract")
    assert first["target"] == _m("no-structured-target-in-legacy-source")
    assert first["workload"]["workload_id"] == _m("no-workload-declaration-in-legacy-source")
    assert first["input_manifest"] == _m("no-legacy-input-manifest")
    assert first["sample_class"] == _m("no-warm-up-marking-existed")
    assert first["pid"] == _m("pid-not-captured-in-legacy-collection")
    assert first["record_digest"] == _m("post-hoc-digests-deferred")
    assert first["compat"] == {"putative_target": "t"}
    cases = (
        ("env", f"{C}/repaired-1.env.json", "no-line-addressing-in-json-document"),
        ("s3", f"{C}/repaired-1.json", "no-line-addressing-in-json-document"),
        ("stderr", f"{C}/hanging-1.stderr.log", "opaque-text-no-record-lines"),
        ("summary", "synthetic/summary-1.json", "no-line-addressing-in-json-document"),
    )
    for kind, rel, line_reason in cases:
        prov = _adapt(kind, _bytes(rel), "s")["provenance"]
        assert prov["line"] == _m(line_reason)
        assert prov["attempt"] == _m("no-attempt-association-for-this-record-kind")
    env = leg.adapt_env(_bytes(f"{C}/repaired-1.env.json"), source_path="e")
    assert len(env["completion"]) == 7
    assert all(v == _m("not-collected-in-legacy-run") for v in env["completion"].values())


@pytest.mark.parametrize(("kind", "payload", "path", "exc", "rule", "section"), MALFORMED)
def test_malformed_fails_closed(
    kind: str, payload: Any, path: Any, exc: type[F3Error], rule: str, section: str
) -> None:
    with pytest.raises(exc) as caught:
        _adapt(kind, payload, path)
    assert caught.value.rule == rule and caught.value.section == section


def test_slot_semantics() -> None:
    full = leg.adapt_slot(_slot("repaired-1"), slot="repaired-1")
    assert full["missing"] == []
    assert sorted(full["artifacts"]) == ["env", "s3", "stderr", "timing"]
    hang = leg.adapt_slot(_slot("hanging-1"), slot="hanging-1")
    assert hang["missing"] == ["timing", "env", "s3"]
    assert sorted(hang["artifacts"]) == ["stderr"]
    assert hang["artifacts"]["stderr"]["source"]["content"].startswith("attest: error:")
    assert leg.adapt_stderr(b"", source_path="e.log")["source"] == {"content": "", "byte_length": 0}
    assert leg.adapt_slot({}, slot="x")["missing"] == ["timing", "env", "s3", "stderr"]
    bad: Any = ({"timing": (b"{}", "t")}, {"nope": None}, {"timing": [b"{}", "t"]})
    for mapping in bad:
        with pytest.raises(F3SchemaError):
            leg.adapt_slot(mapping, slot="x")
    with pytest.raises(F3SchemaError):
        leg.adapt_slot({"timing": (b"{}", "t")}, slot=7)  # type: ignore[arg-type]


def test_unknown_keys_preserved() -> None:
    line = b'{"record_type": "attempt", "attempt": 1, "x_custom": [1, "two", null]}'
    view = leg.adapt_timing(line, source_path="t")[0]
    assert view["source"]["x_custom"] == [1, "two", None]
    forged = leg.adapt_env(b'{"format": "forged", "record_kind": "attempt"}', source_path="e")
    assert forged["source"]["format"] == "forged" and forged["format"] == "legacy-v1-sidecar"
    assert "record_kind" not in forged


def test_duplicate_attempts_preserved() -> None:
    raw = b'{"record_type": "attempt", "attempt": 1}\n{"record_type": "attempt", "attempt": 1}\n'
    views = leg.adapt_timing(raw, source_path="t")
    got = [(v["provenance"]["line"], v["provenance"]["attempt"]) for v in views]
    assert got == [(1, 1), (2, 1)]


def test_quine_outcomes_and_determinism() -> None:
    wants = {"repaired-1": "PASS", "vulnerable-1": "VIOLATION", "crashing-1": "INFRA_FAILURE"}
    for stem, want in wants.items():
        raw = _bytes(f"{C}/{stem}.timing.jsonl")
        views = leg.adapt_timing(raw, source_path="t")
        assert [v["source"]["outcome"] for v in views[:3]] == [want] * 3
        parsed = [json.loads(line) for line in raw.decode().splitlines()]
        assert parsed == [v["source"] for v in views]
    crash = _bytes(f"{C}/crashing-1.json")
    assert leg.adapt_s3(crash, source_path="s")["source"] == json.loads(crash.decode())
    raw = _bytes(f"{C}/repaired-1.timing.jsonl")
    first = leg.to_canonical_bytes(leg.adapt_timing(raw, source_path="t"))
    assert leg.to_canonical_bytes(leg.adapt_timing(raw, source_path="t")) == first
    forward = leg.adapt_slot(_slot("repaired-1"), slot="repaired-1")
    items = list(_slot("repaired-1").items())
    backward = leg.adapt_slot(dict(reversed(items)), slot="repaired-1")
    assert leg.to_canonical_bytes(backward) == leg.to_canonical_bytes(forward)


def test_isolation() -> None:
    legacy = (VECTORS / "expected" / "stderr-hanging-1.bin").read_bytes()
    with pytest.raises(F3SchemaError) as first:
        parse_record_bytes(legacy)
    assert (first.value.rule, first.value.section) == ("V-B6", "7")
    with pytest.raises(F3SchemaError) as second:
        parse_record_bytes(b'{"record_kind": "legacy-v1-sidecar"}')
    assert (second.value.rule, second.value.section) == ("V-B6", "7")
    with pytest.raises(F3SchemaError):
        validate_attempt({"format": "legacy-v1-sidecar", "elapsed_s": "1.0"})
    with pytest.raises(F3SchemaError):
        validate_attempt({"record_kind": "attempt", "format": "legacy-v1-sidecar"})


def test_isolation_package_and_cli(
    tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    blob = (VECTORS / "expected" / "stderr-hanging-1.bin").read_bytes()
    (tmp_path / "legacy-view.json").write_bytes(blob)
    report = validate_package(tmp_path)
    assert len(report.findings) == 2 and report.severity == "INCOMPLETE"
    assert report.quorums == () and report.composition == ()
    assert cli_main(["validate", str(tmp_path)]) == 3
    payload = json.loads(capsysbinary.readouterr().out.decode("utf-8"))
    assert payload["severity"] == "INCOMPLETE"
