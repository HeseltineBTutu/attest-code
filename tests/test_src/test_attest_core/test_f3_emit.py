"""F3 report emission: faithful canonical JSON serialization (unit)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

from f3_identity_pkg import INVOCATION_1, INVOCATION_2
from f3_validate_pkg import (
    attempt_dict,
    campaign_dict,
    env_dict,
    group_dicts,
    total_dict,
    write_campaign,
)

from attest_core.f3_digest import record_digest
from attest_core.f3_emit import emit_report, to_jsonable
from attest_core.f3_validate import validate_package
from attest_sdk import canonical

EVIDENCE = b"s3-report-bytes-0"


def _records(specs: list[Any], **kw: Any) -> list[dict[str, Any]]:
    warmups = [i + 1 for i, (_, sample) in enumerate(specs) if sample == "warmup"]
    out = [campaign_dict(specs, warmups=warmups, required=1, **kw)]
    for inv, sample in specs:
        out.extend(group_dicts(inv, sample))
    return out


def _validate(root: Path, records: list[dict[str, Any]], evidence: dict[str, bytes]) -> Any:
    write_campaign(root, records, evidence)
    return validate_package(root)


def test_exact_keys_and_mechanical_spelling(tmp_path: Path) -> None:
    """Emission uses implemented field names; tuples spell as lists."""
    specs = [(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")]
    report = _validate(tmp_path, _records(specs), {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE})
    payload = to_jsonable(report)
    assert sorted(payload) == [
        "attributes",
        "campaign_id",
        "composition",
        "diagnostics",
        "findings",
        "inventory",
        "measurements",
        "quorums",
        "severity",
        "status",
    ]
    (quorum,) = payload["quorums"]
    assert sorted(quorum) == [
        "eligible",
        "eligible_count",
        "excluded",
        "met",
        "required_successful",
        "series_key",
    ]
    assert "eligible_invocations" not in quorum
    assert quorum["excluded"] == [[INVOCATION_1, "warmup"]]
    assert payload["attributes"][0]["machine_class"] == ["AMD EPYC 7763", 17179869184]
    assert payload["composition"][0]["stored_verdicts"] == [
        [INVOCATION_1, "PASSED"],
        [INVOCATION_2, "PASSED"],
    ]
    assert payload["composition"][0]["summary"]["series"] == "repaired/b1/latency"
    assert payload["composition"][0]["summary"]["statistic"] == "attempt"


def test_absent_summary_preserved(tmp_path: Path) -> None:
    """Absent summaries stay null-with-reason, never omitted or zeroed."""
    made = [attempt_dict(INVOCATION_1, n, censored=True) for n in (1, 2, 3)]
    records = [campaign_dict([(INVOCATION_1, "measured")], warmups=[], required=1)]
    records.extend([*made, total_dict(INVOCATION_1), env_dict(INVOCATION_1)])
    report = _validate(tmp_path, records, {INVOCATION_1: EVIDENCE})
    (one,) = to_jsonable(report)["composition"]
    assert one["summary"] is None
    assert "0 successful" in one["absent_reason"]


def test_nulls_preserved(tmp_path: Path) -> None:
    """Null fields are emitted as null, never silently omitted."""
    empty = to_jsonable(validate_package(tmp_path / "absent"))
    assert empty["severity"] is None and empty["campaign_id"] is None
    assert "severity" in empty and "campaign_id" in empty
    specs = [(INVOCATION_1, "measured")]
    write_campaign(tmp_path, _records(specs), {INVOCATION_1: EVIDENCE})
    manifest = json.loads((tmp_path / "manifest.json").read_bytes())
    manifest["digest_projection"] = {"name": "f3-digest-projection", "version": 99}
    (tmp_path / "manifest.json").write_bytes((json.dumps(manifest) + "\n").encode())
    (tmp_path / "manifest.sha256").write_text(record_digest("manifest", manifest) + "\n")
    refused = to_jsonable(validate_package(tmp_path))
    assert refused["status"] == "refused"
    assert any("projection" in f["reason"] for f in refused["findings"])


def test_deterministic_bytes(tmp_path: Path) -> None:
    """Same report serializes to identical bytes with canonical key order."""
    specs = [(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")]
    report = _validate(tmp_path, _records(specs), {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE})
    assert to_jsonable(report) == to_jsonable(report)
    first = canonical.canonicalize(to_jsonable(report))
    assert canonical.canonicalize(to_jsonable(report)) == first
    assert first.startswith(b'{"attributes":')


def test_canonical_readback(tmp_path: Path) -> None:
    """Emitted bytes parse under the strict parser to the same payload."""
    specs = [(INVOCATION_1, "measured")]
    report = _validate(tmp_path, _records(specs), {INVOCATION_1: EVIDENCE})
    payload = to_jsonable(report)
    assert canonical.parse_bytes(canonical.canonicalize(payload) + b"\n") == payload


def test_nfc_boundary_is_mechanism_behavior(tmp_path: Path) -> None:
    """Non-NFC context normalizes in bytes only; the report is untouched."""
    specs = [(INVOCATION_1, "measured")]
    write_campaign(tmp_path, _records(specs), {INVOCATION_1: EVIDENCE})
    decomposed = "é"
    assert [hex(ord(c)) for c in decomposed] == ["0x65", "0x301"]
    decomposed = "e\u0301"
    assert [hex(ord(c)) for c in decomposed] == ["0x65", "0x301"]
    report = validate_package(tmp_path, context={"note": decomposed})
    parsed = canonical.parse_bytes(canonical.canonicalize(to_jsonable(report)))
    assert parsed["composition"][0]["summary"]["context"] == {"note": "\u00e9"}
    assert report.composition[0].summary is not None
    assert report.composition[0].summary.context == {"note": decomposed}


def test_no_mutation(tmp_path: Path) -> None:
    """Serialization and emission leave the report object untouched."""
    specs = [(INVOCATION_1, "measured")]
    report = _validate(tmp_path, _records(specs), {INVOCATION_1: EVIDENCE})
    before = repr(report)
    to_jsonable(report)
    emit_report(report, io.BytesIO())
    assert repr(report) == before


def test_emit_byte_contract(tmp_path: Path) -> None:
    """Emission is exactly canonical bytes plus one newline."""
    specs = [(INVOCATION_1, "measured")]
    report = _validate(tmp_path, _records(specs), {INVOCATION_1: EVIDENCE})
    stream = io.BytesIO()
    emit_report(report, stream)
    assert stream.getvalue() == canonical.canonicalize(to_jsonable(report)) + b"\n"


def test_ordering_preserved(tmp_path: Path) -> None:
    """Findings, inventory, and measurements keep report order."""
    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "measured")]
    out = [campaign_dict(specs, warmups=[], required=1)]
    out.extend(group_dicts(INVOCATION_1, "measured", numbers=(1, 2)))
    out.extend(group_dicts(INVOCATION_2, "measured"))
    report = _validate(tmp_path, out, {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE})
    payload = to_jsonable(report)
    assert [f["rule"] for f in payload["findings"]] == [f.rule for f in report.findings]
    assert [i["invocation_id"] for i in payload["inventory"]] == [INVOCATION_1, INVOCATION_2]
    assert [m["invocation_id"] for m in payload["measurements"]] == [INVOCATION_1, INVOCATION_2]


def test_no_invented_digest_fields(tmp_path: Path) -> None:
    """Emission defines no report digests (records/manifests only)."""

    def keys(value: Any, found: set[str]) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                found.add(key)
                keys(item, found)
        elif isinstance(value, list):
            for item in value:
                keys(item, found)

    specs = [(INVOCATION_1, "measured")]
    report = _validate(tmp_path, _records(specs), {INVOCATION_1: EVIDENCE})
    found: set[str] = set()
    keys(to_jsonable(report), found)
    assert not (found & {"digest", "report_digest", "manifest_digest", "sha256"})
