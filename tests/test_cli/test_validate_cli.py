"""F3 validate CLI: parsing, exits, and end-to-end emission."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from f3_identity_pkg import INVOCATION_1, INVOCATION_2
from f3_validate_pkg import campaign_dict, group_dicts, write_campaign

from apps.cli import build_parser, main
from attest_core.f3_digest import record_digest
from attest_sdk import canonical

EVIDENCE = b"s3-report-bytes-0"


def test_parser_registers_validate() -> None:
    args = build_parser().parse_args(["validate", "pkg"])
    assert (args.command, args.manifest_digest) == ("validate", None)
    assert str(args.package) == "pkg"


def test_parser_digest_passthrough() -> None:
    digest = "ab" * 32
    args = build_parser().parse_args(["validate", "pkg", "--manifest-digest", digest])
    assert args.manifest_digest == digest


def test_parser_rejects_bad_digest() -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["validate", "pkg", "--manifest-digest", "zzz"])
    assert exc.value.code == 3


def test_valid_package_exit_zero(
    tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    specs = [(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")]
    records = [campaign_dict(specs, warmups=[1], required=1)]
    records.extend(group_dicts(INVOCATION_1, "warmup"))
    records.extend(group_dicts(INVOCATION_2, "measured"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE})
    assert main(["validate", str(tmp_path)]) == 0
    out = capsysbinary.readouterr().out
    assert out.endswith(b"\n") and not out.endswith(b"\n\n")
    payload = canonical.parse_bytes(out)
    assert (payload["status"], payload["severity"]) == ("validated", "VALID")
    assert payload["quorums"][0]["met"] is True


def test_invalid_package_exit_three_with_report(
    tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured", target="baseline"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    assert main(["validate", str(tmp_path)]) == 3
    payload = canonical.parse_bytes(capsysbinary.readouterr().out)
    assert payload["severity"] == "INVALID"
    assert "R-ID9" in [f["rule"] for f in payload["findings"]]
    assert payload["quorums"] == []


def test_incomplete_exit_three(tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured", numbers=(1, 2)))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    assert main(["validate", str(tmp_path)]) == 3
    payload = canonical.parse_bytes(capsysbinary.readouterr().out)
    assert payload["severity"] == "INCOMPLETE"


def test_refused_exit_three_with_report(
    tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    manifest = json.loads((tmp_path / "manifest.json").read_bytes())
    manifest["canonicalization"] = {"name": "attest-canonical-json", "version": 99}
    (tmp_path / "manifest.json").write_bytes((json.dumps(manifest) + "\n").encode())
    (tmp_path / "manifest.sha256").write_text(record_digest("manifest", manifest) + "\n")
    assert main(["validate", str(tmp_path)]) == 3
    payload = canonical.parse_bytes(capsysbinary.readouterr().out)
    assert payload["status"] == "refused"
    assert any("canonicalizer" in f["reason"] for f in payload["findings"])


def test_infra_exit_three_with_report(
    tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert main(["validate", str(tmp_path / "absent")]) == 3
    payload = canonical.parse_bytes(capsysbinary.readouterr().out)
    assert payload["status"] == "infrastructure-failure"
    assert payload["severity"] is None


def test_malformed_args() -> None:
    """Missing positionals and bad flags are usage errors (exit 3)."""
    with pytest.raises(SystemExit) as exc:
        main(["validate"])
    assert exc.value.code == 3
    with pytest.raises(SystemExit) as bad:
        main(["validate", "pkg", "--manifest-digest", "zzz"])
    assert bad.value.code == 3


def test_output_error_exit_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    """An unwritable stdout reports the error and exits 3."""

    class Broken:
        @property
        def buffer(self) -> Any:
            raise OSError("broken pipe")

    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    monkeypatch.setattr(sys, "stdout", Broken())
    assert main(["validate", str(tmp_path)]) == 3
    assert b"attest: error" in capsysbinary.readouterr().err


def test_held_digest_acceptance(tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    """A held digest verifies the manifest bytes (§8.1, F3-B01)."""
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    sidecar = (tmp_path / "manifest.sha256").read_text().strip()
    assert main(["validate", str(tmp_path), "--manifest-digest", sidecar]) == 0
    first = canonical.parse_bytes(capsysbinary.readouterr().out)
    assert (first["status"], first["severity"]) == ("validated", "VALID")
    assert main(["validate", str(tmp_path), "--manifest-digest", "00" * 32]) == 3
    second = canonical.parse_bytes(capsysbinary.readouterr().out)
    assert "V-B1" in [f["rule"] for f in second["findings"]]
