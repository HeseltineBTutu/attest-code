"""F3 P8 acceptance: refusal, infrastructure, determinism, trust."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from f3_fixtures import assert_fails
from f3_identity_pkg import INVOCATION_1, INVOCATION_2
from f3_series_pkg import INVOCATION_3
from f3_validate_pkg import (
    TRIPLE8,
    attempt_dict,
    campaign_dict,
    env_dict,
    group_dicts,
    total_dict,
    write_campaign,
)

from attest_core import f3_fields as ff
from attest_core import f3_paths as paths_mod
from attest_core.f3_digest import record_digest
from attest_core.f3_validate import validate_package

EVIDENCE = b"s3-report-bytes-0"
RID = "ffffffff-ffff-4fff-8fff-ffffffffffff"


def _run(root: Path, records: list[Any], evidence: dict[str, bytes], record_ids: Any = None) -> Any:
    write_campaign(root, records, evidence)
    if record_ids is None:
        return validate_package(root)
    return validate_package(root, record_ids=record_ids)


def test_pin_refusal(tmp_path: Path) -> None:
    """Unknown pin versions refuse the package (§8.2), naming the pin."""
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[])]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    manifest = json.loads((tmp_path / "manifest.json").read_bytes())
    manifest["digest_projection"] = {"name": "f3-digest-projection", "version": 99}
    (tmp_path / "manifest.json").write_bytes((json.dumps(manifest) + "\n").encode())
    (tmp_path / "manifest.sha256").write_text(record_digest("manifest", manifest) + "\n")
    report = validate_package(tmp_path)
    assert report.status == "refused"
    assert report.severity == "INVALID"
    assert (report.inventory, report.quorums, report.composition) == ((), (), ())
    assert any("projection" in f.reason for f in report.findings)


def test_infra_missing_root(tmp_path: Path) -> None:
    """An unusable root is infrastructure failure, never a success."""
    report = validate_package(tmp_path / "absent")
    assert report.status == "infrastructure-failure"
    assert (report.severity, report.findings) == (None, ())
    assert (report.inventory, report.measurements) == ((), ())


def test_infra_midrun_preserves_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A root lost after P2 keeps completed findings with infra status."""
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[])]
    records.extend(group_dicts(INVOCATION_1, "measured", target="baseline"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    calls = 0
    real_open = paths_mod.open_root

    def flaky(root: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("package root unusable: simulated")
        return real_open(root)

    monkeypatch.setattr(paths_mod, "open_root", flaky)
    report = validate_package(tmp_path)
    assert report.status == "infrastructure-failure"
    assert "R-ID9" in [f.rule for f in report.findings]
    assert [i.invocation_id for i in report.inventory] == [INVOCATION_1]
    assert report.severity == "INVALID"


def test_malformed_inputs_refused(tmp_path: Path) -> None:
    """Caller errors raise; they never become validation results."""
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[])]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    write_campaign(tmp_path, records, {INVOCATION_1: EVIDENCE})
    key = ("repaired", *TRIPLE8, 1)
    root: Any = b"bytes-root"
    with pytest.raises(ValueError, match="byte paths"):
        validate_package(root)
    with pytest.raises(ValueError, match="SHA-256 hex"):
        validate_package(tmp_path, manifest_digest="zzz")
    assert_fails(
        lambda _: validate_package(tmp_path, record_ids={key: "not-a-uuid"}),
        None,
        rule="V-B6",
        section="7.5",
        location="$.record_id",
        reason="UUID",
    )
    bad: dict[str, Any] = {"note": 7}
    assert_fails(
        lambda _: validate_package(tmp_path, context=bad),
        None,
        rule="V-B6",
        section="7.5",
        location="$.context.note",
        reason="strings",
    )


def test_deterministic_with_fixed_ids(tmp_path: Path) -> None:
    """Same bytes plus fixed ids validate byte-identically, twice."""
    specs = [(INVOCATION_1, "warmup"), (INVOCATION_2, "measured")]
    records = [campaign_dict(specs, warmups=[1], required=1)]
    records.extend(group_dicts(INVOCATION_1, "warmup"))
    records.extend(group_dicts(INVOCATION_2, "measured"))
    evidence = {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE}
    key = ("repaired", *TRIPLE8, 1)
    write_campaign(tmp_path, records, evidence)
    first = validate_package(tmp_path, record_ids={key: RID})
    second = validate_package(tmp_path, record_ids={key: RID})
    assert first == second
    minted = validate_package(tmp_path)
    assert minted.composition[0].summary.record_id != RID
    assert ff.uuid4(minted.composition[0].summary.record_id, "7.5", "$")
    assert minted.composition[0].summary.median_s == first.composition[0].summary.median_s


def test_verdict_opacity_end_to_end(tmp_path: Path) -> None:
    """Opposite stored verdicts change carried values only (M2)."""
    campaign = campaign_dict([(INVOCATION_1, "measured")], warmups=[], required=1)
    made = [attempt_dict(INVOCATION_1, n) for n in (1, 2, 3)]
    environment = env_dict(INVOCATION_1)
    passing = total_dict(INVOCATION_1, verdict="PASSED")
    failing = {**passing, "verdict": "FAILED"}
    key = ("repaired", *TRIPLE8, 1)
    reports = []
    for name, tot in (("a", passing), ("b", failing)):
        root = tmp_path / name
        root.mkdir()
        records = [campaign, *made, tot, environment]
        reports.append(_run(root, records, {INVOCATION_1: EVIDENCE}, {key: RID}))
    first, second = reports
    assert first.composition[0].summary == second.composition[0].summary
    assert [m.m1 for m in first.measurements] == [m.m1 for m in second.measurements]
    assert first.quorums == second.quorums
    assert first.composition[0].stored_verdicts == ((INVOCATION_1, "PASSED"),)
    assert second.composition[0].stored_verdicts == ((INVOCATION_1, "FAILED"),)


def test_absent_summary_end_to_end(tmp_path: Path) -> None:
    """A censored series composes an explicit absence, staying VALID."""
    specs = [(INVOCATION_1, "measured")]
    records = [campaign_dict(specs, warmups=[], required=1)]
    made = [attempt_dict(INVOCATION_1, n, censored=True) for n in (1, 2, 3)]
    records.extend([*made, total_dict(INVOCATION_1), env_dict(INVOCATION_1)])
    report = _run(tmp_path, records, {INVOCATION_1: EVIDENCE})
    (one,) = report.composition
    assert one.summary is None
    assert "0 successful" in (one.absent_reason or "")
    assert report.quorums[0].excluded == ((INVOCATION_1, "measurement-inconclusive"),)
    assert (report.status, report.severity) == ("validated", "VALID")


def test_per_series_isolation_end_to_end(tmp_path: Path) -> None:
    """Quorum and summaries evaluate per series, never pooled (AQ-2)."""
    specs = [(INVOCATION_1, "measured"), (INVOCATION_2, "warmup"), (INVOCATION_3, "measured")]
    records = [
        campaign_dict(
            specs,
            warmups=[2],
            required=2,
            targets=["repaired", "baseline"],
            entry_targets={INVOCATION_2: "baseline", INVOCATION_3: "baseline"},
        )
    ]
    records.extend(group_dicts(INVOCATION_1, "measured"))
    records.extend(group_dicts(INVOCATION_2, "warmup", target="baseline"))
    records.extend(group_dicts(INVOCATION_3, "measured", target="baseline"))
    evidence = {INVOCATION_1: EVIDENCE, INVOCATION_2: EVIDENCE, INVOCATION_3: EVIDENCE}
    report = _run(tmp_path, records, evidence)
    assert [q.met for q in report.quorums] == [False, False]
    assert [s.summary.n_total for s in report.composition] == [3, 3]
    first, second = (set(s.summary.observation_ids) for s in report.composition)
    assert first.isdisjoint(second)
    assert report.severity == "VALID"
