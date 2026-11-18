"""P10 golden vectors: byte-exact adapter outputs and fixture integrity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from attest_core import f3_legacy as leg

VECTORS = Path(__file__).resolve().parent / "f3_legacy_vectors"
C = "campaign04"
CASES = [
    ("timing", f"{C}/repaired-1.timing.jsonl", "timing-repaired-1"),
    ("timing", f"{C}/vulnerable-1.timing.jsonl", "timing-vulnerable-1"),
    ("timing", f"{C}/crashing-1.timing.jsonl", "timing-crashing-1"),
    ("timing", "synthetic/mini-timing.jsonl", "timing-mini-synthetic"),
    ("env", f"{C}/repaired-1.env.json", "env-repaired-1"),
    ("s3", f"{C}/repaired-1.json", "s3-repaired-1"),
    ("s3", f"{C}/crashing-1.json", "s3-crashing-1"),
    ("stderr", f"{C}/hanging-1.stderr.log", "stderr-hanging-1"),
    ("stderr", f"{C}/repaired-1.stderr.log", "stderr-repaired-1-empty"),
    ("summary", "synthetic/summary-1.json", "summary-synthetic-1"),
    ("slot", "repaired-1", "slot-repaired-1"),
    ("slot", "hanging-1", "slot-hanging-1"),
]
FORBIDDEN = ("record_kind", "f3-record-v1", "campaign-03", "MEASUREMENT_")


def _bytes(rel: str) -> bytes:
    return (VECTORS / rel).read_bytes()


def _golden(name: str) -> bytes:
    blob = (VECTORS / "expected" / f"{name}.bin").read_bytes()
    want = (VECTORS / "expected" / f"{name}.sha").read_text(encoding="utf-8").strip()
    assert hashlib.sha256(blob).hexdigest() == want
    return blob


def _slot(stem: str) -> dict[str, tuple[bytes, str] | None]:
    out: dict[str, tuple[bytes, str] | None] = {}
    for role, suffix in (("timing", ".timing.jsonl"), ("env", ".env.json")):
        path = VECTORS / "campaign04" / f"{stem}{suffix}"
        out[role] = (path.read_bytes(), f"{stem}{suffix}") if path.exists() else None
    for role, suffix in (("s3", ".json"), ("stderr", ".stderr.log")):
        path = VECTORS / "campaign04" / f"{stem}{suffix}"
        out[role] = (path.read_bytes(), f"{stem}{suffix}") if path.exists() else None
    return out


@pytest.mark.parametrize(("kind", "src", "golden"), CASES)
def test_golden_vectors(kind: str, src: str, golden: str) -> None:
    if kind == "slot":
        view = leg.adapt_slot(_slot(src), slot=src)
    else:
        view = getattr(leg, f"adapt_{kind}")(_bytes(src), source_path=src.rsplit("/", 1)[-1])
    assert leg.to_canonical_bytes(view) == _golden(golden)


def test_fixture_manifest_integrity() -> None:
    raw = (VECTORS / "fixtures.manifest").read_text(encoding="utf-8")
    entries = json.loads(raw)["fixtures"]
    assert len(entries) == 15
    for entry in entries:
        blob = (VECTORS / entry["path"]).read_bytes()
        assert len(blob) == entry["bytes"]
        assert hashlib.sha256(blob).hexdigest() == entry["sha256"]
        origin = entry["origin"]
        assert origin == "campaign-04-test-vector" or origin.startswith("synthetic/")
    assert sum(e["origin"] == "campaign-04-test-vector" for e in entries) == 13


def test_summary_values_and_hygiene() -> None:
    view = leg.adapt_summary(_bytes("synthetic/summary-1.json"), source_path="s")
    assert view["source"]["observations"] == 15
    assert view["source"]["origin"] == "synthetic/summary-1"
    assert view["quorum_basis"] == (
        "attempt-pool-pre-f3-convention (descriptive only; not a policy invocation quorum)"
    )
    assert view["warmup_invocations"] == []
    assert view["warmup_note"] == "no warm-up marking existed; cold-start effects included."
    for blob in (VECTORS / "expected").glob("*.bin"):
        text = blob.read_bytes().decode("utf-8")
        assert all(token not in text for token in FORBIDDEN)
