"""Filesystem package builders for P8 validator tests (deterministic)."""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Any

from f3_fixtures import to_bytes, valid_attempt, valid_campaign, valid_env, valid_total
from f3_identity_pkg import CAMPAIGN_ID
from f3_input_pkg import EMPTY_DIGEST, manifest, workload
from f3_package import evidence_entry, manifest_dict, record_entry, write_package

TRIPLE8 = ("Medium", "auth-admin-001", EMPTY_DIGEST)

_counter = itertools.count(1)


def _rid() -> str:
    """Fresh valid UUIDv4 record id."""
    return f"eeeeeeee-eeee-4eee-8eee-{next(_counter):012x}"


def attempt_dict(invocation: str, number: int, **overrides: Any) -> dict[str, Any]:
    """One attempt record dict with P4-coherent default echoes."""
    base: dict[str, Any] = {
        "record_id": _rid(),
        "campaign_id": CAMPAIGN_ID,
        "invocation_id": invocation,
        "attempt": number,
        "workload_class": TRIPLE8[0],
        "workload_id": TRIPLE8[1],
        "input_digest": TRIPLE8[2],
    }
    base.update(overrides)
    return valid_attempt(**base)


def total_dict(invocation: str, **overrides: Any) -> dict[str, Any]:
    """One total record dict with P4-coherent default echoes."""
    base: dict[str, Any] = {
        "record_id": _rid(),
        "campaign_id": CAMPAIGN_ID,
        "invocation_id": invocation,
        "workload_class": TRIPLE8[0],
        "workload_id": TRIPLE8[1],
        "input_digest": TRIPLE8[2],
    }
    base.update(overrides)
    return valid_total(**base)


def env_dict(invocation: str, **overrides: Any) -> dict[str, Any]:
    """One environment record dict with P4-coherent default echoes."""
    base: dict[str, Any] = {
        "record_id": _rid(),
        "campaign_id": CAMPAIGN_ID,
        "invocation_id": invocation,
        "workload_class": TRIPLE8[0],
        "workload_id": TRIPLE8[1],
        "input_digest": TRIPLE8[2],
    }
    base.update(overrides)
    return valid_env(**base)


def group_dicts(
    inv: str, sample: str, numbers: tuple[int, ...] = (1, 2, 3), **kw: Any
) -> list[dict[str, Any]]:
    """Coherent record dicts for one invocation (attempts, total, env)."""
    made = [attempt_dict(inv, n, sample_class=sample, **kw) for n in numbers]
    tot = total_dict(
        inv,
        sample_class=sample,
        attempts_completed=len(numbers),
        attempt_outcomes={"PASS": len(numbers)},
        **kw,
    )
    return [*made, tot, env_dict(inv, sample_class=sample, **kw)]


def campaign_dict(
    specs: list[tuple[str, str]],
    *,
    warmups: list[int] | None = None,
    targets: list[str] | None = None,
    required: int = 5,
    entry_targets: dict[str, str] | None = None,
    workloads: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """One campaign record dict with digest-coherent default workloads."""
    entry_targets = entry_targets or {}
    workloads = workloads or {}
    entries = [
        {
            "run_sequence": position + 1,
            "invocation_id": inv,
            "sample_class": sample,
            "target": entry_targets.get(inv, "repaired"),
            "workload": workloads.get(inv, workload(manifest())),
        }
        for position, (inv, sample) in enumerate(specs)
    ]
    protocol = {
        "benchmark_category": "end-to-end",
        "required_successful": required,
        "attempts_per_invocation": 3,
        "warmup_invocations": warmups if warmups is not None else [],
        "targets": targets if targets is not None else ["repaired"],
        "profile": "hardened",
    }
    return valid_campaign(
        record_id=_rid(), campaign_id=CAMPAIGN_ID, protocol=protocol, invocations=entries
    )


def write_campaign(
    root: Path,
    records: list[dict[str, Any]],
    evidence: dict[str, bytes],
    extra: dict[str, bytes] | None = None,
) -> Path:
    """Write records plus evidence plus extras with a correct manifest."""
    files = {f"records/{i:02d}.json": to_bytes(item) for i, item in enumerate(records)}
    files.update({f"evidence/{key}.json": data for key, data in evidence.items()})
    files.update(extra or {})
    manifest = manifest_dict(
        records=[record_entry(item, f"records/{i:02d}.json") for i, item in enumerate(records)],
        evidence=[
            evidence_entry(inv, f"evidence/{inv}.json", data) for inv, data in evidence.items()
        ],
    )
    return write_package(root, manifest=manifest, files=files)


def tamper_file(root: Path, relpath: str) -> None:
    """Change one byte of a package file (stays parseable, digest breaks).

    Fixture files always contain a zero byte (timeouts, wallclocks);
    evidence bytes must include one (all fixtures here do).
    """
    target = root / relpath
    target.write_bytes(target.read_bytes().replace(b"0", b"1", 1))
