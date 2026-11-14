"""F3 manifest entries: duplicate rules and resolution loop."""

from __future__ import annotations

import dataclasses
from typing import Any

from attest_core import f3_entry_resolve as resolve
from attest_core import f3_entry_shapes as shapes
from attest_core.f3_errors import F3Error, F3IncompleteError


@dataclasses.dataclass(frozen=True)
class Finding:
    """One verified problem: severity, rule, location, and cause."""

    severity: str
    rule: str
    location: str
    reason: str


@dataclasses.dataclass(frozen=True)
class EntryResult:
    """Resolution outcome for one manifest entry."""

    source: str
    index: int
    identity: str
    findings: tuple[Finding, ...]
    record: dict[str, Any] | None

    @property
    def severity(self) -> str:
        """Worst finding wins; clean entries are VALID."""
        if any(item.severity == "INVALID" for item in self.findings):
            return "INVALID"
        if any(item.severity == "INCOMPLETE" for item in self.findings):
            return "INCOMPLETE"
        return "VALID"


def finding_for(exc: F3Error) -> Finding:
    """Map an error to its finding (incomplete iff F3IncompleteError)."""
    severity = "INCOMPLETE" if isinstance(exc, F3IncompleteError) else "INVALID"
    return Finding(severity=severity, rule=exc.rule, location=exc.location, reason=exc.reason)


def _identity(source: str, index: int, entry: Any) -> str:
    """Best-available entry identity, else its manifest position."""
    if isinstance(entry, dict):
        if source == "records":
            rid = entry.get("record_id")
            if isinstance(rid, str) and rid:
                return rid
        else:
            inv = entry.get("invocation_id")
            role = entry.get("role")
            if isinstance(inv, str) and inv and isinstance(role, str) and role:
                return f"({inv}, {role})"
    return f"{source}[{index}]"


def _dup_relpaths(valid: list[tuple[str, int, dict[str, Any]]]) -> dict[tuple[str, int], str]:
    """V-P4: equal relpath strings across both lists (exact match)."""
    by_path: dict[str, list[tuple[str, int]]] = {}
    for source, index, entry in valid:
        by_path.setdefault(entry["relpath"], []).append((source, index))
    out: dict[tuple[str, int], str] = {}
    for relpath in sorted(by_path):
        members = by_path[relpath]
        if len(members) > 1:
            for pos, (source, index) in enumerate(members):
                others = ", ".join(f"{s}[{i}]" for j, (s, i) in enumerate(members) if j != pos)
                out[(source, index)] = f"duplicate relpath {relpath!r} (also at {others})"
    return out


def _dup_evidence_pairs(
    valid: list[tuple[str, int, dict[str, Any]]],
) -> dict[tuple[str, int], str]:
    """V-B5: duplicate (invocation_id, role) pairs across evidence[]."""
    by_pair: dict[tuple[str, str], list[tuple[str, int]]] = {}
    for source, index, entry in valid:
        if source != "evidence":
            continue
        by_pair.setdefault((entry["invocation_id"], entry["role"]), []).append((source, index))
    out: dict[tuple[str, int], str] = {}
    for pair in sorted(by_pair):
        members = by_pair[pair]
        if len(members) > 1:
            for pos, (source, index) in enumerate(members):
                others = ", ".join(f"{s}[{i}]" for j, (s, i) in enumerate(members) if j != pos)
                note = f"duplicate (invocation_id, role) {pair!r} (also at {others})"
                out[(source, index)] = note
    return out


def resolve_all(
    root_fd: int, root: str, records: list[Any], evidence: list[Any]
) -> list[EntryResult]:
    """Shape-check, de-duplicate, and resolve every entry in order."""
    shaped: list[tuple[str, int, dict[str, Any] | None, list[Finding]]] = []
    for source, items, check in (
        ("records", records, shapes.validate_record_entry),
        ("evidence", evidence, shapes.validate_evidence_entry),
    ):
        for index, raw in enumerate(items):
            location = f"{source}[{index}]"
            try:
                shaped.append((source, index, check(raw, "8.3", location), []))
            except F3Error as exc:
                shaped.append((source, index, None, [finding_for(exc)]))
    valid = [(s, i, e) for (s, i, e, _) in shaped if e is not None]
    dup_paths = _dup_relpaths(valid)
    dup_pairs = _dup_evidence_pairs(valid)
    opened: list[
        tuple[str, int, str, dict[str, Any] | None, list[Finding], tuple[int, int] | None]
    ] = []
    for source, index, entry, shape_findings in shaped:
        findings = list(shape_findings)
        location = f"{source}[{index}]"
        identity = _identity(source, index, entry)
        if entry is None:
            opened.append((source, index, identity, None, findings, None))
            continue
        if (source, index) in dup_paths:
            findings.append(
                Finding(
                    severity="INVALID",
                    rule="V-P4",
                    location=f"{location}.relpath",
                    reason=dup_paths[(source, index)],
                )
            )
            opened.append((source, index, identity, None, findings, None))
            continue
        if (source, index) in dup_pairs:
            findings.append(
                Finding(
                    severity="INVALID",
                    rule="V-B5",
                    location=location,
                    reason=dup_pairs[(source, index)],
                )
            )
        try:
            if source == "records":
                parsed, file_id = resolve.resolve_record(root_fd, root, entry, location)
                opened.append((source, index, identity, parsed, findings, file_id))
            else:
                file_id = resolve.resolve_evidence(root_fd, root, entry, location)
                opened.append((source, index, identity, None, findings, file_id))
        except F3Error as exc:
            findings.append(finding_for(exc))
            opened.append((source, index, identity, None, findings, None))
    by_file: dict[tuple[int, int], list[str]] = {}
    for source, index, _, _, _, fid in opened:
        if fid is not None:
            by_file.setdefault(fid, []).append(f"{source}[{index}]")
    results: list[EntryResult] = []
    for source, index, identity, record, findings, fid in opened:
        location = f"{source}[{index}]"
        holders = by_file.get(fid, []) if fid is not None else []
        if len(holders) > 1:
            others = ", ".join(loc for loc in holders if loc != location)
            findings.append(
                Finding(
                    severity="INVALID",
                    rule="V-P5",
                    location=f"{location}.relpath",
                    reason=f"hardlink alias: same file as {others}",
                )
            )
        payload = record
        if any(item.severity == "INVALID" for item in findings):
            payload = None
        results.append(EntryResult(source, index, identity, tuple(findings), payload))
    return results
