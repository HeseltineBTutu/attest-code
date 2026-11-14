"""F3 benchmark series: decomposition, warm-up declaration and prefix (W1, W3).

Series are computed deterministically from declared
per-invocation targets and workload triples: maximal runs of
consecutive run_sequence sharing both. Keys stay unique via
the campaign-global series ordinal. Record↔entry echo is
P3's domain; P5 trusts it (P8 runs P3 first) and checks
declarations: protocol warm-up list (W1) and prefix shape
(W3). Gapped sequences break runs (never pooled); P3 owns
the gap finding.
"""

from __future__ import annotations

import dataclasses

from attest_core.f3_manifest_entries import Finding
from attest_core.f3_records_campaign import CampaignRecord


@dataclasses.dataclass(frozen=True)
class Diagnostic:
    """A mandatory report note that never fails the package (§13)."""

    rule: str
    location: str
    reason: str


@dataclasses.dataclass(frozen=True)
class SeriesMember:
    """One declared invocation placed in a series."""

    run_sequence: int
    entry_index: int
    invocation_id: str
    sample_class: str
    relative: int


@dataclasses.dataclass(frozen=True)
class Series:
    """One benchmark series: key plus members in run order."""

    key: tuple[str, str, str, str, int]
    ordinal: int
    members: tuple[SeriesMember, ...]


@dataclasses.dataclass(frozen=True)
class SeriesReport:
    """Decomposition plus findings; diagnostics never affect severity."""

    series: tuple[Series, ...]
    findings: tuple[Finding, ...]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def severity(self) -> str:
        """Worst finding wins; clean packages are VALID."""
        if any(item.severity == "INVALID" for item in self.findings):
            return "INVALID"
        if any(item.severity == "INCOMPLETE" for item in self.findings):
            return "INCOMPLETE"
        return "VALID"

    @property
    def ok(self) -> bool:
        """True only when no finding of any severity exists."""
        return not self.findings


def compute_series(campaign: CampaignRecord) -> tuple[Series, ...]:
    """Deterministic W3 decomposition over declared entries in run order."""
    ordered = sorted(enumerate(campaign.invocations), key=lambda pair: int(pair[1]["run_sequence"]))
    out: list[Series] = []
    current: list[SeriesMember] = []
    previous: tuple[str, str, str, str] | None = None
    last_seq = 0
    for entry_index, item in ordered:
        seq = int(item["run_sequence"])
        workload = item["workload"]
        identity = (
            str(item["target"]),
            str(workload["workload_class"]),
            str(workload["workload_id"]),
            str(workload["input_digest"]),
        )
        if previous is not None and (identity != previous or seq != last_seq + 1):
            out.append(_close(previous, len(out) + 1, current))
            current = []
        current.append(
            SeriesMember(
                run_sequence=seq,
                entry_index=entry_index,
                invocation_id=str(item["invocation_id"]),
                sample_class=str(item["sample_class"]),
                relative=len(current) + 1,
            )
        )
        previous, last_seq = identity, seq
    if current and previous is not None:
        out.append(_close(previous, len(out) + 1, current))
    return tuple(out)


def _close(
    identity: tuple[str, str, str, str], ordinal: int, members: list[SeriesMember]
) -> Series:
    """Seal one series with its global key."""
    return Series(key=(*identity, ordinal), ordinal=ordinal, members=tuple(members))


def check_warmup_declarations(campaign: CampaignRecord) -> tuple[Finding, ...]:
    """W1 protocol leg: entry warm-up set must equal the declared list."""
    declared = {int(item) for item in campaign.protocol["warmup_invocations"]}
    observed = {
        int(item["run_sequence"])
        for item in campaign.invocations
        if str(item["sample_class"]) == "warmup"
    }
    out: list[Finding] = []
    for seq in sorted(declared - observed):
        out.append(
            Finding(
                severity="INVALID",
                rule="W1",
                location="$.campaign.protocol.warmup_invocations",
                reason=f"run_sequence {seq} listed warmup but no warmup entry declares it",
            )
        )
    for index, item in enumerate(campaign.invocations):
        seq = int(item["run_sequence"])
        if str(item["sample_class"]) == "warmup" and seq not in declared:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="W1",
                    location=f"$.campaign.invocations[{index}]",
                    reason=(f"run_sequence {seq} declares warmup but the protocol list omits it"),
                )
            )
    return tuple(out)


def check_prefix(series: Series) -> tuple[Finding, ...]:
    """W3: warm-ups must occupy relative ordinals 1..K (K >= 0)."""
    out: list[Finding] = []
    measured_seen = 0
    for member in series.members:
        if member.sample_class == "measured":
            measured_seen = member.relative
        elif measured_seen:
            out.append(
                Finding(
                    severity="INVALID",
                    rule="W3",
                    location=f"$.campaign.invocations[{member.entry_index}]",
                    reason=(
                        f"warmup at series-relative ordinal {member.relative} "
                        f"follows measured at ordinal {measured_seen} "
                        f"(series {display_key(series.key)})"
                    ),
                )
            )
    return tuple(out)


def display_key(key: tuple[str, str, str, str, int]) -> str:
    """Derived `<target>/b<ordinal>` series display prefix (§7.5)."""
    return f"{key[0]}/b{key[4]}"
