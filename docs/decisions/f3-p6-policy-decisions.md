# F3 P6 Policy Decisions (AQ-1, AQ-2)

Owner decisions recorded 2026-11-15. These decisions resolve
AQ-1 and AQ-2 for P6 implementation and acceptance. They do
not rewrite or retroactively alter the frozen Revision 5
design document (`docs/f3-measurement-record-design.md`) or
the frozen performance policy.

## AQ-1 — Measurement violation quorum eligibility

Owner decision: YES.

A reproducible, complete, uncensored VIOLATION measurement
repetition counts as a successful measurement sample for
quorum under the explicit P6 eligibility rules (Q1, R5
§10.6): measurement-complete AND sample_class = measured
AND M1 ∈ {MEASUREMENT_CLEAN, MEASUREMENT_VIOLATION} AND
evidence-verified. Below-threshold counts remain
`met: false`, never success.

Preserved distinctions (non-negotiable):

- Measurement-sample eligibility is not verifier success.
- M1 measurement classification is not verifier verdict
  classification (`classify_with_reason`).
- A VIOLATION observation must never be described as proof
  of correctness, as a passing result, or as a verifier
  PASS/verification success.

Implementation consequence:

- Retain `VIOLATION_COUNTS_AS_SUCCESSFUL = True` in
  `src/attest_core/f3_quorum.py` as an owner-confirmed
  policy decision, not a provisional default.
- Preserve all other eligibility conjuncts and the
  warmup | incomplete | measurement-inconclusive |
  evidence-missing exclusion vocabulary unchanged.

Limitation: the decision settles quorum counting only. It
confers no verdict authority on measurement records and
does not change M2 stored-verdict opacity.

## AQ-2 — Per-series quorum and warm-up scope

Owner decision: adopt per-series evaluation.

Each deterministic P5 series (maximal consecutive
run_sequence sharing target and workload triple, R5 §6.3)
has its own warm-up prefix, measured repetition set,
measurement classification accounting, quorum evaluation,
and comparability context. No campaign-wide warm-up prefix
or cross-series quorum aggregation is introduced.

Implementation consequence:

- P6 consumes P5's existing per-series decomposition
  (`f3_series.compute_series`) unchanged.
- P3 remains authoritative for identity, cardinality, and
  sequence findings; P5 gaps split runs and P3 reports
  sequence gaps.
- P5 remains authoritative for deterministic series
  decomposition and warm-up-prefix validation (W3).
- Q1 evaluates once per series key; one series meeting
  quorum never satisfies another series.
- Comparability compares series attribute blocks; it
  never merges independent series into one evaluation.

Limitation: the decision adopts the proposed W3
decomposition reading for multi-target campaigns.
Single-target campaigns satisfy both readings identically;
no existing single-series behavior changes.

## Provenance

- Decided by the owner on 2026-11-15.
- Applies to P6 implementation and acceptance in the
  M5.1 worktree (`m5-1-measure`, from P5 checkpoint
  `45b6c61`).
- Recorded here rather than in Revision 5 to preserve the
  frozen design document byte-for-byte.
