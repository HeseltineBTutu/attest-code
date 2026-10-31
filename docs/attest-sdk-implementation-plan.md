# attest_sdk Implementation Plan

Status: PROPOSED. Planning document for roadmap milestone 2. The
frozen `docs/attest-spec-v1.md` (content digest `67bb4435…`, verified
during drafting) is authoritative; this plan reinterprets nothing.
No SDK source or tests exist yet.

## 1. Goal and scope

Ship a stable programmatic interface over the frozen spec: parse and
validate v1 invariants, canonicalize and digest, evaluate registry
histories, check request eligibility, run parent-engine verification
with exact-pinned verifiers, emit and verify v3 attestations, replay
history, and execute the published vectors. In scope: new
`src/attest_sdk/` package, its tests, packaging, and a vector
conformance runner. Out of scope here: new verifier implementations,
adapters, and CLI rewrites (see §11).

## 2. Success criteria

- Every frozen-vector row applicable to the SDK reproduces or refuses
  exactly as its manifest expects.
- All §15 matrix rows implementable without new normative decisions.
- `import attest_sdk` pulls no fastapi/demo modules; offline paths run
  on stdlib plus PyYAML.
- All five quality gates pass; every new file holds the 200-line rule.
- Parent engine classifies every verdict; no verifier or model path
  can emit PASSED/FAILED independently.

## 3. Existing architecture audit

- `attest_spec` (75 lines, stdlib-only): `Verdict`,
  `AttemptOutcome`, v0 `Invariant`/`ApprovalRecord`. Stable; reuse
  the enums, never fork them.
- `attest_core/invariants.py` (151): v0 YAML loading, 5-field
  digest, `is_approval_valid`, in-memory `Registry`. Reuse the
  digest-equality pattern only; v1 needs new documents, digests,
  and event chains.
- `attest_core/evidence.py` (178): v2 records, `canonical_bytes`
  with `ensure_ascii=True`, `verify_attestation`. Reuse the
  fail-closed validation shape; MUST NOT reuse its canonicalizer
  for spec digests (it diverges from attest-canonical-json v1).
- `attest_core/verdicts.py` (71): 3-attempt policy. Reuse verbatim.
- `attest_core/verification.py` (160): 3-attempt orchestration
  emitting v2 attestations. Reuse the loop/classify shape behind
  an adapter; v1 request, approval-event, and v3 shapes differ.
- `attest_core/{git,snapshot,runtime,exec_profile,bounds}`: revision
  pinning, snapshot export, runtime binding, profiles
  (`standard`/`contained`/`hardened`), worker supervision. Reuse
  for execution; SDK adds no isolation of its own.
- `apps/{review,approvals,verify,cli,output}`: CLI review/verify,
  YAML store, exit codes 0/1/2/3. Compatibility anchors; the SDK
  exposes `approve()`/`verify()` primitives but does not replace
  CLI UX in this milestone.
- Lifecycle: no invariant-lifecycle code exists (only
  process-supervision matches); §8 is greenfield.
- Vectors: `spec/attest-spec/v1/vectors/manifest.json` (46
  fixtures: input bytes, canonical bytes, digests, outcomes,
  reason classes, `probe_checkable` flags) is directly consumable
  by a manifest-driven runner.
- Size/import facts: `verify.py` (222), `snapshot.py` (311),
  `envelope.py` (226), `origin.py` (231), `sandbox.py` (223)
  exceed 200 lines — add no backend logic to them. Package
  `__init__` files are import-light; fastapi enters only via
  `apps.demo_api`/`examples` (demo fixtures).

## 4. Proposed package structure

New top-level package `src/attest_sdk/` (name already reserved by
`docs/architecture.md` and README), added to both hatch `packages`
lists. One responsibility per module, each ≤200 lines:

```text
src/attest_sdk/
  __init__.py      re-export stable surface only (__all__)
  version.py       SDK version + SUPPORTED_SPEC_VERSIONS = (1,)
  errors.py        exception hierarchy (refusal vs verdict)
  canonical.py     attest-canonical-json v1: strict parse, NFC,
                   JCS order, int-only, limits, sha256
  schema.py        v1 document validation (absent-vs-empty, x- rules)
  documents.py     Invariant v1 types + content digests
  events.py        approval/lifecycle event hashing + chain validation
  registry.py      layout discovery, folds, joint eligibility
  requests.py      verification-request validation + verifier pin
  verifiers.py     Verifier protocol + registry of implementations
  engine.py        parent-engine orchestration adapter (3 attempts,
                   verdict classification; verifiers report only)
  attestation.py   v3 emit/verify + v2 dual-read
  history.py       registry@commit replay (git materialization port)
  vectors.py       manifest-driven conformance runner + report
```

Tests mirror at `tests/test_src/test_attest_sdk/`, one module per
source module plus `test_conformance_vectors.py` (manifest-driven).

## 5. Public API proposal

Import path `attest_sdk`; sync-first API. Rationale:
`docs/security-model.md` requires serialized verification, and
the engine spawns and supervises real processes — sync keeps the
trust boundary explicit and reviewable. A threaded/async wrapper
is a documented non-goal until a serialized design exists.

```text
# Documents and digests
load_invariant(source: Path | bytes, format: str) -> Invariant
canonicalize(value) -> bytes
digest_of(value) -> str            # sha256 hex over canonical bytes
invariant_digest(inv) -> str       # 8-field v1 content digest

# Registry and eligibility
class Registry:                    # root: Path
    get(id, version) -> Invariant
    list_versions(id) -> list[int]
    approval_chain(id, version) -> ApprovalHistory
    lifecycle_chain(id, version) -> LifecycleHistory
    effective_approval(id, version) -> ApprovalEvent   # raises if none
    lifecycle_state(id, version) -> str
    check_eligible(id, version, policy) -> Eligibility # raises if not

# Verification (parent engine retains verdict authority)
class Verifier(Protocol):          # implementations report, never verdict
    verification_type: str; spec_versions: tuple; parameter_schema: dict
    def run(self, scope, target, params) -> AttemptObservation: ...
@dataclass AttemptObservation:    # per-attempt checks, no verdict
    outcome: AttemptOutcome; checks: tuple; detail: str
verify(request: VerificationRequest, verifier: Verifier) -> Report
    # validates pin/approval/eligibility, runs 3 attempts, classifies

# Attestation and history
emit_attestation(report, context) -> AttestationV3
verify_attestation(payload, digest, invariant, evidence=None) -> AttestationV3
verify_historical(attestation, registry_at_commit) -> HistoricalVerdict

# Conformance
run_vectors(vectors_dir: Path) -> ConformanceReport
```

Exceptions (`errors.py`), refusal (raise, never a verdict) versus
verdict (returned) kept disjoint: `AttestError` base;
`ParseError`, `SchemaError`, `CanonicalizationError`
(`LimitExceeded` names the limit), `UnsupportedSpecVersion`;
`RegistryError` (`AmbiguousHistory`); `ApprovalError`
(`NoApproval`, `StaleApproval`, `RevokedApproval`);
`EligibilityError`; `VerifierError` (`UnknownType`,
`UnsupportedSpec`, `Refused`, `ParameterError`);
`AttestationError`; `HistoryUnavailable`. Pre-execution failures
raise; execution uncertainty returns INCONCLUSIVE. CLI exit-code
mapping (0/1/2/3) documented for later CLI adoption, unchanged.

Versioning: SDK `1.x` implements attest-spec v1 only;
`SUPPORTED_SPEC_VERSIONS = (1,)`; anything else refuses.
Additive API in minor releases; any handshake/behavior change
bumps major. Extension: third-party verifiers implement the
`Verifier` protocol out of tree; the SDK validates pin,
spec support, parameters, and evidence shape before execution.

## 6. Specification-to-component traceability matrix

R = reuse as-is, A = adapt behind an interface, N = new. "Outside"
names functionality the SDK consumes but does not own.

| Frozen requirement (§) | SDK component | Mode | Outside SDK |
|---|---|---|---|
| Strict JSON/YAML parse + schema (§§3,5) | `schema.py` + `canonical.py` parser | N | — |
| attest-canonical-json v1 + limits (§5) | `canonical.py` | N | — |
| Invariant identity + digest (§§3–4) | `documents.py` | N | — |
| Approval hashing/discovery/fold (§7) | `events.py` + `registry.py` | N | git history (accountability aid) |
| Lifecycle hashing/transitions/fold (§8) | `events.py` + `registry.py` | N | — |
| Joint eligibility (§§8,12) | `registry.py.check_eligible` | N | — |
| Request validation (§9) | `requests.py` | N | — |
| Exact verifier pin + artifact state (§9) | `requests.py` + `verifiers.py` | N | artifact digest producers |
| Verifier execution, 3 attempts (§§9–10) | `engine.py` + `verifiers.py` | A (`verification.py`, `verdicts.py` R) | verifier impls; `git`/`snapshot`/`bounds` (R) |
| Evidence shape enforcement (§10) | `engine.py` | A (`evidence.py` shapes) | — |
| Attestation v3 + v2 dual-read (§11) | `attestation.py` | A (`evidence.py` v2 path R) | — |
| Historical replay (§12) | `history.py` | N + R (`git.py` materialization) | git binary / object store |
| v0/YAML + v2 compat (§13) | `documents.py`, `attestation.py` | A (`invariants.py`, `approvals.py` read paths) | — |
| Vector execution + reporting (§§6,15) | `vectors.py` | N | — |
| Verdicts/exits (§14) | `engine.py`, `errors.py` mapping | R (`verdicts.py`, `cli.py` codes) | — |

## 7. Dependency and migration analysis

Layering (each layer imports only below it):

```text
attest_sdk.documents/events ──> attest_spec, stdlib, yaml
attest_sdk.registry/requests/verifiers/attestation/history/vectors
  ──> sibling SDK modules + attest_spec
attest_sdk.engine ──> attest_core.verification/verdicts/evidence
  (+ git/snapshot/bounds/exec_profile on execution paths)
demos only ──> apps.demo_api / examples (fastapi; lazy import)
```

`import attest_sdk` MUST NOT import fastapi, demo, or model
packages (enforced by an import-light test). `attest_core`
imports stay within the light subset for offline paths; the
engine path reuses snapshotting and supervision untouched.
Packaging: add `src/attest_sdk` to both hatch lists; no new
third-party dependencies (stdlib + PyYAML only). Migration:
v0 engine, CLI, and YAML store keep working unchanged; SDK
consumes them read-only where noted. Later CLI adoption of
SDK primitives is a separate milestone, not this one.

## 8. Implementation phases and acceptance criteria

P0 Scaffolding. Package skeleton, `version.py`, `errors.py`,
hatch + tests wiring, empty-module import test. Accept: gates
1–4 pass; `import attest_sdk` clean under `-X importtime`
spot-check.

P1 Canonicalization + invariant validation. `canonical.py`
(strict parser, NFC + declared version, UTF-16 order,
int-only, five limits, YAML core conversion),
`schema.py`/`documents.py` (v1 validation, absent-vs-empty,
digests). Accept: every probe-checkable canonical/boundary
accept fixture byte-identical; every invalid/refuse fixture
refused with the manifest reason class.

P2 Registry folds. `events.py` (hashing, chain validation for
both kinds, transplant/misplaced/transition rules) and
`registry.py` (layout discovery, folds, joint eligibility).
Accept: all 18 chain fixtures evaluate exactly as their
manifest expects, incl. joint eligible/revoked/draft.

P3 Requests + engine. `requests.py` (pin, artifact state,
spec support, profile enum), `verifiers.py` (protocol +
reference adapter over `examples.admin_authorization`),
`engine.py` (refusal gates, 3-attempt loop, verdict
classification via `verdicts.py`). Accept: refusal matrix
(unknown type/spec/profile, bad params, missing/stale/
revoked approval, ineligible lifecycle) raises pre-execution;
demo verifier end-to-end yields PASSED/FAILED/INCONCLUSIVE
per policy with engine-classified verdicts only.

P4 Attestation + history. `attestation.py` (v3 emit/verify,
full-payload digest, v2 dual-read), `history.py`
(registry@commit evaluation reusing `git.py`). Accept:
round-trip, per-field mutation matrix, v2 fixtures still
verify, historical replay on fixture repos distinguishes
valid/revoked/unavailable.

P5 API stabilization + packaging. `__all__` freeze, docstrings,
import-light test, version-policy doc, wheel/sdist build check.
Accept: API review checklist signed in-plan; `pip install`
from sdist imports and runs vectors offline.

P6 Conformance integration. `vectors.py` manifest runner +
report; `test_conformance_vectors.py` wired into the suite.
Accept: full manifest green except rows explicitly
out-of-scope with recorded rationale; no conformance claimed
beyond executed evidence.

## 9. Validation plan

Per phase: focused `pytest tests/test_src/test_attest_sdk/<module>`
plus `ruff check`, `ruff format --check`, strict `mypy`
on `src/attest_sdk`, then the five-gate
`scripts/quality-gate.sh` before phase sign-off. P1/P2/P6
additionally run the vector runner against
`spec/attest-spec/v1/vectors/` with byte-compare evidence.
Highest-risk validation: P3 refusal-matrix completeness —
every normative MUST-refuse needs a test proving refusal
happens before any verdict or execution side effect.

## 10. Security and trust boundaries

- Verdict authority: only `engine.py` (via `verdicts.py`)
  classifies; `Verifier.run` returns observations; model code
  has no SDK path to approval, registry writes, or verdicts.
- Refusal integrity: fail-closed exception paths; no silent
  fallback, coercion, or lenient modes anywhere.
- Registry trust: SDK validates hashes/chains/order itself;
  git supplies history availability only, never authenticity
  (frozen §16 assumption preserved).
- Execution trust: unchanged `snapshot`/`bounds`/profiles
  semantics; SDK adds no isolation claims.
- Supply chain: no new dependencies; artifact digests
  recorded-or-explicitly-unavailable per §9, never omitted.

## 11. Non-goals, assumptions, unresolved decisions

Non-goals: new verifier implementations; IDE/CI/GitHub
adapters; CLI rewrite onto the SDK; async API; signatures or
identity infrastructure; registry server/database; performance
optimization beyond limit compliance.

Assumptions: sync-only API is acceptable for milestone 2
(security-model serialization note); PyYAML remains the YAML
engine (existing dependency); `attest_sdk` top-level package
name per established convention.

Unresolved (need owner input before P3/P5): (1) Should P0 also
ship type stubs or is inline strict typing sufficient?
(Recommendation: inline only.) (2) May the reference verifier
adapter live in the SDK package or must all verifier code stay
out of tree? (Recommendation: thin in-tree adapter over
`examples`, clearly marked reference-only.) (3) Is PyPI
publication in scope for milestone 2 or deferred to
distribution? (Recommendation: deferred; sdist build only.)

## 12. Risks

- Strict-parser subtlety (UTF-16 order, NFC edges, YAML core
  corners): mitigated by frozen vectors plus differential
  testing against the two probes.
- Engine-adapter impedance (v0 vs v1 shapes): mitigated by
  keeping `attest_core` untouched and mapping at the SDK
  boundary, with refusal tests proving no semantic leakage.
- Scope creep into CLI/verifier work: mitigated by phase gates
  and the non-goal list; any expansion needs owner approval.
