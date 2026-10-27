# Security Model

## Trust boundaries

1. Invariants are authoritative only after explicit human approval.
2. Model-generated invariant suggestions remain untrusted drafts.
3. Model-generated tests may supplement verification but cannot replace or
   weaken approved requirements.
4. Approved invariant changes require a new version and renewed approval.
5. Meta model output is untrusted input.
6. The verifier, not the model, determines the final verdict.
7. The model cannot change the approved invariant registry through its repair
   workflow.

## Approval boundary design

- Definitions (YAML) carry `id`, `version`, `requirement`, and `scope`. A
  definition file may contain an `approved` key for human convenience, but the
  loader ignores it (`IGNORED_DEFINITION_KEYS`).
- Authority comes only from an `ApprovalRecord` created via
  `create_approval`, which must be invoked by a human-driven flow (CLI review
  command or review UI — planned, not yet implemented).
- Each approval binds `(invariant_id, invariant_version, content_digest)`.
  Any change to the requirement, title, or scope changes the digest and
  invalidates prior approvals.
- The registry refuses approvals with no matching definition and refuses to
  resolve definitions without a matching approval.

## Limitations (explicit)

- Current approval records are in-memory/file objects with no cryptographic
  authorship: anyone with write access to the approval store could forge a
  record naming a reviewer. No signing infrastructure exists in this phase.
- Hashing (SHA-256 over canonical JSON) detects changes relative to a trusted
  digest. It does not establish authorship or authenticity.
- `approved_at` is a caller-supplied string; no trusted timestamping.
- `attest review` is the human approval flow: it shows the invariant with its
  content digest and prior approval state (none, MATCH, or STALE), requires
  `--approver` naming the reviewer, and writes to the YAML approval store
  only on explicit `y`/`yes` confirmation. Tests act as that operator via
  explicit fixtures, never as model output.
- `run_verification` and `attest verify` enforce the boundary at invocation:
  a missing or stale approval refuses verification instead of verdicting.
- No sandbox isolation exists yet; untrusted execution stays disabled.
  Checks run in worker subprocesses via a FastAPI test client, and only
  verifier-owned check code runs — model-provided code is never executed.

## Revision integrity (MVP policy)

- `attest verify --revision <rev>` resolves `<rev>` to a full 40-hex commit
  id and records that id, never the raw label.
- Verification refuses unless HEAD equals the requested commit (check it out
  first; the tool never switches branches) and `src/`, `tests/`, and
  `invariants/` show no staged, unstaged, or untracked changes.
- A fingerprint (HEAD id plus relevant status) is taken before and after the
  run; a mismatch overrides any verdict with INCONCLUSIVE and is flagged in
  the output (`snapshot-changed: true`).
- Honesty gap: the demo target is fixture code imported from the operator's
  tree, and `--repo` selects the tree whose snapshot is enforced. In real
  use `--repo` must be the tree containing the code under test; the tool
  cannot prove that separately-selected trees coincide.

## Bounded execution

- Each attempt runs in a spawned subprocess with a wall-clock deadline
  (`--timeout`, default 60s). Expiry terminates the worker (SIGTERM, then
  SIGKILL); an expired, crashed, or erroring worker yields an
  infrastructure outcome, so timeouts and crashes give INCONCLUSIVE and can
  never alone establish FAILED.
- Limits: workers run with the operator's privileges and share the
  filesystem; this bounds stuck execution but is not a sandbox against
  malicious code. Worker callables must be picklable top-level references.
  A bare `run_verification` library call remains in-process and unbounded;
  only the CLI path applies deadlines.

## Endpoint inventory mechanism

- `admin_route_paths` inventories registered routes whose path starts with
  `/admin`, sorted for determinism.
- Checks require exact correspondence between declared scope and actual
  routes: an undeclared admin endpoint, a declared-but-missing endpoint, or
  an unreadable inventory all fail closed to an infrastructure outcome
  (INCONCLUSIVE), never a silent pass or a claimed violation.
- Limitations: prefix-based only; mounted sub-applications, dynamic routes,
  and admin behavior under non-`/admin` paths are not discovered. Probes use
  GET only and distinguish paths, not methods. The inventory does not claim
    to discover every possible dynamic or indirectly exposed endpoint.

## Verdict policy

- FAILED requires a reproducible invariant violation across three independent
  attempts under the same recorded revision and configuration, each with
  evidence.
- Timeouts, crashes, missing evidence, mixed results, scope-coverage gaps,
  and revision/config mismatches yield INCONCLUSIVE, never FAILED.
- PASSED is the policy's verified outcome: all required checks passed in all
  three attempts with scope coverage established.
- No universal proof of correctness is claimed. Each classification states
  precisely what was checked (attempt count, same-revision/config rule,
  evidence presence).
- The three-attempt rule is not a universal guarantee against
  nondeterminism: attempts run in separate worker processes but on one
  machine without execution isolation, so they catch flaky or
  non-reproducible results but cannot prove determinism.

## Model-data hygiene (planned integration)

- Keep model calls separate from verification execution.
- Never send secrets, private credentials, or unrelated repository contents.
- Send only the failing invariant id/version, the minimal failing evidence
  excerpt, and the implicated code region.
- Mock results must never be presented as evidence of a real Meta API
  integration.
