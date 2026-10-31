# Architecture

## Logical boundaries

- `attest_spec`: shared data contracts and schema definitions. No dependencies
  on other attest packages.
- `attest_sdk` (planned): public programmatic interface over core.
- `attest_core.invariants` (implemented): loading, validating, versioning, and
  resolving approved invariants.
- `attest_core.verification` (implemented): three-attempt orchestration over
  caller-supplied check runners, reusing the verdict and evidence modules.
- `attest_core.evidence` (implemented): versioned evidence records and SHA-256
  digests over canonical JSON.
- `attest_core.verdicts` (implemented): deterministic verdict policy.
- `attest_core.git` (implemented): revision resolution and the clean-snapshot
  policy with before/after fingerprints.
- `attest_core.bounds` (implemented): per-attempt worker subprocesses with
  wall-clock deadlines (bounding, not a sandbox); passes execution
  flags into contained/quota runs and attaches resource evidence.
- `attest_core.origin` (implemented): repository-root canonicalization,
  input containment, and parent/worker module-origin binding.
- `attest_core.snapshot` (implemented): exports the verified execution
  closure from git objects with a manifest digest; workers import from it
  instead of the live worktree.
- `attest_core.runtime` (implemented): import-override and root startup-module
  validation (a pre-spawn preflight plus an already-imported tripwire), plus
  deterministic runtime settings (interpreter, `PYTHONPATH`, installed
  versions, manifest hashes) bound into the configuration digest.
- `attest_core.sandbox` (implemented S1+S2): worker exposure reduction —
  minimal worker environment, controlled working directory, per-attempt
  bytecode caches, bounded diagnostic capture, and guarded spawning.
  Not OS-enforced isolation (see security-model.md).
- `attest_core.supervision` (implemented S2): supervision
  orchestration — lifecycle, TERM→grace→KILL escalation, reaping, and
  verified-empty-tree confirmation before a clean result. Supervision
  of ordinary descendants; not unbreakable containment.
- `attest_core.process_group` (implemented S2): Unix process-group
  establishment, handshake verification, and signalling.
- `attest_core.tree_inspection` (implemented S2): supervised-tree
  membership observation (`/proc` scan with a conservative fallback).
- `attest_core.envelope` (implemented S1): versioned JSON worker-result
  protocol with strict schema validation, replacing pickle IPC.
- `attest_core.exec_profile` (implemented S3): named execution
  profiles (`standard`/`contained`/`hardened`), the authoritative
  profile-to-flags mapping, lazy capability preflight, stable
  quota settings for the config digest, and enforcement
  derivation from attempt outcomes.
- `attest_core.resource_evidence` (implemented S3): per-attempt
  scope-counter collection into the separate `resources`
  evidence field; explicit unavailable markers, never zeros.
- `attest_core.scope_metrics` (implemented S3): per-scope
  cgroup readers for peak memory, peak tasks, and cumulative
  CPU, with documented units and sampling semantics.
- `attest_core.runner_protocol` (implemented S3): parent/runner
  wire-protocol version contract with pre-spawn snapshot probing.
- `attest_core.seccomp` (implemented M4): BPF denylist construction
  and fail-closed installation plus availability probing.
- `attest_core.seccomp_probes` (implemented M4): per-rule live
  probes, allowed/inherit/fallback controls, ddmin diagnostic.
- `attest_core.contained_runner` (implemented M1/M2/M3/M4): the
  in-namespace runner — scope placement self-check, namespace
  entry, private root, rlimits, seccomp install, workload,
  single result envelope.
- `attest_core.scopes` (implemented M3-A): transient systemd scope
  launch-into-scope, limit verification, event counters, and
  stop-and-verify-empty teardown.
- `apps.cli` (implemented): argparse entry point mapping outcomes to exit
  codes; no CLI framework dependency.
- `apps.approvals` (implemented): YAML approval store keyed by id/version.
- `apps.review` (implemented): invariant display and confirmed approval.
- `apps.verify` (implemented): authoritative verification flow.
- `apps.output` (implemented): text and versioned JSON report rendering.
- `apps.demo_api` (implemented): synthetic FastAPI fixtures and the
  registered-route inventory.
- `integrations.meta_models` (implemented): isolated Meta model client
  boundary for diagnose-and-propose-patch. Requires a FAILED report;
  model output is untrusted and never verdicts, writes, or applies.
- `examples.admin_authorization` (implemented): approved checks for
  AUTH-ADMIN-001 with fail-closed scope coverage.
- `invariants/auth-admin-001.yaml` (implemented): the invariant definition.

Only the modules needed so far exist. Planned packages are not scaffolded
as empty placeholders. Dependency direction: `examples/*` and `apps/*` may
import `attest_core`; core never imports them, and `attest_spec` depends on
nothing internal. Demo web dependencies (`fastapi`, `httpx`) currently live
in main dependencies as a provisional hackathon simplification.

## Data flow (target)

1. Human approves an invariant version; the approval binds to a content digest.
2. The registry resolves only definitions with a valid, matching approval.
3. `attest review` displays one invariant with its content digest and prior
   approval state, and records a new approval only on explicit confirmation.
4. `attest verify` resolves the revision to a full commit id, refuses unless
   HEAD matches and the snapshot scope (source dirs, root manifests,
   git-semantics files) is clean with no hidden executables, requires a
   valid approval for the exact content digest, confines inputs to the
   repo, proves loaded modules (parent and worker) originate from the
   tree, validates/binds the runtime environment, and resolves the
   `--exec` profile with capability preflight (missing mandatory
   capabilities refuse before any attempt; see security-model.md).
5. `run_verification` requires a matching approval at invocation and raises
   instead of verdicting when it is absent or stale.
6. Checks compare declared scope against the app's registered routes, then
   run 401/403/200 probes per endpoint over a fresh test client, each
   attempt in a worker subprocess (minimal env, controlled cwd,
   per-attempt bytecode cache, bounded JSON result file, wall-clock
   deadline, supervised process group with TERM→KILL escalation and
   verified-empty-tree cleanup) running under the selected profile —
   plain workers for `standard`, the namespace runner for
   `contained`, plus quotas and seccomp for `hardened`.
7. The orchestrator genuinely re-executes the checks three times under one
   recorded revision and configuration digest, emitting per-check and
   per-attempt evidence records.
8. A post-run fingerprint mismatch overrides any verdict with INCONCLUSIVE.
9. The verdict policy classifies the attempt set as PASSED, FAILED, or
   INCONCLUSIVE; an attestation references every evidence hash and commits
   to the exact invariant content verified (`verify_attestation` checks
   both the integrity digest and the content binding).

## Model boundary

```
model diagnosis/patch proposal  -->  untrusted input
approved invariant registry     -->  verifier-owned, model cannot write
verification execution          -->  verifier-owned
final verdict                   -->  verifier-owned
```

Model output is evaluated against the unchanged approved invariant. Repair
proposals never modify the registry.

## Engineering rules

- Source files target fewer than 200 lines where practical.
- No circular imports; `attest_spec` depends on nothing internal.
- Security-sensitive decisions are deterministic functions with unit tests.
- Explicit error handling via typed exceptions (`InvariantRegistryError`).
