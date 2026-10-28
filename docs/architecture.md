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
  wall-clock deadlines (bounding, not a sandbox).
- `attest_core.origin` (implemented): repository-root canonicalization,
  input containment, and parent/worker module-origin binding.
- `attest_core.runtime` (implemented): import-override validation and
  deterministic runtime settings (interpreter, `PYTHONPATH`, manifest hashes)
  bound into the configuration digest.
- `attest_core.sandbox` (planned): execution isolation and resource limits.
- `apps.cli` (implemented): argparse entry point mapping outcomes to exit
  codes; no CLI framework dependency.
- `apps.approvals` (implemented): YAML approval store keyed by id/version.
- `apps.review` (implemented): invariant display and confirmed approval.
- `apps.verify` (implemented): authoritative verification flow.
- `apps.output` (implemented): text and versioned JSON report rendering.
- `apps.demo_api` (implemented): synthetic FastAPI fixtures and the
  registered-route inventory.
- `integrations.meta_models` (planned): isolated Meta model client boundary.
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
   tree, and validates/binds the runtime environment.
5. `run_verification` requires a matching approval at invocation and raises
   instead of verdicting when it is absent or stale.
6. Checks compare declared scope against the app's registered routes, then
   run 401/403/200 probes per endpoint over a fresh test client, each
   attempt in a bounded worker subprocess.
7. The orchestrator genuinely re-executes the checks three times under one
   recorded revision and configuration digest, emitting per-check and
   per-attempt evidence records.
8. A post-run fingerprint mismatch overrides any verdict with INCONCLUSIVE.
9. The verdict policy classifies the attempt set as PASSED, FAILED, or
   INCONCLUSIVE; an attestation references every evidence hash.

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
