# Hackathon Scope

Built for the Meta Global AI Developer Hackathon.

## Implemented (Phase 1: foundation)

- uv-managed Python project (`pyproject.toml`, `.venv`, dev group).
- `attest_spec` contracts; `attest_core` invariants, evidence, and verdicts.
- pytest suite (15 tests), Ruff lint/format, mypy strict.
- README, architecture, security-model, and this scope document.

## Implemented (Phase 2: AUTH-ADMIN-001 vertical slice)

- `apps.demo_api`: FastAPI app with `/admin/users` and `/admin/settings`,
  synthetic users only; vulnerable, incomplete-repair, and repaired
  factories returning fresh app objects; prefix-based route inventory.
- `examples.admin_authorization`: approved checks (401/403/200 per endpoint)
  with fail-closed scope coverage against registered routes.
- `attest_core.verification`: orchestration re-executing checks three times
  under one recorded revision and configuration; approval required at
  invocation; per-check and per-attempt evidence plus attestation.
- `invariants/auth-admin-001.yaml`: the invariant definition.
- pytest suite (40 tests), Ruff lint/format, mypy strict. No Meta API calls.

## Implemented (Phase 3: CLI and revision integrity)

- `attest review`: invariant display with content digest, prior-approval
  state, explicit-confirmation approval into a YAML store.
- `attest verify`: full-OID resolution, clean-snapshot enforcement, approval
  validation, bounded worker attempts, before/after fingerprinting, text and
  versioned JSON output, documented exit codes (0/1/2/3).
- `attest_core.git` and `attest_core.bounds`: focused adapter and
  terminate-on-deadline workers (bounding, not a sandbox).
- pytest suite (79 tests), Ruff lint/format, mypy strict. No Meta API calls.

## Implemented (F1–F7: verification integrity hardening)

- F1: module-origin binding — executed verifier/demo packages must resolve
  inside the snapshot-enforced tree (parent and worker probe).
- F2/F3: expanded snapshot coverage (source, tests, invariants, root
  manifests), ignored-executable detection, and Git index-flag checks.
- F4: attestation v2 binding the verified invariant content digest, with
  `verify_attestation` validation.
- F5: startup-module preflight (root and `src/`), already-imported tripwire,
  and runtime/dependency settings bound into the configuration digest.
- F6: per-attempt live fingerprint guards and per-run worker bytecode-cache
  isolation.
- F7: execution closure exported from Git objects with a manifest digest;
  workers import from the verified snapshot, each worker re-validates its
  own origins, the manifest is re-verified at every attempt boundary, and
  the snapshot digest is bound into verification evidence.
- pytest suite (210 tests), Ruff lint/format, mypy strict. No Meta API calls.

Accepted limitations (see `docs/security-model.md`): no sandbox — workers
share operator privileges; continuous within-attempt immutability is not
guaranteed; digests prove content identity, never authenticity; the parent
interpreter remains inside the trusted-launch boundary.

## Implemented (Meta integration: diagnose-and-propose-patch)

- `integrations.meta_models`: isolated client for the Meta Model API
  (`https://api.meta.ai/v1`, `POST /chat/completions`, Bearer auth).
  Live check on 2026-10-28: `GET /models` returned HTTP 200 with
  `muse-spark-1.3` listed; that standard model is the pinned default and
  contributor variants are refused.
- Transport has explicit timeouts, bounded retries (transient failures
  only; 401/403/4xx never retried, `Retry-After` honored), request and
  response size caps, and sanitized errors that never carry the API key.
- Diagnose-only contract: `list_models()` and `diagnose()` over bounded
  inputs (invariant id/version/text, sanitized FAILED summary, bounded
  excerpt). Model replies must carry separate diagnosis and unified-diff
  fields; diffs are structurally validated and confined to `src/`/`tests/`.
- FAILED-gating: only schema-v1 FAILED verify reports are diagnosed;
  INCONCLUSIVE and PASSED are refused. Output is rendered UNVERIFIED for
  human review. The model never verdicts, never touches approvals,
  evidence, or the registry, and nothing is applied automatically.
- No new dependencies (`httpx` was already present). pytest suite
  (256 tests), Ruff lint/format, mypy strict. Unit tests use a mocked
  transport; they do not claim live API availability.

Accepted limitations: the completion response shape is parsed strictly
and fails closed if it differs; optional API parameters (such as
`response_format`) are omitted until verified; standard proxy
environment variables are honored with TLS verification. The diagnose
input report is operator-supplied JSON: it is shape-validated, not
attestation-verified by this tool, and it influences only the
diagnostic prompt — never any verdict or evidence.

## Next milestone (recommended)

- `attest_core.sandbox`: execution isolation and resource-limit interfaces.

## Planned after that

- `attest_sdk`: public programmatic interface.

## Explicitly out of scope

Dashboard, billing, multi-tenant SaaS, autonomous merging, IDE integrations,
general-purpose AI coding agent, and signing infrastructure (this phase).
