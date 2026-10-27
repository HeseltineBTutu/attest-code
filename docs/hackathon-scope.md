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

## Next step (recommended)

Build the Meta integration boundary in this order:

1. `integrations.meta_models`: isolated client using official Meta API docs
   and real model identifiers only.
2. Diagnose-and-propose-patch flow evaluated against the unchanged approved
   invariant; the model never verdicts and never writes the registry.

## Planned after that

- `attest_core.sandbox`: execution isolation and resource-limit interfaces.
- `attest_sdk`: public programmatic interface.

## Explicitly out of scope

Dashboard, billing, multi-tenant SaaS, autonomous merging, IDE integrations,
general-purpose AI coding agent, and signing infrastructure (this phase).
