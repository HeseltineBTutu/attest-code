# Attest Code

Independent software verification layer: code is evaluated against explicit,
developer-approved invariants.

Core principle: **a generator cannot be a verifier.** Meta models may diagnose
failures and propose repairs. They must not control the invariant registry,
weaken approved requirements, or determine the final verdict.

## Current status (F7: verified execution snapshot)

Implemented:

- `attest_spec`: shared contracts (`Invariant`, `ApprovalRecord`, verdict enums).
- `attest_core.invariants`: definition loading, validation, versioning, and an
  explicit human-approval boundary.
- `attest_core.evidence`: versioned evidence records, SHA-256 digests over
  canonical JSON, and attestation v2 with invariant-content binding plus
  `verify_attestation`.
- `attest_core.verdicts`: deterministic policy (FAILED requires three
  reproducible violations under the same revision and configuration).
- `attest_core.verification`: orchestration that re-executes the approved
  checks three times under one recorded revision and configuration, then
  classifies via the verdict policy. PASSED means verified under that policy.
- `attest_core.git`: focused adapter resolving revisions and enforcing the
  clean-snapshot policy.
- `attest_core.origin`: repository-root canonicalization and parent/worker
  module-origin binding (F1).
- `attest_core.runtime`: import-override validation, startup-module preflight,
  and deterministic runtime settings bound into the configuration digest
  (F2/F5).
- `attest_core.bounds`: wall-clock-bounded worker subprocesses per attempt,
  each re-validating its own snapshot origins before running checks.
- `attest_core.snapshot`: execution closure exported from Git objects with a
  manifest digest; workers import from the verified snapshot instead of the
  live worktree, and the manifest is re-verified at every attempt boundary
  (F7). The digest is bound into verification evidence; continuous
  within-attempt immutability is not guaranteed.
- `apps.demo_api`: synthetic FastAPI app with vulnerable, incomplete-repair,
  repaired, hanging, and crashing fixtures plus a registered-route inventory.
- `examples.admin_authorization`: approved independent checks for
  AUTH-ADMIN-001 with fail-closed scope coverage.
- `apps.cli` (`attest review` / `attest verify`): operator approval flow and
  authoritative verification with text and versioned JSON output.
- `invariants/auth-admin-001.yaml`: the approved invariant definition.
- `integrations.meta_models`: isolated Meta Model API client
  (diagnose-and-propose-patch). Standard model `muse-spark-1.3` only;
  contributor variants are refused. Requires a FAILED verify report,
  sends only bounded diagnostic inputs, validates the reply's diff
  against the `src/`/`tests/` scope, and renders the proposal as
  UNVERIFIED for human review. Never verdicts, never writes the repo.
- 256 tests covering the slice, the CLI, git policy, bounded execution,
  the F1–F7 security controls, and the Meta integration contract.

Not yet implemented (see `docs/hackathon-scope.md`):

- Sandbox isolation against malicious code.
- `attest_sdk` public programmatic interface.

## CLI usage

```sh
export UV_CACHE_DIR=/tmp/uv-cache  # only if the default uv cache is read-only
uv sync --group dev

# Review and approve (requires explicit confirmation; --approver names you)
uv run attest review invariants/auth-admin-001.yaml --approver <name>

# Verify the recorded snapshot (revision must be checked out, tree clean)
uv run attest verify invariants/auth-admin-001.yaml --revision HEAD
uv run attest verify invariants/auth-admin-001.yaml --revision HEAD --format json
uv run attest verify invariants/auth-admin-001.yaml --revision HEAD --target vulnerable

# Diagnose a FAILED report (needs MODEL_API_KEY; human review still required)
uv run attest verify invariants/auth-admin-001.yaml --revision HEAD \
  --target vulnerable --format json > /tmp/verify.json
uv run python -m integrations.meta_models diagnose --report /tmp/verify.json \
  --invariant-file invariants/auth-admin-001.yaml --excerpt <excerpt-file>
```

Exit codes: 0 for approval/PASSED, 1 for FAILED, 2 for INCONCLUSIVE, 3 for
usage errors, declined review, invalid approval, unsafe snapshots, or other
execution errors.

## Quickstart

Prerequisites: Python >= 3.11 and `uv`.

```sh
export UV_CACHE_DIR=/tmp/uv-cache  # only if the default uv cache is read-only
uv sync --group dev
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src tests
```

Run just the vertical slice: `uv run pytest tests/test_admin_authorization.py -q`.
Run the CLI suites: `uv run pytest tests/test_review.py tests/test_verify_cli.py -q`.

## Documents

- `docs/architecture.md`: module boundaries and data flow.
- `docs/security-model.md`: trust boundaries, approval design, and limitations.
- `docs/hackathon-scope.md`: implemented vs planned work.

## Security notes

- A YAML `approved: true` field is ignored; only a separate approval record
  created through an explicit human flow confers authority.
- Hashing detects changes relative to a trusted digest. It does not establish
  authorship or authenticity. No signing infrastructure exists in this phase.
- No universal correctness is claimed. Each verdict states precisely what was
  checked. Incomplete evidence yields INCONCLUSIVE, never FAILED.
