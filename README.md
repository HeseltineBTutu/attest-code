# Attest Code

Independent software verification layer: code is evaluated against explicit,
developer-approved invariants.

Core principle: **a generator cannot be a verifier.** Meta models may diagnose
failures and propose repairs. They must not control the invariant registry,
weaken approved requirements, or determine the final verdict.

## Current status (Phase 3: CLI and revision integrity)

Implemented:

- `attest_spec`: shared contracts (`Invariant`, `ApprovalRecord`, verdict enums).
- `attest_core.invariants`: definition loading, validation, versioning, and an
  explicit human-approval boundary.
- `attest_core.evidence`: versioned evidence records and SHA-256 digests over
  canonical JSON.
- `attest_core.verdicts`: deterministic policy (FAILED requires three
  reproducible violations under the same revision and configuration).
- `attest_core.verification`: orchestration that re-executes the approved
  checks three times under one recorded revision and configuration, then
  classifies via the verdict policy. PASSED means verified under that policy.
- `attest_core.git`: focused adapter resolving revisions and enforcing the
  clean-snapshot policy.
- `attest_core.bounds`: wall-clock-bounded worker subprocesses per attempt.
- `apps.demo_api`: synthetic FastAPI app with vulnerable, incomplete-repair,
  repaired, hanging, and crashing fixtures plus a registered-route inventory.
- `examples.admin_authorization`: approved independent checks for
  AUTH-ADMIN-001 with fail-closed scope coverage.
- `apps.cli` (`attest review` / `attest verify`): operator approval flow and
  authoritative verification with text and versioned JSON output.
- `invariants/auth-admin-001.yaml`: the approved invariant definition.
- 79 tests covering the slice, the CLI, git policy, and bounded execution.

Not yet implemented (see `docs/hackathon-scope.md`):

- Sandbox isolation against malicious code and the Meta model integration
  boundary (diagnose only, no API calls in this phase).

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
