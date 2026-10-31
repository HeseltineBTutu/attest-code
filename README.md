# Attest Code

Independent software verification layer: code is evaluated against explicit,
developer-approved invariants — never against a generator's own claims about
itself.

Core principle: **a generator cannot be a verifier.** Models may diagnose
failures and propose repairs, but they must not control the invariant
registry, weaken approved requirements, or determine the final verdict.
That boundary is enforced in code, not just documented: the parent
verification engine alone classifies verdicts.

## Current status and maturity

Pre-release research software. Nothing here claims production readiness.

- **Attest Spec v1 is frozen** (`docs/attest-spec-v1.md`, frozen
  2026-10-31): the portable, language-independent contract for invariant
  documents, canonicalization, approval and lifecycle chains,
  verification requests, and attestations.
- **Conformance fixtures are published** (`spec/attest-spec/v1/vectors/`):
  canonicalization, boundary-limit, and chain-evaluation vectors with a
  manifest. Implementations must reproduce applicable vectors byte-for-byte.
- **`attest_sdk` is implemented through P5** (pre-release `1.0.0a0`,
  local build only): canonicalization and invariant validation, registry
  folds and eligibility, verification requests with a parent-owned
  engine, attestation v3 issuance with historical verification and v2
  dual-read, and a stabilized 58-name public API.
- **Execution is injected, not built in.** The SDK defines a `Verifier`
  protocol and orchestrates three attempts; the caller supplies the
  executable verifier. `src/examples/reference_adapter.py` demonstrates
  the contract and is not authoritative.
- **History replay needs a caller-supplied materializer.** Git checkout
  stays outside the SDK; the materializer is trusted and
  verifier-controlled, and the SDK cannot prove its honesty.
- **Distribution is a local monorepo wheel** (`attest-code`, built with
  `uv build`). There is no SDK-only distribution and no public package
  release; both are explicitly deferred.

## How verification works

1. A developer writes an invariant: an ID, version, normative
   requirement, scope, and verification type.
2. A human approves the exact invariant bytes. Approval binds an
   invariant ID, version, and content digest; any content change voids
   the binding until fresh approval.
3. The engine checks eligibility (approval plus lifecycle state),
   runs the pinned verifier three times under one recorded revision
   and configuration, then classifies the verdict itself.
4. Passing or failing runs emit evidence-bound attestations that stay
   verifiable as historical records, independent of later revocation.

```python
>>> from attest_sdk import SUPPORTED_SPEC_VERSIONS, schema_version_of
>>> SUPPORTED_SPEC_VERSIONS
(1,)
>>> schema_version_of({"schema_version": 2})
2
```

## Architecture and component boundaries

- `docs/attest-spec-v1.md`: the frozen normative contract. Everything
  else implements it; nothing reinterprets it.
- `attest_sdk`: parsing, canonicalization, digests, registry folds,
  requests, parent-owned verification, attestation v3, and historical
  replay. No Git, subprocess, or network execution at runtime.
- `attest_spec`: shared dependency-free contracts (invariant shape,
  verdict enums).
- `attest_core` + `apps.cli`: the original (v0) engine — approval
  store, bounded supervised workers, snapshot enforcement, execution
  profiles, and the `attest review` / `attest verify` CLI. The SDK
  reuses its verdict policy and evidence record shapes.
- `examples/`: reference checks and the reference adapter. Demonstrates
  contracts; never authoritative.
- `integrations.meta_models`: isolated diagnose-and-propose client.
  Renders suggestions UNVERIFIED for human review; never verdicts and
  never writes the repo.
- `apps.demo_api`: synthetic FastAPI fixtures (vulnerable, incomplete,
  repaired, hanging, crashing) used by tests and the CLI demo targets.

Details: `docs/architecture.md`, `docs/attest-sdk-guide.md`,
`docs/attest-sdk-api-reference.md`.

## Installation and quick start

Prerequisites: Python >= 3.11 and `uv`.

```sh
export UV_CACHE_DIR=/tmp/uv-cache  # only if the default uv cache is read-only
uv sync --group dev
./scripts/quality-gate.sh  # line-limit, ruff, format, mypy, full suite
```

Build and install the local distribution:

```sh
uv build  # dist/attest_code-0.1.0-py3-none-any.whl (monorepo wheel, not SDK-only)
uv pip install --python <your-env> dist/attest_code-0.1.0-py3-none-any.whl
```

Consumer workflows and the public API:
`docs/attest-sdk-guide.md`, `docs/attest-sdk-api-reference.md`.

## Defining and approving invariants

- v0 YAML flow (CLI-managed): `invariants/auth-admin-001.yaml` holds the
  approved example definition; `approvals.yaml` holds the approval store.

```sh
uv run attest review invariants/auth-admin-001.yaml --approver <name>
uv run attest verify invariants/auth-admin-001.yaml --revision HEAD
uv run attest verify invariants/auth-admin-001.yaml --revision HEAD --format json
uv run attest verify invariants/auth-admin-001.yaml --revision HEAD --target vulnerable
```

`review` takes `--approver` (required), `--approvals`, `--id`.
`verify` takes `--revision` (required), `--repo`, `--target`
(`vulnerable`, `incomplete`, `repaired`, `hanging`, `crashing`),
`--timeout`, `--format`, `--exec` (`standard`, `contained`, `hardened`).

- v1 registry flow (spec-defined): append-only approval and lifecycle
  event chains under `registry/approvals/` and `registry/lifecycle/`.
  The SDK reads, validates, and folds these chains. Chain authoring
  tooling does not exist yet; the CLI manages only the v0 store.

## Verdicts and CLI exit codes

- `PASSED`: verification requirements satisfied.
- `FAILED`: reproducible invariant violation under the defined policy —
  three violations under the same revision and configuration, each with
  evidence.
- `INCONCLUSIVE`: verification could not establish a trustworthy
  result. Crashes, timeouts, missing or incomplete evidence, and
  infrastructure failures land here, never in `FAILED`.

CLI exit codes (`src/apps/cli.py`): 0 for approval/`PASSED`, 1 for
`FAILED`, 2 for `INCONCLUSIVE`, 3 for usage errors, declined review,
invalid approval, unsafe snapshots, or other execution errors.

## Attestations and historical verification

- Attestation v2 (legacy): verdict statement bound to invariant content
  and ordered evidence hashes. Retained and verifiable indefinitely.
- Attestation v3: adds execution-time context — spec version, effective
  approval event, structured registry commit, exact verifier identity,
  revision, execution profile, and observed lifecycle state. The SDK
  issues and verifies v3; digest covers the complete payload.
- Historical verification replays approval and lifecycle folds as of
  the recorded registry commit. Later revocation never rewrites a
  historical verdict; unresolvable history refuses with no verdict and
  no fallback to current state.
- Routing is explicit: v2 records verify only via `verify_v2`, v3 only
  via `verify_v3` / `verify_historical`. Unknown versions refuse.

## Security model and limitations

Enforced: approval bound to exact content digests; three-attempt
reproducibility policy; parent-owned verdicts; snapshot and revision
enforcement with before/after fingerprinting; bounded, supervised
worker execution; fail-closed handling of ambiguous history,
malformed input, and unknown normative semantics.

Trust assumptions: the historical materializer is honest and
verifier-controlled (the SDK establishes no Git provenance); digests
are checked against caller-trusted values; approver names and methods
are unauthenticated display strings; the injected verifier is
validated observation-by-observation but executes outside the SDK.

Known limitations: no OS-enforced isolation; no signing or PKI and no
authenticated authorship; a change planted and reverted strictly
inside one attempt is invisible by construction; SDK replay of a
deprecated version is permissive because v3 records no policy.

Details: `docs/security-model.md`, `docs/attest-sdk-history-contract.md`.

## Testing and conformance

```sh
uv run pytest  # full suite, including docs and line-limit enforcement
uv run pytest tests/test_integration/test_admin_authorization.py -q  # vertical slice
uv run pytest tests/test_src/test_apps/test_review.py tests/test_cli/test_verify_cli.py -q
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src tests
```

Tests establish that the implementation matches the frozen spec and
vectors, that refusal paths fail closed, and that verdict semantics
hold across unit, CLI, and integration coverage. They do not establish
production readiness, complete sandbox security, tamper-proofing, or
materializer authenticity. Conformance fixture rules and limits:
`spec/attest-spec/v1/vectors/README.md`. Test organization:
`docs/testing.md`.

## Roadmap and deferred work

Done: attest-spec v1 design, freeze, and published vectors; `attest_sdk`
P0–P5 (scaffolding, canonicalization, registry folds, requests and
engine, attestations and history, API stabilization and packaging).

Deferred or planned, in roadmap order: further verifier
implementations, IDE/CI integrations and adapters, evidence
interoperability, and distribution and adoption (including any
SDK-only distribution or public release).

## Documentation index

- `docs/attest-spec-v1.md`: frozen normative specification (authoritative).
- `spec/attest-spec/v1/vectors/README.md`: conformance fixture guide.
- `docs/attest-sdk-guide.md`: SDK consumer workflows.
- `docs/attest-sdk-api-reference.md`: public API inventory.
- `docs/attest-sdk-history-contract.md`: historical materializer contract.
- `docs/attest-sdk-implementation-plan.md`: SDK implementation phases.
- `docs/architecture.md`: module boundaries and data flow.
- `docs/security-model.md`: trust boundaries and limitations.
- `docs/testing.md`: test organization and quality gates.
- `docs/hackathon-scope.md`: original project scope log.
