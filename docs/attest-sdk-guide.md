# Attest SDK — Consumer Guide (P5)

Pre-release (`1.0.0a0`), local build only. No public package is
published and no production readiness is claimed. Normative behavior
is defined by frozen Attest Spec v1 (`docs/attest-spec-v1.md`); the
full call inventory is `docs/attest-sdk-api-reference.md`.

## Install

Prerequisites: Python >= 3.11 and `uv`. From a checkout:

```sh
uv build
uv pip install --python <your-env> dist/attest_code-0.1.0-py3-none-any.whl
```

This installs the `attest-code` distribution, which currently bundles
the SDK with the engine, CLI, demo, and integrations. An SDK-only
distribution does not exist yet; SDK-only consumers still install
`fastapi` and `httpx` transitively even though the SDK never imports
them. Runtime SDK needs are `attest_spec` (bundled), the stdlib, and
PyYAML (only on YAML code paths; top-level import stays light).

## Minimal example

```python
>>> from attest_sdk import load_invariant, invariant_digest, schema_version_of
>>> doc = b'''{"spec_version": 1, "id": "DOC-001", "version": 1,
... "title": "T", "requirement": "R.", "scope": ["/a"],
... "invariant_type": "security.access-control",
... "verification_type": "http-auth-probe/1"}'''
>>> invariant = load_invariant(doc)  # or load_invariant(Path("inv.json"))
>>> len(invariant_digest(invariant))
64
>>> schema_version_of({"schema_version": 3})  # route explicitly: 2 or 3
3
```

## Four separate operations

1. **Parsing** (`load_invariant`, `parse_request`, `parse_attestation`)
   validates structure only. Parsing never verifies anything.
2. **Integrity verification** (`verify_v3`, `verify_v2`) checks digests,
   bindings, and (when records are supplied) ordered evidence. It
   authorizes nothing and executes nothing.
3. **Eligibility** (`Registry.check_eligible`) folds approval and
   lifecycle history at one registry state. Current eligibility never
   rewrites history.
4. **Execution** (`verify`) runs a pinned verifier three times under
   the parent engine, which alone classifies the verdict. Verifiers
   report observations, never verdicts.

## v2 versus v3

Records route explicitly by `schema_version`: v2 via `verify_v2`
(exact legacy semantics, errors wrapped with the original chained),
v3 via `verify_v3` / `verify_historical`. Unknown versions refuse;
versions never fall back to each other. v2 records carry no
`registry_commit` and therefore cannot replay historically.

## Historical verification

`verify_historical` replays both chains as of the recorded commit via
your `materialize` hook. The materializer is trusted and
verifier-controlled, never presenter-supplied: it resolves the exact
immutable commit (ignoring `ref`) and returns one stable snapshot.
The SDK cannot prove materializer honesty. Full contract:
`docs/attest-sdk-history-contract.md`.

## Errors and edge semantics

- Every refusal raises an `AttestError` subclass and means no verdict
  was produced. `ValueError` signals caller programming errors only.
- `evidence=None` skips ordered record binding; every other check
  still applies. Pass records when you need record verification.
- Deprecated state replays as eligible with a warning (v3 records no
  policy, so strict-then is unknowable). Revocation is prospective:
  later revocation never invalidates a valid historical replay.
- Unknown `verification_type`/`execution_profile` values in a record
  are preserved through integrity checks but authorize nothing.

## Trust assumptions and limitations

- A matching digest proves integrity against a trusted digest, never
  authorship. No signing infrastructure exists.
- Approval records carry unauthenticated display names; Git history is
  an accountability aid, not cryptographic authenticity.
- `FAILED` requires three reproducible violations; crashes, timeouts,
  and incomplete evidence yield `INCONCLUSIVE`, never `FAILED`.

## What stays outside the SDK

Git checkout/materialization, sandbox or container execution, CI/IDE
adapters, and verifier implementations for other normative types are
caller or deployment responsibilities. The reference adapter in
`examples/` demonstrates the verifier contract; it is not part of
the SDK core and is not authoritative over the parent engine.
