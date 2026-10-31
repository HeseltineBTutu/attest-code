# Attest SDK — Public API Reference (P5)

Stabilized public contract for `attest_sdk`. Normative behavior is defined
by frozen Attest Spec v1 (`docs/attest-spec-v1.md`); this document lists
only the SDK surface, signatures, and caller-visible commitments. It does
not duplicate the specification and does not claim production readiness.

`SUPPORTED_SPEC_VERSIONS == (1,)`; `__version__ == "1.0.0a0"` (pre-release;
the 1.0.0 API-stability marker follows a separate release decision).

## Entry points

| Function | Purpose |
|---|---|
| `verify(request, invariant, verifier, registry) -> Report` | Full verification: refusal gates, three attempts, parent-classified verdict. The invariant MUST come from `load_invariant`; the verifier is untrusted. |
| `parse_request(data) -> VerificationRequest` | Validate §9 request wire data (structure only; no execution). |
| `load_invariant(source, source_format="json") -> Invariant` | Parse + schema-validate a v1 invariant from `Path` or bytes. `source_format` other than `"json"`/`"yaml"` raises `ValueError`. |
| `invariant_digest(invariant) -> str` | P1 content digest over the covered projection (excludes publisher/metadata). |
| `ensure_known_verification_type(invariant)` | Execution-boundary refusal for unknown verification types. |
| `issue_attestation(report, *, spec_version, registry_commit, statement)` | Emit a v3 `(payload, digest)` pair; transcribes the engine verdict, never re-decides. `registry_commit.vcs` must be `"git"`. |
| `verify_v3(payload, invariant, expected_digest, evidence=None)` | v3 integrity: structure, full-payload digest, invariant bindings, ordered evidence. |
| `verify_v2(payload, invariant, expected_digest, evidence=None)` | Legacy v2 dual-read under exact legacy accept/reject semantics; errors wrapped with `__cause__` preserved. Takes the legacy `attest_spec.Invariant`. |
| `verify_historical(payload, invariant, expected_digest, materialize, evidence=None)` | v3 integrity plus approval/lifecycle replay as of `registry_commit`. See the materializer contract below. |
| `parse_attestation(payload) -> AttestationV3` | Structural validation only — never verification. |
| `schema_version_of(payload) -> int` | Explicit version routing (`2` or `3`); callers route, the SDK never falls back. |
| `canonicalize / canonicalize_bytes / digest_of / digest_bytes` | P1 profile primitives over values or source bytes (JSON or YAML). |
| `unicode_version() -> str` | Declared Unicode normalizer version, or `"unknown"`. |

## Types

- Documents: `Invariant`. Requests: `VerificationRequest`, `VerifierRef`, `ArtifactState`, `EXECUTION_PROFILES` (`standard`, `contained`, `hardened`).
- Registry: `Registry(root)`, `ApprovalHistory`/`LifecycleHistory` (event tuples plus stray reports), `ApprovalEvent`/`LifecycleEvent`, `Eligibility`, `Policy(strict_deprecated=False, require_artifact_digest=False)`.
- Execution: `Verifier` protocol (`verification_type`, `implementation`, `version`, `spec_versions`, `inventory_mechanism`, `run(...)`), `AttemptObservation`, `Report`, `KNOWN_VERIFICATION_TYPES` (`http-auth-probe/1`).
- Attestations: `AttestationV3`, `RegistryCommit(vcs, commit, ref=None)`, `HistoricalAttestation`, `errors` module namespace.

## Exceptions (all under `AttestError`)

`ParseError`, `SchemaError`, `CanonicalizationError` (`LimitExceededError`),
`UnsupportedSpecVersionError`, `RegistryError` (`AmbiguousHistoryError`),
`ApprovalError` (`NoApprovalError`, `StaleApprovalError`,
`RevokedApprovalError`), `EligibilityError`, `VerifierError`
(`UnknownVerificationTypeError`, `UnsupportedVerifierSpecError`,
`VerifierRefusedError`, `VerifierParameterError`), `AttestationError`,
`HistoryUnavailableError`. Every SDK refusal raises one of these; a raised
error always means no verdict was produced. `ValueError` is reserved for
programming errors (bad `source_format`, bad `Registry` arguments).

## Routing and trust rules

- v2 records verify only via `verify_v2`; v3 only via `verify_v3` /
  `verify_historical`. Unknown schema versions refuse; versions never
  fall back to each other. v2 records cannot replay (no `registry_commit`).
- `evidence=None` skips ordered record binding only; all other integrity
  checks still apply. Callers needing record verification must pass records.
- `verify_historical` folds both chains over the single directory returned
  by the caller-supplied materializer. Full contract:
  `docs/attest-sdk-history-contract.md` — trusted, verifier-controlled,
  never presenter-supplied; exact-commit resolution ignoring `ref`; one
  stable snapshot; the SDK cannot prove materializer honesty.
- Deprecated replays as eligible with a warning (permissive; v3 records
  no policy). Revocation is prospective: replay at the recorded commit is
  unaffected by later revocation.
- Unknown `verification_type`/`execution_profile` values in a record are
  preserved through integrity checks but authorize nothing; execution
  still refuses unknown verification types before running.

## Compatibility commitments

- All names in `attest_sdk.__all__` are intentional and sorted; the
  import stays light (no `attest_core`, FastAPI, pytest, or YAML pulled
  by top-level import — enforced by `test_package.py`). PyYAML is
  required only on YAML code paths.
- `attest_core` is lazily required for `verify`, evidence-bound v3
  verification, v2 dual-read, and `Report`/`EvidenceRecord` handling.
  Pure canonicalization, parsing, digest, registry-fold, and
  structure-only operations need only `attest_spec` plus the stdlib
  (and PyYAML for YAML sources).
- No Git, subprocess, or network execution exists in the SDK runtime.
  Git materialization is the caller's responsibility via the
  materializer hook.
