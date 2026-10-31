# attest-spec v1 — Conformance Vectors

Frozen test vectors for `attest-canonical-json` v1, resource limits,
and registry chain evaluation. Normative document:
`docs/attest-spec-v1.md`. These files are the freeze baseline:
implementations MUST reproduce every applicable vector byte-for-byte.

## Layout

- `manifest.json` — complete inventory. Every fixture lists its input
  file, kind, expected outcome, and (for valid cases) the expected
  canonical bytes file, byte length, and SHA-256 digest.
- `canonical/` — core vectors V1-updated, V2–V7 plus
  `auth-admin-001` (the amended §3 example) and V6 (v0 payload).
- `boundaries/` — resource-limit pairs: accept at exactly the limit,
  refuse at limit-plus-one, for source bytes, depth, string
  scalars, container entries, and canonical output bytes; plus a
  YAML alias-expansion bomb and an astral scalar-count test.
- `chains/` — approval-chain, lifecycle-chain, and joint-evaluation
  fixtures with expected validity, effective approval, and state.

## Encodings

- `.input.json` / `.canonical.json`: exact UTF-8 bytes. Compare
  byte-for-byte; a digest match alone is insufficient evidence.
- `.input.bytes`: raw bytes that are NOT valid UTF-8 (V5c).
- `.input.yaml`: UTF-8 YAML 1.2 core-schema sources. Expand aliases
  per the YAML specification, then canonicalize the resulting
  value model. Alias expansion MUST be bounded before
  materialization (§5 limits).
- `.chain.json`: UTF-8 JSON describing one chain evaluation:
  `chain_dir`, `kind` (`approval`, `lifecycle`, or `joint`),
  `files` (name/content pairs in registry layout), and `expect`.

## Expected outcomes

- `valid`: canonicalize the input bytes; the output bytes and
  SHA-256 MUST equal the published values exactly.
- `invalid`: refuse with the named `reason_class` (duplicate-key,
  non-integer-number, trailing-data, invalid-utf8,
  non-json-constant, limit-*, ...). Reason wording is
  implementation-defined; only the refusal and its class are
  normative.
- Chain `expect.validity`: `valid` (evaluate fold/state),
  `ambiguous` (refuse, no verdict), or valid-with-null
  `effective_approval` (refuse, no approval). `outcome` uses
  `eligible-subject-to-lifecycle` where only one chain is shown.

## How to consume

1. Parse `manifest.json` and iterate `fixtures`.
2. For `probe_checkable` canonical/boundary fixtures: feed the
   input file bytes to the implementation, compare output bytes
   and digest, or confirm refusal with the right class.
3. Boundary `refuse` fixtures and YAML fixtures whose outcome is
   `invalid` require limit enforcement and YAML support; they are
   marked `"probe_checkable": false` for byte-comparison harnesses
   without those capabilities, but their expected outcomes are
   still normative.
4. Chain fixtures: materialize `files` into the `chain_dir`
   layout (or equivalent), run registry validation, fold, and
   joint evaluation per §§7–8, and compare `validity`,
   `effective_approval`/`state`, and `outcome`.
5. `joint-*` fixtures reference two chain fixtures by id plus a
   registry state; evaluate both at the same state per §8.

## Notes

- V6 reproduces the live v0 digest `67c5a545...f103` as an
  ASCII-subset compatibility proof. It MUST NOT approve the v1
  document. `auth-admin-001` canonical bytes hash to
  `219bf343...`, while its invariant content digest (publisher
  excluded per §3) is `686892e3...`; chain fixtures bind the
  content digest, never the canonical bytes hash.
- The `out8m` pair is large by construction (8,388,608 canonical
  bytes): the output limit is reachable in practice only through
  YAML alias expansion, and the fixtures prove the exact
  boundary. Implementations MUST count output bytes during
  serialization and refuse past the limit.
- Depth counts every nesting level with the root at depth 0, so
  `depth32.accept` (32 nested arrays plus scalar) is the
  deepest valid shape and `depth33.refuse` exceeds it by one.
- String length counts Unicode scalar values, never UTF-16 code
  units; `astral-scalar.accept` (65,535 ASCII plus one astral
  character) discriminates the two counting methods.
- Vector files are frozen. Corrections require a specification
  amendment; implementations MUST NOT substitute their own
  expected values.
