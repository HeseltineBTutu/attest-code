# attest-spec v1 — Consolidated Design Proposal

Status: **FROZEN** — attest-spec v1, frozen 2026-10-31 by explicit
project-owner authorization. Normative content (sections 3–14) is
fixed; further changes require a specification amendment. This
document does not change runtime code, tests, schemas used by the
live verifier, or production configuration.

Amendment record: O1–O6 freeze decisions from
`docs/attest-spec-v1-freeze-decisions.md` incorporated per owner
approval, including the Unicode-demonstration and YAML-alias-bounding
clarifications. Remediation record: F1–F12 audit findings
resolved per specification-remediation authorization. Freeze record:
see section 17.

Scope: the portable invariant document, canonicalization and digest
rules, classification, the approval event chain, lifecycle and
revocation, the verification request and exact verifier identity
contract, attestation v3 execution-time context, historical
verification, migration, and conformance. `attest_sdk`, verifiers,
adapters and distribution are out of scope and unchanged in roadmap
order.

Labels used throughout: **Normative** (a rule implementations must
follow), **Recommendation** (advisory), **Assumption** (a relied-upon
fact or limitation), **Test** (a conformance check), **Open** (needs an
owner decision; see section 18).

## 1. Executive summary and scope

attest-spec v1 separates four things the v0 engine already keeps apart
in practice — invariant content, human approval, execution, and evidence
— and makes each portable across implementations. The v1 document adds
`spec_version`, `invariant_type` and `verification_type` to the
digest-covered core; lifecycle and approval state move out of the
document into append-only, content-addressed, hash-chained registry
histories; verification requests pin an exact verifier identity;
attestation v3 records full execution-time context so history stays
verifiable after later revocation. Canonical bytes are defined by
`attest-canonical-json` v1, a constrained JCS-compatible profile
verified byte-for-byte by two independent implementations (Python and
JavaScript, sharing no code). The three-verdict model, CLI exit codes
and refusal-before-verdict rule are unchanged.

## 2. Normative terminology

**Normative.** The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`,
`SHALL NOT`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `MAY` and
`OPTIONAL` are to be interpreted as described in RFC 2119. A `MUST`
violation by an input means rejection; a `MUST` violation by an
implementation means non-conformance.

## 3. Complete invariant schema and AUTH-ADMIN-001 example

**Normative.** An invariant document is a JSON object (or YAML
convertible per section 5) with these fields:

Required and digest-covered: `spec_version` (integer, `1` in v1),
`id` (non-empty string), `version` (integer >= 1),
`title` (non-empty string), `requirement` (non-empty string),
`scope` (non-empty ordered array of non-empty strings),
`invariant_type` (non-empty classification label, section 4),
`verification_type` (non-empty procedure id, section 10).

Optional and digest-covered: `description` (string), `applicability`
(object), `parameters` (object), `evidence_expectations` (object).

Optional and NOT digest-covered: `publisher` (string),
`metadata` (object). These MUST be preserved and carried but MUST NOT
affect the digest or any verdict. `x-` prefixed fields, when
present, are digest-covered like any present field;
MAY-ignore-semantics does not exclude them from canonical bytes.

**Normative.** `publisher`, when present, MUST be 1 to 8
dot-separated segments, each matching
[a-z0-9]([a-z0-9-]*[a-z0-9])?, with total length 1 to 128
characters. Uppercase and any other characters MUST be
rejected; no case normalization is performed. Reverse-DNS
ordering (for example "org.example.team") is RECOMMENDED but
not required. v1 defines no ownership, registration, or
dispute resolution: identical strings from different sources
MUST be treated as unrelated claims. Invariant identity is
(id, version, content digest) alone; a namespace string NEVER
proves identity, and tools MUST NOT present `publisher` as
verified identity.

**Normative.** Unknown fields without an `x-` prefix MUST be rejected.
Lifecycle or approval fields (`status`,
`approved`, `approval`, event references) MUST be rejected anywhere in
the document. `version` increments by exactly 1 per approved change;
any change to a digest-covered field REQUIRES a new version and fresh
approval. Unknown `verification_type` MUST refuse before execution;
unknown `invariant_type` MUST be preserved and MUST NOT refuse or
influence any verdict. Implementations MUST refuse documents
whose `spec_version` they do not support before further
processing.

AUTH-ADMIN-001 v1 (amended; content values from
`invariants/auth-admin-001.yaml`):

```json
{
  "spec_version": 1,
  "id": "AUTH-ADMIN-001",
  "version": 1,
  "title": "Administrative endpoints require administrator authorization",
  "requirement": "Every endpoint in the declared administrative scope must reject unauthenticated requests and deny access to authenticated users without the administrator role. An administrator may access endpoints permitted by the defined policy.",
  "scope": ["/admin/users", "/admin/settings"],
  "invariant_type": "security.access-control",
  "verification_type": "http-auth-probe/1",
  "parameters": {},
  "evidence_expectations": {"attempts": 3},
  "publisher": "attest-code"
}
```

**Test.** Content digest of the above (publisher excluded per
the coverage rule):
`686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8`
(reproduced by two independent implementations; vectors
frozen under spec/attest-spec/v1/vectors/). The canonical
bytes still include `publisher`; only the digest projection
excludes it. The v0 digest
`67c5a5451d9e149c5d84c28646588c441f60753b642dcc1c7909859e3fb7f103`
MUST NOT validate or approve this document.

## 4. Classification taxonomy rules

**Normative.** `invariant_type` is a namespaced, extensible
classification label: dot-separated segments of lowercase ASCII
letters, digits and hyphens (for example
`security.access-control`). Labels MUST match
^[a-z0-9-]+(\.[a-z0-9-]+)*$; malformed labels MUST be rejected
as schema-invalid. The taxonomy is NOT a closed enum;
conformance MUST NOT depend on membership in a fixed list.

**Normative.** Initial seed: `security.*` (with
`security.access-control` assigned to AUTH-ADMIN-001). New labels MAY
be introduced by any document author without a specification change.

**Normative.** Classification is non-authoritative: taxonomy
membership MUST NOT authorize verification, select verdicts, or
gate execution. Unknown labels MUST be preserved byte-for-byte,
covered by the digest, and carried into requests and attestations.

**Recommendation.** Registries SHOULD index by `invariant_type` for
discovery. Human interfaces SHOULD display it alongside the title.

**Test.** Changing `invariant_type` changes the digest; an unknown
label verifies identically to a known one given equal approval and
evidence.

## 5. Canonicalization profile and exact processing order

**Normative.** `attest-canonical-json` v1 is a constrained profile
compatible with RFC 8785 (JCS): for every input within its supported
domain it produces byte-identical output to JCS. The constraints are:
mandatory NFC normalization (JCS does not normalize), integer-only
numbers within ±(2^53−1) (JCS allows all JSON numbers with
ECMAScript semantics), and documented depth/size limits. It is NOT
unrestricted JCS; JCS conformance alone does not imply v1
conformance.

**Normative.** Processing order before any digest:

1. Strict UTF-8 decoding; reject undecodable bytes and BOMs.
2. YAML-to-JSON conversion where applicable: YAML 1.2 core schema,
   string-only mapping keys, anchors resolved, duplicate keys
   rejected, decimal integers converted by value (non-decimal
   spellings are strings under core schema and fail
   integer-field validation), floats rejected, folded scalars
   per YAML semantics.
3. Strict JSON parsing: reject duplicate keys, `NaN`/`Infinity`,
   trailing data, unescaped control characters, lone surrogates.
4. NFC-normalize every string, then reject post-normalization key
   collisions. Sorting operates on normalized keys.
5. Value-model validation (integers in range, no other numbers)
   and key sorting by UTF-16 code units, recursively.
6. Canonical serialization: minimal escaping (`"`, `\`,
   U+0000–U+001F with short escapes or lowercase `\u00xx`; `/`
   never escaped), no insignificant whitespace, UTF-8 output, no
   BOM, no trailing newline. The limits stated below MUST be
   enforced; exceeding any limit MUST deterministically refuse
   with the violated limit identified.
7. SHA-256 over the exact canonical bytes; lowercase hex digest.

**Normative.** Unicode version: implementations MUST apply
Unicode NFC normalization and MUST declare the Unicode version
of their normalizer in their conformance statement.
Declaration alone is insufficient evidence of conformance:
implementations MUST demonstrate conformance by reproducing
the normalization probe vectors byte-for-byte. An
implementation that cannot perform NFC normalization MUST NOT
compute or verify attest-canonical-json digests. An
implementation that cannot determine its normalizer's Unicode
version MUST declare "unknown"; conformance suites MUST flag
such declarations, and strict policy MAY refuse digests from
them. Digest mismatches arising from normalization
differences MUST fail closed as refusals; implementations MUST
NOT coerce, re-normalize, or negotiate digests. A Unicode
version update does NOT by itself require a new profile
version; a new profile version is REQUIRED if and only if this
specification changes its normalization requirements.
Implementations SHOULD re-run the conformance suite after any
Unicode upgrade.

**Normative.** Limits, identical across implementations with
no platform-specific defaults: source document bytes at most
1,048,576, measured on the original input bytes before
decoding; nesting depth at most 32, where the root value has
depth 0 and each nested container adds 1; string length at
most 65,536 Unicode scalar values per string, measured after
decoding and before normalization (UTF-16 implementations MUST
count scalar values, not code units); object and array entries
at most 4,096 per container, measured on the parsed value
model after YAML conversion; canonical output bytes at most
8,388,608, measured on serialized bytes before hashing. YAML
alias expansion MUST be bounded before materializing expanded
structures: implementations MUST enforce expansion bounds
during parsing and MUST refuse before fully materializing any
structure that would exceed these limits. Truncation and
partial processing are forbidden.

**Normative.** Acceptance sequence for any digest-bearing object:

1. Parse the source.
2. Validate the parsed value against the applicable
   `spec_version` schema.
3. Canonicalize the validated value.
4. Calculate the digest.

A canonical digest MUST NOT make a schema-invalid document
acceptable. Canonicalization is well-defined on values; acceptance
additionally requires schema validity. Unsupported
`spec_version` values MUST be refused at step 2, before
canonicalization.

**Normative.** Absent-versus-empty: an omitted optional field DIFFERS
from an explicitly supplied empty object, array or string. Validators
MUST NOT insert defaults before canonicalization unless this
specification explicitly requires that normalization (it currently
requires none). Presence is part of the digest. v1 defines no
implicit defaults: validators MUST NOT supply any value for an
omitted field. Any future default MUST state its exact
substituted value, apply identically before digest computation
in all implementations, and require a specification version
bump when it affects digest-covered content. Deprecated
constructions MUST NOT be emulated: future deprecations MUST
state reject-or-ignore handling per version and MUST NOT
silently map old semantics onto new ones. Compatibility
handling MUST NOT alter digest-covered content on read: no
trimming, case-folding, or reordering beyond canonicalization
itself.

## 6. Canonicalization vectors and conformance requirements

**Test.** Frozen vectors (each reproduced byte-for-byte by
independent Python and JavaScript implementations sharing no code,
published under spec/attest-spec/v1/vectors/):

- V1-updated: 8-field invariant-like document (unordered keys,
  whitespace) → canonical with sorted keys →
  `e8540259285d745709a18e5c358e43550ec303b18943f1569122320ab0b09778`.
- V2a/V2b: NFD (`caf\u0065\u0301` + astral G-clef) and NFC
  (`café` + G-clef) inputs → identical canonical bytes →
  `468205c7fc271187ff4ff8a99bf350a6f427f2f0ae5e3ea5f980b5c609c252ef`.
- V3: nested objects, order-preserving arrays, safe-range
  integers, astral key sorting before U+E000 (opposite of Python
  `sort_keys`; verified discriminator) →
  `91ed9b26589db26baed4b43321ab1382144f9b71923dbed19e1ec8ec6c0ea2ec`.
- V4a/V4b/V4c: `1.5`, `1e3`, `9007199254740992` → INVALID.
- V5a–V5d: duplicate keys, trailing data, invalid UTF-8,
  `NaN` → INVALID.
- V6: live v0 AUTH-ADMIN-001 payload → `67c5a545...f103`
  (ASCII-subset compatibility with the current implementation;
  MUST NOT approve the v1 document).
- V7a/V7b/V7c: `{"a":1}` → `015abd7f...`,
  `{"a":1,"b":{}}` → `3aec7def...`,
  `{"a":1,"b":""}` → `4cae71c1...` (absent differs from empty).

**Normative.** Cross-language conformance REQUIRES two independent
implementations in different programming languages, sharing no
canonicalization code, reproducing every published vector
byte-for-byte. One implementation's output is necessary but never
sufficient evidence of conformance.

**Normative.** Unicode-version declaration and stable-only
vectors: implementations MUST declare their normalizer's
Unicode version and demonstrate conformance on the probe
vectors (section 5); all normative vectors use
normalization-stable characters only. The V7 trio and
per-limit boundary tests (accept at exactly-limit, refuse at
limit-plus-one) are REQUIRED conformance obligations.

## 7. Approval event schema, hashing and chain validation

**Normative.** Approval history is a set of append-only,
content-addressed event files, one chain per (invariant id,
version). Each event carries: `seq` (integer, genesis `0`),
`prev` (predecessor `event_id`, `null` for genesis),
`invariant_id`, `invariant_version`, `invariant_digest` (exact
content digest the event binds to), `event_type` (`APPROVE`,
`REVOKE_APPROVAL` or `NOTE`), `approver` (display name),
`approver_id` (optional URI), `method` (how approval was granted),
`timestamp` (RFC 3339 UTC, informational only), optional `reason`
and optional `supersedes` (prior event id).

**Normative.** `method` MUST match
^[a-z0-9][a-z0-9.\-]{0,63}$; malformed values make the event
invalid and MUST fail closed. The v1 method registry contains
exactly `cli-review` (the implemented interactive CLI review
flow). Names beginning `x-` are reserved for private or
experimental methods and require no amendment. Any other
registered name requires a specification amendment. Unknown
well-formed methods MUST be preserved and MUST NOT affect
approval authority or refuse by default; policy MAY restrict
methods to an allowlist, in which case non-listed methods
refuse as policy refusals recorded distinctly from
chain-invalid refusals. Method identity MUST NOT be presented
as, or confused with, cryptographic proof of approver
identity.

**Normative.** `event_id` is the SHA-256 of the canonical event
payload (section 5) EXCLUDING the `event_id` field itself. Files
are named by `event_id`; existing files MUST NOT be overwritten.
Duplicates (same `event_id`) are idempotent.

**Normative.** Registry layout: each approval chain lives in
`registry/approvals/<invariant_id>/<version>/` as one file per
event named `<event_id>.json`, containing the complete event
object including its `event_id`, serialized as canonical JSON
(section 5) in UTF-8. Validation MUST remove `event_id`,
re-canonicalize, and require the recomputed hash to equal both
the embedded `event_id` and the filename stem. Discovery MUST
enumerate `<event_id>.json` files; ordering follows chain
linkage (`prev`/`seq`), never filenames or timestamps. Files
failing to parse, failing hash verification, or violating
chain rules make history ambiguous and MUST fail closed.
Non-event files (names not matching 64 lowercase hex plus
`.json`) MUST be ignored for chain evaluation and reported by
registry validation.

**Normative.** Chain validity: exactly one genesis event
(`seq = 0`, `prev = null`); every other event references an
existing predecessor with `seq - 1`; every event has at most one
successor; the checked-out chain has exactly one valid effective
tip. Missing predecessors, sequence gaps, inconsistent sequence
values, forks and competing tips make history ambiguous.
Ambiguous history MUST fail closed: refuse verification before
any verdict. Timestamps MUST NEVER determine event authority or
ordering; backdating and clock skew MUST NOT change the outcome.

**Normative.** An event binds ONLY to its exact
(`invariant_id`, `invariant_version`, `invariant_digest`) triple.
Effective approval is the fold of the single valid chain: the
last `APPROVE` whose digest matches the recomputed definition
digest, unless a later `REVOKE_APPROVAL` applies. `NOTE` events
are never authoritative. The digest MUST be recomputed from
definition bytes at both record time and read time. The
optional `supersedes` field is purely informational provenance
and MUST NOT affect chain validation, the effective-approval
fold, or replay.

**Recommendation.** Git review and repair procedure: concurrent
writers may fork history across branches; git preserves every
proposal. A merge MUST produce one unambiguous chain in the
checked-out tree (human-selected, human-reviewed); a merge commit
alone MUST NOT make conflicting branches valid. Losing branches
stay reachable in git history. **Assumption.** Git authorship is
an accountability aid, NOT cryptographic approval authenticity.

## 8. Approval/revocation lifecycle

**Normative.** Lifecycle states per invariant version:
`draft → active → deprecated → superseded`, with `revoked`
terminal from `active` or `deprecated`. Transitions are
append-only lifecycle events, separate files from invariant
content; a transition MUST NOT modify any version's bytes or
digest.

**Normative.** Lifecycle event contract: each version's
lifecycle history is a separate chain in
`registry/lifecycle/<invariant_id>/<version>/`, reusing the
section 7 file layout, hashing (canonical JSON excluding
`event_id`), discovery, ordering, and fail-closed rules with
lifecycle event types substituted. Each event carries `seq`,
`prev`, `event_id`, `invariant_id`, `invariant_version` (which
MUST match the enclosing directory; mismatch fails closed and
prevents chain transplanting), `event_type` (one of `ACTIVATE`,
`DEPRECATE`, `SUPERSEDE`, `REVOKE_INVARIANT`), `actor`
(display name, informational), `timestamp` (RFC 3339 UTC,
informational, never authority), optional `reason`, and
`successor_version` (integer, REQUIRED on `SUPERSEDE` and
MUST be absent on other event types).
Lifecycle events do not bind a content digest: eligibility
attaches to the (id, version) pair while content integrity is
enforced independently by the approval chain's digest binding.
A version with no lifecycle events is in `draft`. Valid
transitions: `draft→active` via `ACTIVATE`,
`active→deprecated` via `DEPRECATE`,
`active|deprecated→superseded` via `SUPERSEDE`,
`active|deprecated→revoked` via `REVOKE_INVARIANT`; any other
transition makes the chain invalid. Approval and lifecycle
chains MUST NOT be confused: separate directories, disjoint
event types, independent validation; a misplaced event makes
history ambiguous.

**Normative.** Eligibility: `draft` refuses (not eligible);
`active` verifies with effective approval; `deprecated` verifies
with a warning unless strict policy refuses; `superseded` SHOULD
refuse new verifications but MAY permit historical reproduction;
`revoked` MUST refuse, no verdict.

**Normative.** Two revocation concepts, never conflated:
`REVOKE_APPROVAL` (approval-history event: withdraws one
approval; the version MAY later be re-approved) and
`REVOKE_INVARIANT` (lifecycle event: the version is permanently
ineligible). Revocation is prospective only: it prevents new
runs, never rewrites history (section 12).

**Normative.** Joint evaluation: new and historical runs MUST
fold both the approval chain and the lifecycle chain at the
same registry state (current tip for new runs; the recorded
`registry_commit` for replay). Effective approval (section 7)
AND eligible lifecycle state (section 8) are both REQUIRED;
failure or ambiguity in either refuses the run before any
verdict. Lifecycle state MUST NOT be mistaken for approval:
`active` without effective approval refuses, and effective
approval on a `revoked` version refuses.

## 9. Verification request and exact verifier identity contract

**Normative.** The verification request carries: `invariant_id`,
`invariant_version`, `spec_version`, `expected_content_digest`,
`approval_ref` (effective event id), `repo` identity, `revision`
(full commit OID), `verifier_ref`, `execution_profile` (one of
`standard`, `contained`, `hardened`). Optional: `timeout`, `target_selector`, `client`, `policy`
(lifecycle strictness, digest requirements), `request_metadata`.

**Normative.** `execution_profile` MUST be exactly one of
`standard`, `contained`, `hardened` (the implemented profile
set). Unsupported values MUST refuse before execution. Future
profile values require a specification amendment; removing or
redefining an existing value requires a new specification
version.

**Normative.** `revision` MUST be a full-length lowercase
hexadecimal commit object id (40 hex for SHA-1, 64 hex for
SHA-256 repositories); short, uppercase, or non-hex values
MUST be rejected. Branch names and tags MUST NOT substitute
for `revision`. `repo` identifies the repository under test;
v1 leaves its exact format implementation-defined, but
implementations MUST document the format, MUST reject empty
values, and MUST treat `repo` as an opaque routing hint that
never weakens revision binding.

**Normative.** `verifier_ref` is request-only — it MUST NOT appear
in the invariant document — and pins an EXACT identity:
`type` (must equal the invariant's `verification_type`),
`implementation`, `version` (exact; ranges are NOT supported in
v1), and `artifact` state: either `available` with `algorithm`
plus digest value, or explicitly `unavailable` with a `reason`.
The digest field MUST NEVER be silently omitted. Policy MAY
require `available` and MUST refuse execution when it is
`unavailable` under such policy.

**Normative.** The verifier implementation MUST advertise
supported `spec_versions`; a mismatch MUST refuse before
execution, as MUST unknown `verification_type`, schema-failing
parameters, or any digest/approval/eligibility mismatch. Requests carrying
an unsupported `spec_version` MUST refuse before execution. The
normative type defines procedure and evidence; the implementation
MUST NOT define or weaken expectations (section 10).

## 10. Normative verification type and evidence expectations

**Normative.** `http-auth-probe/1` (transcribed from the
implemented demo checks, capabilities neither added nor removed):
per attempt, obtain the target's authoritative route inventory
(reference mechanism: registered routes under the `/admin`
prefix, sorted); REQUIRE exact equality of
`sorted(set(declared_scope))` with the inventory — any mismatch
yields attempt outcome infrastructure-failure with a failing
`scope-coverage` check, never a pass. For each declared endpoint
in sorted order: anonymous `GET` MUST return 401, non-admin
bearer `GET` MUST return 403, admin bearer `GET` MUST return 200.
Credentials are verifier configuration, not invariant content.
The parenthesized inventory mechanism is INFORMATIVE (it
describes the reference implementation); it MUST NOT
independently determine verdicts or weaken declared scope. The
normative rule is exact equality between declared scope and
the verifier's documented inventory; implementations MUST
document their inventory mechanism.

**Normative.** Evidence shape: check ids `scope-coverage`,
`unauthenticated-rejected`, `non-admin-denied`, `admin-allowed`;
one record per probe with target endpoint and
`"<context>: expected <E>, got <A>"` detail. All passed →
attempt pass; any probe failed → violation; inventory or
execution failure → infrastructure-failure. Coverage is
established only if every attempt holds a passing
`scope-coverage` record. Missing expected checks MUST NOT
produce `PASSED`.

**Normative.** `parameters` for this type MUST be `{}`; anything
else refuses. Expected status codes are fixed, not tunable. A
verifier MUST NOT narrow scope, skip endpoints, reinterpret
parameters, or convert violations to passes; unfaithful
conditions MUST refuse or yield infrastructure-failure. Demo
fixture names (`vulnerable`, `repaired`, …) are NOT normative.
Model output MAY propose content and MUST NEVER approve.

## 11. Attestation v3 execution-time context

**Normative.** Attestation v3 retains all v2 fields
(`schema_version`, `verdict`, `invariant_id`,
`invariant_version`, `content_digest`, `evidence_hashes`,
`statement`) and ADDS execution-time context: `spec_version`,
`approval_event_id` (effective at execution),
`registry_commit` (structured `{vcs, commit}` reference, see below),
`verification_type`, `verifier` (exact implementation, version,
artifact-digest state), `revision`, `execution_profile`, and
`lifecycle_state` observed at execution.

**Normative.** v3 records MUST carry `schema_version` 3. The
v3 digest covers the complete canonical v3 payload; no fields
are excluded. The `verifier` object MUST carry `implementation`
(string), `version` (exact string), and `artifact` state
exactly as specified for `verifier_ref` in section 9
(`available` with `algorithm` plus digest value, or explicitly
`unavailable` with a `reason`).

**Normative.** `registry_commit` is an object with required
`vcs` (string) and `commit` (string) fields and an optional
`ref` hint that MUST be ignored for resolution. In v1, `vcs`
MUST be "git". `commit` MUST be the full-length lowercase
hexadecimal object id (40 hex for SHA-1, 64 hex for SHA-256
repositories); short, uppercase, or non-hex values MUST be
rejected. Branch names, tags, or other mutable references MUST
NOT be accepted as `commit`. Parsers MUST preserve unknown
`vcs` values and MUST refuse historical replay requiring them;
new-run authorization MUST NOT depend on `registry_commit`.

**Recommendation.** Dual-read migration: parsers accept v2 and
v3; emitters write v3 after freeze; the v2 verify path is
retained indefinitely for historical evidence. No other
attestation redesign.

## 12. Historical verification semantics

**Normative.** Revocation is prospective: it prevents new runs
and MUST NOT retroactively invalidate historical attestations.
Current approval state MUST NEVER rewrite a historical verdict.

**Normative.** Historical verification replays execution-time
context: check out (or otherwise materialize) the registry at
the attestation's recorded `registry_commit`, recompute the
definition digest, fold the approval chain AS OF that commit,
and confirm the recorded `approval_event_id` was effective and
the lifecycle state eligible THEN. Integrity checks (attestation
digest, content binding, ordered evidence hashes) apply
unchanged. A later revocation is irrelevant to this procedure
by construction. If the referenced commit is unresolvable,
verification MUST report history-unavailable as a refusal with
no verdict, and MUST NOT fall back to current registry state. Lifecycle
history folds under the same as-of-commit rule; ambiguity in
either chain fails closed.

## 13. Migration and re-approval contract

**Normative.** The v0→v1 converter MUST require explicit
`--invariant-type`; no silent default or inferred classification.
Converted documents MUST reproduce YAML folded scalars exactly
(technique demonstrated by V6). Genesis `APPROVE` events preserve legacy
approver/timestamp/method verbatim with a `migrated: true`
marker, digests recomputed never copied.

**Normative.** The old approval digest `67c5a545...f103` MUST
NOT authorize the amended document. Fresh approval through the
normal review flow is MANDATORY, exactly once. Historical v2
attestations remain readable as historical records; old
documents MUST NOT be silently reinterpreted as v1.

**Recommendation.** Dual-read period for the YAML store path,
then deprecation of title-defaults-to-id and the bare-YAML
approval file.

## 14. Existing verdict and CLI compatibility contract

**Normative.** Unchanged: verdicts `PASSED`, `FAILED`,
`INCONCLUSIVE`; exit codes 0/1/2/3 (usage, approval, snapshot,
execution or refusal errors → 3); verdict authority in the
parent engine; three-attempt reproducibility policy;
infrastructure failures MUST NOT be misclassified as invariant
violations; refusal-before-verdict on any approval, digest,
eligibility, compatibility or integrity failure. Evidence
eligibility rules are unchanged.

## 15. Conformance acceptance matrix

**Test.** Every row MUST pass before freeze. (Rule = normative
section; Expected = required acceptance result.)

Canonicalization (§5–§6): V1-updated/V2/V3/V6/V7 digests
byte-identical in two languages; V4/V5 rejected with reasons;
NFC pair identical; astral order discriminator; YAML duplicate
keys, BOM, trailing data, bad UTF-8, depth-33 and >1 MiB
refused; schema-invalid-but-canonicalizable input refused at
acceptance; absent-vs-empty trio distinct.

Invariant semantics (§3–§4, §9–§10): `invariant_type` change
alters digest; unknown `invariant_type` verifies (no refusal,
no verdict effect); unknown `verification_type` refuses before
execution; `verifier_ref` in document refused; inexact or
mismatched verifier identity refuses; `unavailable` artifact
under strict policy refuses; missing `scope-coverage` cannot
yield `PASSED`; narrowed-scope verifier output yields refusal
or infrastructure-failure.

Approval chain (§7): valid genesis and append accepted;
duplicate event idempotent; missing predecessor, gap,
inconsistent `seq`, fork, competing tips, wrong digest
binding all refuse; backdated timestamps and clock skew do
not change the effective tip; every ambiguous history fails
closed with no verdict.

Revocation and history (§8, §11–§12): post-revocation new run
refuses; pre-revocation attestation still verifies against
its `registry_commit`; approval event id and lifecycle state
at execution preserved; current-state changes leave
historical verdicts untouched.

Migration (§13): converter without `--invariant-type` exits
non-zero; explicit classification byte-preserved; old digest
rejected against new document; verification without fresh
approval refused; v2 attestation still reads as history.

Compatibility (§14): verdict set, exit codes, authority and
evidence rules byte- and behavior-compatible with v0.

O1–O6 decision rows: declared Unicode versions recorded and
`unknown` flagged, stable-only vectors byte-identical in two
languages; `registry_commit` shape matrix and
history-unavailable path; method accept/reject/neutrality and
no-identity-proof inspection; no-default audit, `x-` coverage,
read-path preservation, deprecated-policy pair; five limit
boundary pairs plus alias-bomb and astral scalar-count tests;
publisher syntax matrix, digest invariance, unrelated-claims
handling, never-verified UI check.

F1–F3 remediation rows: `version: 0x1` rejected as
schema-invalid while decimal `version: 1` accepted; each of
`standard`, `contained`, `hardened` accepted with unknown
profiles refused pre-execution; chain directories discover
exactly the `<event_id>.json` set with hash-verified
filenames, stray files ignored-and-reported, malformed event
files refusing; lifecycle genesis/valid-transition/invalid-
transition matrix with transplanted chains refusing.

F4–F12 remediation rows: unknown non-`x-` fields refused
unconditionally; malformed `invariant_type` rejected while
unknown well-formed verifies; v3 emits `schema_version` 3
with full-payload digest verified by field mutation; short/
uppercase revisions and empty repos rejected; `supersedes`
presence ignored by folds; inventory mechanism documented
with the equality rule enforced; unsupported `spec_version`
refused at load, canonicalization and request; V2a
`caf\u0065\u0301` reproducing
468205c7fc271187ff4ff8a99bf350a6f427f2f0ae5e3ea5f980b5c609c252ef
in two languages; §13 wording inspection.

## 16. Security limitations and explicit non-goals

**Assumption.** Approver names, methods and timestamps are
unauthenticated strings; git history and review controls are
accountability aids, NOT cryptographic authenticity. Detached
signatures are a future extension, explicitly a non-goal
for v1.

**Assumption.** SHA-256 provides tamper-evidence against a
trusted digest, never authorship. NFC platform-version drift,
YAML-alias resource abuse (bounded by size limits), and the
accepted plant-and-revert residual inside one attempt carry
over. Floats are unsupported by design. No distributed
registry, database, network service, PKI, or implementation
registry in v1. Per the O1–O6 decisions: NFC drift is bounded
by declared versions, demonstrated probe conformance,
stable-only normative vectors, and fail-closed divergence;
alias expansion is bounded before materialization under the
O5 limits; method and publisher strings are explicitly
non-authenticating.

## 17. Freeze checklist

Specification freeze prerequisites (all must hold before freeze):

- [x] Owner approved sections 3–14 as normative, including F1–F12 corrections.
- [x] Section 18 items resolved (O1–O6 decided; see freeze-decisions doc).
- [x] `registry_commit` format and method vocabulary pinned.
- [x] Vectors V1-updated, V2–V7 published as machine-readable files with byte-exact inputs.
- [x] Document status flipped PROPOSED → FROZEN by owner act (this act is the freeze).

Post-freeze implementation acceptance (requires built
implementations; MUST NOT be marked complete from
specification text alone):

- [ ] Published vectors reproduced by two independent implementations.
- [ ] Registry and lifecycle implementation tests pass.
- [ ] Conformance matrix (section 15) fully green against implementations.

Freeze record: attest-spec v1 frozen 2026-10-31 under explicit
project-owner authorization. Original normative content digest
(SHA-256, historical):
`67bb4435a3ef1d298ca4c2e7ca57e8b43c0ed024368fc256581059e4a333825c`,
computed over the file bytes from the `## 3.` heading line
through the line before the `## 15.` heading line, LF endings
as stored. Vector publication:
spec/attest-spec/v1/vectors/ (`manifest.json`, `README.md`,
46 fixtures). Post-freeze implementation acceptance above
remains pending.

Amendment record 2026-10-31 (publisher/metadata digest
exclusion, owner-authorized): the §3 AUTH-ADMIN-001 content
digest and dependent chain-fixture bindings were corrected
from the publisher-inclusive value `219bf343...` to the
normative publisher-excluded projection `686892e3...`
(full: `686892e3f409735c7538e315f29727f3d3e2e2860df7eb979d8cc17bf5fdabf8`).
No normative rule changed; test artifacts were brought into
conformance with the standing exclusion rule. Amended
normative digest (SHA-256 over §§3–14 as defined above):
`acfa46ae1934872ae146d62c434ed4b56d65c7e72bf0898e86931b01c880f7f1`.
The amended artifact is NOT byte-identical to the original
freeze. Specification version remains v1: no rule change
occurred, only artifact correction under the authorized
amendment procedure.

## 18. Outstanding decisions, if any

All O1–O6 are DECIDED per owner approval; normative text is
incorporated above. Details in
`docs/attest-spec-v1-freeze-decisions.md`.

**Decided O1.** Platform NFC with declared, demonstrated
Unicode version (§2 of decisions; normative §5–§6).

**Decided O2.** Structured `{vcs, commit}` registry reference
(§3 of decisions; normative §11–§12).

**Decided O3.** Controlled method registry, `cli-review`
initial, `x-` extension (§4 of decisions; normative §7).

**Decided O4.** Zero implicit defaults; §8 deprecated default
confirmed (§5 of decisions; normative §3, §5, §8, §13).

**Decided O5.** Five fixed limits with fixed measurement
points (§6 of decisions; normative §5–§6).

**Decided O6.** Strict publisher syntax, no ownership, no
authentication (§7 of decisions; normative §3).
