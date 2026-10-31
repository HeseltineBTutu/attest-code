# attest-spec v1 — Freeze Decisions O1–O6

Status: **PROPOSED**. Companion to `docs/attest-spec-v1.md`
(sections cited as §N). Resolves the six outstanding decisions with
exact normative wording. It does not edit the main specification;
amendments in section 8 apply only after explicit project-owner
approval. No settled architectural decision is reopened.

## 1. Decision summary

- O1 Unicode version: platform NFC with declared version, safe-direction
  failure, stability-scoped conformance. No pinned tables, no new fields.
- O2 `registry_commit`: structured VCS-qualified object
  `{vcs, commit}`, git-only in v1, full lowercase hex, explicit
  history-unavailable refusal when unresolvable.
- O3 Method vocabulary: controlled registry with `x-` extension;
  initial method `cli-review` only; method never affects authority.
- O4 Defaults and deprecation: zero implicit defaults in v1;
  absent-vs-empty preserved; `x-` fields digest-covered when present;
  compatibility reads MUST NOT rewrite covered content; §8
  deprecated-eligibility default confirmed.
- O5 Limits: 1 MiB source, depth 32, 65,536 scalars per string,
  4,096 entries per container, 8 MiB canonical output; fixed
  measurement points; deterministic refusal.
- O6 Publisher: lowercase dotted syntax (reverse-DNS recommended),
  no ownership, no authentication, no semantic effect.

## 2. O1 — Unicode normalization version

Question: pin normalization tables or rely on platform NFC?

**PROPOSED DECISION.** Platform NFC with a declared Unicode
version, conformance-scoped to normalization-stable characters,
and fail-closed divergence. No pinned tables, no new
specification fields.

**NORMATIVE WORDING.**

```text
Implementations MUST apply Unicode NFC normalization during
canonicalization. Each implementation MUST declare the Unicode
version of its normalizer in its conformance statement, and
SHOULD expose it at runtime where the platform permits. An
implementation that cannot perform NFC normalization MUST NOT
compute or verify attest-canonical-json digests. An
implementation that cannot determine its normalizer's Unicode
version MUST declare "unknown"; conformance suites MUST flag
such declarations, and strict policy MAY refuse digests from
them. Digest mismatches arising from normalization differences
MUST fail closed as refusals; implementations MUST NOT coerce,
re-normalize, or negotiate digests. A Unicode version update
does NOT by itself require a new canonicalization profile
version; a new profile version is REQUIRED if and only if this
specification changes its normalization requirements.
Implementations SHOULD re-run the conformance suite after any
Unicode upgrade.
```

**RATIONALE.** Pinning exact tables was rejected: mainstream
platforms (CPython `unicodedata`, Node ICU, Rust and Go crates)
track different Unicode releases on independent schedules, and
forcing one vintage would block conforming implementations
without testable benefit — the observed Python/JavaScript
agreement on vector V2 demonstrates pipeline equivalence on
stable characters but is not claimed as general table
equivalence. The safe direction (mismatch → refusal) makes
residual drift a liveness cost, never a soundness hole.
Historical documents composed of normalization-stable
characters (including all ASCII) canonicalize identically
across versions; version-sensitive characters are vanishingly
rare in invariant text.

**COMPATIBILITY IMPACT.** None on frozen vectors or digests.
Future Unicode upgrades need no re-approval and no profile
bump unless normalization requirements change.

**CONFORMANCE REQUIREMENTS.** Suite MUST record each
implementation's declared Unicode version and flag `unknown`.
All normative vectors use normalization-stable characters
only and MUST reproduce byte-identically. A supplementary
informational probe set MAY exercise edge characters; results
are recorded, not gated.

## 3. O2 — `registry_commit` format

Question: git-specific, VCS-agnostic, or structured reference?

**PROPOSED DECISION.** Structured VCS-qualified object,
git-only in v1, with explicit unresolvable-history behavior.

**NORMATIVE WORDING.**

```text
`registry_commit` is an object with required `vcs` (string)
and `commit` (string) fields, and an optional non-authoritative
`ref` (string) hint that MUST be ignored for resolution. In v1,
`vcs` MUST be "git". `commit` MUST be the full-length lowercase
hexadecimal object id (40 hex for SHA-1 repositories, 64 for
SHA-256 repositories); short, uppercase, or non-hex values MUST
be rejected. Branch names, tags, or any other mutable reference
MUST NOT be accepted as `commit`, alone or otherwise.
Historical verification MUST materialize the registry at the
referenced commit; if the commit is unresolvable, verification
MUST report history-unavailable as a refusal with no verdict,
and MUST NOT fall back to current registry state. Parsers MUST
preserve unknown `vcs` values and MUST refuse historical replay
requiring them; new-run authorization MUST NOT depend on
`registry_commit`.
```

**RATIONALE.** A bare git SHA was rejected as non-extensible;
a fully VCS-agnostic string was rejected as unvalidatable.
The structured object validates strictly today and admits new
`vcs` values by later amendment. Lowercase-only avoids silent
normalization. Distinct `history-unavailable` (refusal, no
verdict) prevents misreading missing history as a negative
result.

**COMPATIBILITY IMPACT.** Additive to attestation v3 (field
shape pinned before any v3 emitter exists). v2 attestations
unaffected. Future VCS support needs no v3 redesign.

**CONFORMANCE REQUIREMENTS.** Accept full 40/64-hex git refs;
reject short/uppercase/non-hex/branch-name commits; ignore
`ref` during resolution; unknown `vcs` refuses replay but
preserves bytes; unresolvable commit yields history-unavailable
with no verdict and no current-state fallback.

## 4. O3 — Approval method vocabulary

Question: open strings, closed enum, or controlled registry?

**PROPOSED DECISION.** Controlled registry with `x-` extension.
Initial registry holds `cli-review` only. Method is metadata
and never affects authority.

**NORMATIVE WORDING.**

```text
Approval-event `method` MUST match ^[a-z0-9][a-z0-9.\-]{0,63}$;
malformed values make the event invalid and MUST fail closed.
The v1 method registry contains exactly `cli-review` (the
implemented interactive CLI review flow). Names beginning `x-`
are reserved for private or experimental methods and require
no amendment. Any other registered name requires a
specification amendment. Unknown well-formed methods MUST be
preserved and MUST NOT affect approval authority or refuse by
default; policy MAY restrict methods to an allowlist, in which
case non-listed methods refuse as policy refusals recorded
distinctly from chain-invalid refusals. Method identity MUST
NOT be presented as, or confused with, cryptographic proof of
approver identity.
```

**RATIONALE.** Unrestricted strings were rejected (no
interoperability story); a closed enum was rejected (blocks
future review surfaces without cause). The live engine's
hardcoded `cli-review` (`src/apps/review.py`) becomes the
sole initial value, so v0 genesis events preserve it
verbatim. Authority flows only from chain validity, digest
binding and eligibility — a forged or novel method string
can neither grant nor (by default) deny approval.

**COMPATIBILITY IMPACT.** None on existing records: the only
in-tree method value already conforms. Future methods are
additive.

**CONFORMANCE REQUIREMENTS.** Accept `cli-review` and
well-formed `x-` names; reject malformed strings with chain
failure; unknown method verifies identically to known given
equal chain/digest state; allowlist policy refuses distinctly;
no UI or log may label method as identity proof (documentation
inspection).

## 5. O4 — Defaults, deprecation and legacy behavior

Question (task framing): how do defaults, deprecated fields and
legacy behavior work under "no silent default may change meaning"?

**PROPOSED DECISION.** Zero implicit defaults in v1; explicit
values distinguished from omission; deprecated v0 behaviors
rejected, never emulated; `x-` presence digest-covered;
compatibility reads never rewrite covered content. The §8
deprecated-version eligibility default (warn-and-allow, strict
opt-in) is CONFIRMED unchanged.

**NORMATIVE WORDING.**

```text
v1 defines no implicit defaults: validators MUST NOT supply
any value for an omitted field. An omitted optional field is
absent from canonical bytes; an explicitly supplied empty
object, array or string serializes as such; the two MUST
produce different digests. Any future default MUST state its
exact substituted value, apply identically before digest
computation in all implementations, and require a specification
version bump when it affects digest-covered content. Deprecated
constructions MUST NOT be emulated: `approved`, `approval` and
`status` keys are rejected; a missing `title` is rejected (the
v0 default-to-id behavior is NOT carried forward); future
deprecations MUST state reject-or-ignore handling per version
and MUST NOT silently map old semantics onto new ones.
Compatibility handling MUST NOT alter digest-covered content on
read: no trimming, case-folding, or reordering beyond
canonicalization itself. `x-` prefixed fields, when present,
are digest-covered like any present field; MAY-ignore-semantics
does not exclude them from canonical bytes.
```

**RATIONALE.** Silent defaults are the exact mechanism by which
meaning drifts across implementations; banning them removes a
whole class of divergence. The `x-` clarification closes the
one gap in §3 (allowed-but-coverage-ambiguous). Confirming §8
as written keeps deprecated-version handling stable:
warn-and-allow preserves historical workflows while strict
policy serves high-assurance contexts.

**COMPATIBILITY IMPACT.** None: restates §3/§5/§8/§13 with one
explicit clarification (`x-` coverage). No digest changes.

**CONFORMANCE REQUIREMENTS.** Omitted-vs-empty digest trio
distinct (V7); no-default audit over every optional field;
`approved`/`status` keys and missing `title` rejected;
converter infers nothing semantic; `x-` presence changes the
digest; read-path byte-preservation test on covered fields;
deprecated version warns by default and refuses under strict
policy.

## 6. O5 — Canonicalization depth and size limits

Question: concrete identical-across-implementations limits?

**PROPOSED DECISION.** Five fixed limits with fixed measurement
points and deterministic refusal. Section 5's provisional
numbers (32, 1 MiB) are CONFIRMED and completed.

**NORMATIVE WORDING.**

```text
Conforming implementations MUST enforce exactly these limits,
with no platform-specific defaults: source document bytes at
most 1,048,576, measured on the original input bytes before
decoding; nesting depth at most 32, where the root value has
depth 0 and each nested container adds 1; string length at
most 65,536 Unicode scalar values per string, measured after
decoding and before normalization (UTF-16 implementations MUST
count scalar values, not code units); object and array entries
at most 4,096 per container, measured on the parsed value
model after YAML conversion; canonical output bytes at most
8,388,608, measured on serialized bytes before hashing. YAML
alias expansion MUST respect the structural limits during
conversion. Exceeding any limit MUST deterministically refuse
with the violated limit identified; truncation and partial
processing are forbidden.
```

**RATIONALE.** Realistic invariant documents are kilobytes
(AUTH-ADMIN-001 is ~1 KB); every limit sits orders of magnitude
above legitimate use while bounding per-document memory near
9 MiB worst case (1 MiB source plus 8 MiB output headroom for
the 6× worst-case control-character escape expansion), which
is the DoS argument. Scalar (not code-unit) string counting
is the only UTF-16-portable choice. Measuring structure after
YAML conversion closes alias-bomb gaps that a bytes-only limit
would miss. One open question was output headroom sizing;
8 MiB covers the proven 6× worst case plus structure with
margin, and any document near it is adversarial by definition.

**COMPATIBILITY IMPACT.** None on legitimate documents or
frozen vectors (all far below limits). Over-strict v0 code
paths, if any, would need alignment at implementation time.

**CONFORMANCE REQUIREMENTS.** Boundary tests at exactly-limit
(accept) and limit-plus-one (refuse) for each of the five
limits; a YAML alias-expansion bomb refused during
conversion; scalar-count test with astral characters (UTF-16
implementations must not undercount); refusal reasons name
the violated limit.

## 7. O6 — Publisher format and collision rules

Question: syntax, normalization, ownership, and authority of
`publisher`?

**PROPOSED DECISION.** Strict lowercase dotted syntax,
reverse-DNS recommended, no ownership, no authentication, no
semantic effect. `publisher` stays optional and non-covered.

**NORMATIVE WORDING.**

```text
`publisher`, when present, MUST be 1 to 8 dot-separated
segments, each matching [a-z0-9]([a-z0-9-]*[a-z0-9])?, with
total length 1 to 128 characters. Uppercase and any other
characters MUST be rejected; no case normalization is
performed. Reverse-DNS ordering (for example
"org.example.team") is RECOMMENDED but not required. v1
defines no ownership, registration, or dispute resolution:
identical strings from different sources MUST be treated as
unrelated claims, and registries MAY enforce local uniqueness
as local policy only. A missing `publisher` stays absent with
no default and no effect. Invariant identity is (id, version,
content digest) alone; publisher verification or
authentication is possible only through external mechanisms
(hosting context or future signatures), and a namespace string
NEVER proves identity. Tools MUST NOT present `publisher` as
verified identity. Publisher metadata MUST NOT affect the
digest, approval validity, eligibility, or any verdict.
```

**RATIONALE.** A permissive free-text publisher was rejected
(homoglyph and collision chaos with no upside); a mandatory
registry was rejected (unneeded infrastructure, contradicts
the minimal-registry decision). Strict syntax plus explicit
non-ownership gives registries something indexable without
promising anything unenforceable. Case rejection (rather than
folding) follows the no-silent-rewrite principle.

**COMPATIBILITY IMPACT.** None: the in-tree example value
`attest-code` conforms; non-covered status unchanged, so no
digest effects.

**CONFORMANCE REQUIREMENTS.** Accept conforming values
including `attest-code`; reject uppercase, empty segments,
leading/trailing dots or hyphens, overlong values, and
9-segment values; identical digests with publisher added,
removed, or changed; missing publisher verifies normally;
two same-publisher documents from different sources treated
as unrelated (no cross-authority); UI-review check that
publisher is never labeled verified.

## 8. Consolidated proposed amendments to `docs/attest-spec-v1.md`

Cross-section check: no settled decision is contradicted; no
new fields or mechanisms beyond O1–O6 (the O2 `ref` hint and
O6 syntax rules are the decisions themselves). Affected
sections per decision: O1 → §5, §6, §15, §16, §18; O2 → §11,
§12, §15, §17, §18; O3 → §7, §15, §16, §17, §18; O4 → §3, §5,
§8, §13, §15, §18; O5 → §5, §6, §15, §16, §18; O6 → §3, §15,
§16, §18. Verification request (§9), verifier identity (§9),
verdict contract (§14) and migration digests (§13) are
untouched. Apply after owner approval, in order:

A1. §5, after the processing-order list: insert the O1
normative paragraph (declared Unicode version, unknown-version
handling, no-coercion, profile-version rule).
A2. §5 step 6: replace the provisional limits sentence with
the O5 normative paragraph (five limits, measurement points,
alias expansion, deterministic refusal).
A3. §5 absent-vs-empty paragraph: append the O4 sentences
(zero implicit defaults; future-default versioning rule).
A4. §3 non-covered paragraph: append the O4 `x-` coverage
sentence and a pointer to the O6 publisher syntax (new
§3 paragraph with the O6 normative wording).
A5. §6: append the Unicode-version declaration and stable-only
vector rule from O1; record V7 and boundary-test obligations.
A6. §7 event schema: constrain `method` with the O3 normative
wording (syntax, `cli-review` registry, `x-` extension,
authority neutrality).
A7. §8: no text change (deprecated default confirmed); close
the original O4 in §18 with a pointer here.
A8. §11: replace the bare `registry_commit` mention with the
O2 representation, validation and immutability rules.
A9. §12: add the O2 history-unavailable refusal rule (no
verdict, no current-state fallback).
A10. §15: add one matrix row per decision, quoting sections
2–7 conformance requirements above.
A11. §16: refine residuals — NFC drift bounded by declared
versions and stable-only vectors; alias bombs bounded by O5;
method/publisher explicitly non-authenticating.
A12. §17: mark the `registry_commit`/method checklist item
satisfied upon A6/A8; §18: close O1–O6 with pointers here.

## 9. Remaining risks and unresolved questions

R1. NFC table drift between Unicode versions remains a
liveness risk for documents containing version-sensitive
characters; mitigated by declared versions, stable-only
normative vectors, and fail-closed divergence. No further
action available without pinning tables (rejected in O1).
R2. Historical replay depends on registry-commit availability;
shallow clones or garbage-collected histories yield
history-unavailable, which operators must distinguish from
invalidity. Registry retention policy is future work.
R3. Method-allowlist and digest-required policies are evaluable
but their configuration surface belongs to a future
SDK/policy document, not v1.
R4. Publisher squatting and homoglyph-adjacent confusion
within the allowed syntax are accepted; v1 promises no
ownership.
R5. No new normative questions were found; O1–O6 as framed
are fully answered. Any item above needing an owner call is
R2's retention policy (recommendation: defer past freeze).

## 10. Final freeze-readiness recommendation

**READY FOR OWNER APPROVAL.** All six decisions carry
specific actionable wording, deterministic behavior,
compatibility analysis, and conformance tests; acceptance
criteria are met; no settled decision is contradicted; and
remaining uncertainty (R1–R5) is explicit. The main
specification is NOT yet amended and v1 is NOT frozen:
apply section 8 only after the project owner explicitly
approves this document.
