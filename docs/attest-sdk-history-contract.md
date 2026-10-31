# Attest SDK — Historical Materializer and Replay Contract

Companion to `src/attest_sdk/history.py`. This document records the trust
contract for v3 historical verification. It does not change the frozen
Attest Spec v1 and introduces no new verification semantics.

## 1. Materializer trust contract (audit C1)

`verify_historical` replays approval and lifecycle folds over a registry
state supplied by a caller-provided `materialize` callable. The SDK
passes the exact recorded `RegistryCommit` and folds whatever directory
is returned. Consequences:

- The materializer is a **trusted, verifier-controlled** component.
- It MUST NEVER be supplied or controlled by the attestation presenter.
  A presenter-controlled materializer can fabricate a registry snapshot
  in which any attestation replays as valid.
- It receives the exact recorded `(vcs, commit)` identity.
- It MUST resolve the immutable commit, never a mutable branch or tag.
- The attestation's `ref` is an informational human hint and MUST NOT
  determine resolution.
- It MUST return registry state corresponding exactly to the requested
  commit.
- It MUST return a stable snapshot for the complete replay operation.
- Approval and lifecycle folds MUST operate over the same immutable
  materialized snapshot.
- The SDK performs exactly one `materialize` call per replay and does
  not consult any other directory; there is no current-state fallback.
- The SDK does not independently establish Git provenance and cannot
  prove materializer honesty. Git execution stays outside the SDK.
- A dishonest, mutable, or incorrectly implemented materializer
  invalidates the historical trust guarantee. Documenting this
  contract does not make an untrusted materializer safe.

## 2. Snapshot-read analysis

The replay implementation reads the materialized directory twice per
operation: once to fold the approval chain
(`Registry.effective_approval`) and once to fold the lifecycle chain
(`Registry.lifecycle_state`). No narrowly scoped code change removes
this without altering public `Registry` APIs or copying the tree into
a temporary snapshot (which adds failure modes and its own
time-of-check race during the copy, without establishing provenance).
The stable-snapshot obligation therefore stays on the materializer:
return an immutable snapshot (for example a private `git archive`
extraction or read-only worktree) that cannot change mid-replay.

## 3. Deprecated replay policy (audit L2)

Deprecated historical replay is permitted with a `("deprecated",)`
warning. This is a permissive historical replay policy, and it is
forced: the v3 execution-time context (§11) does not encode the
policy setting in effect at issuance, so historical verification
cannot reconstruct whether strict deprecated-invariant policy was
enabled then. Strictness remains a new-run policy decision. No new
policy field is added; the frozen v1 payload is unchanged.

## 4. Evidence opt-out (audit L3)

`evidence=None` in `verify_v3` and `verify_historical` skips ordered
evidence-record binding only. Structure, digest, invariant bindings,
and (for replay) registry-commit folding still apply unchanged.
Callers requiring evidence-record verification MUST supply the
evidence records. This preserves v2 parity, where supplied evidence
is likewise optional.
