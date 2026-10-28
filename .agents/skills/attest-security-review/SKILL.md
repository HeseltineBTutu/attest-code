---
name: attest-security-review
description: Conduct an independent, evidence-based security review of the Attest Code repository and report ranked findings with a single APPROVE, CHANGES REQUIRED, or INCONCLUSIVE conclusion.
---

# Attest Security Review

Use when the user asks for a security review, pre-commit review, or audit of
Attest Code — a change, a branch, or the working tree. This skill is for
review, not remediation: report findings and stop.

## 1. Establish scope (read-only)

Record branch, HEAD, `git status --short`, and the diff under review
(`git diff --stat` plus untracked security-relevant files). Default scope is
the working tree against HEAD; use a user-supplied commit range or path list
when given. State the scope and any out-of-scope areas in the report.

## 2. Ground every claim in the repository

Read the governing documents before judging any change:

- `docs/security-model.md` — trust boundaries, approval design, F1–F7
  controls, S1/S2 worker policy, and explicitly accepted residuals.
- `docs/architecture.md` — module boundaries, data flow, model boundary.
- `docs/hackathon-scope.md` — implemented vs planned work.

Then trace each reviewed claim through the actual implementation and its
tests. Derive guarantees from code, not from prose: if the documentation
claims a property the code does not establish, that is a finding. Never
invent guarantees the repository does not make.

Fixed reference points (verify against current code; do not restate blindly):

- Verdicts (`attest_core/verdicts.py`): FAILED requires three reproducible
  violations under the same revision and configuration, each with evidence;
  PASSED requires three clean passes with evidence; anything else —
  timeouts, crashes, missing evidence, mixed results, infrastructure
  failures — is INCONCLUSIVE. Infrastructure failures never yield FAILED.
- Authority: the parent verification engine classifies; workers report,
  never verdict. Model output (`integrations/meta_models`) is untrusted
  input: it never verdicts, writes the repo, or touches the registry.
- Approval: a YAML `approved` key is ignored; only an `ApprovalRecord`
  binding id, version, and content digest confers authority. Missing or
  stale approval refuses verification instead of verdicting.
- Execution integrity: F7 snapshot built from Git objects (never the live
  tree), manifest re-verified at every attempt boundary; F1 parent/worker
  origin binding; F2 environment/startup validation; before/after
  fingerprints. A change planted and reverted strictly inside one attempt
  is invisible by construction — an accepted residual, not a defect.
- Worker boundary: S1 exposure reduction (minimal env, controlled cwd,
  versioned JSON protocol, size bounds) plus S2 supervision (verified
  process group, SIGTERM→grace→SIGKILL, reap, verified-empty tree before
  accepting any result). Accepted residuals include: no OS-enforced
  isolation, Windows single-process supervision only, session-detached
  descendants escape by design, and post-reap numeric-PGID reuse is a
  same-UID availability risk with fail-closed verdict handling.

## 3. What to examine

Inspect security-sensitive control flow, trust boundaries, error handling,
and failure paths. For each, ask what an adversary controls and whether
uncertainty fails closed to INCONCLUSIVE or an integrity refusal:

- Approval and registry paths: forgery, staleness, digest binding.
- Verdict derivation: anything that could produce PASSED or FAILED without
  the required reproducibility conditions.
- Snapshot, origin, runtime, and fingerprint checks: bypasses, races,
  fallback paths that skip validation.
- Worker supervision and result ingestion: malformed/oversized output,
  missing files, tampered handshakes, symlinks/FIFOs/devices, exception
  and cancellation paths, reuse races.
- New dependencies, subprocess/file-system interaction, and thread or
  process-global state.
- Missing tests where the gap materially affects assurance of a control.

Distinguish: confirmed defect (demonstrated code path, ideally with a
failing behavior), plausible risk (credible but unverified), missing test,
and accepted documented residual (cite the security-model passage).

## 4. Run checks only when safe

Prefer reading. Run focused `pytest` files for touched areas, plus
`ruff check`, `ruff format --check`, and `mypy src tests` (via
`uv run …` or the project venv) when feasible. Run the full suite only
when proportionate — it takes minutes and spawns real processes. If a
check could mutate tracked files or external state, assess that risk
first and omit it or ask for approval. Report only results actually
observed; name every check that was blocked, skipped, or not run, with
the reason. Never claim a test passed without executing it.

## 5. Read-only policy

The reviewer must not edit, create, delete, or format files; stage,
commit, push, reset, stash, or otherwise mutate Git state; automatically
fix findings; weaken tests; or modify implementation behavior. If
remediation is necessary, report the finding and wait for explicit
authorization in a separate implementation task.

## 6. Report format

1. Branch, HEAD, working-tree state, and review scope.
2. Files and security-sensitive paths inspected.
3. Findings ranked Critical, High, Medium, or Low, each with file:line
   evidence and impact. Critical means verdict/approval compromise or
   silent wrong-verdict paths; rank the rest by exploitability and blast
   radius.
4. Missing tests and residual risks, classified separately from defects.
5. Tests and static checks actually run, with observed outcomes.
6. Limitations and unverified assumptions.
7. One conclusion — APPROVE, CHANGES REQUIRED, or INCONCLUSIVE — with
   justification. APPROVE means no blocking findings were identified
   within the stated scope and assumptions, not that the system is
   perfectly secure.
