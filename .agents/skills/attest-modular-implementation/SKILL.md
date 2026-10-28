---
name: attest-modular-implementation
description: Guide small, testable implementation milestones in Attest Code with bounded scope, 200-line modular files, preserved verdict integrity, and validated reports.
---

# Attest Modular Implementation

Use when the user asks to implement a feature, fix, or milestone in Attest
Code. This skill is for implementation; independent security review belongs
to `attest-security-review`, ideally in a fresh session.

## 1. Define a bounded change

Before editing, record the branch, HEAD, and working-tree status
(`git status --short`), and inspect the relevant implementation and tests.
Propose the smallest cohesive change that satisfies the requirement: list
expected files, interfaces, behavior changes, regression risks, and
acceptance criteria. Make changes only within the agreed scope. Stop and
ask before expanding scope when unrelated architectural work becomes
necessary.

## 2. Enforce modular architecture

- Every Python file must contain no more than 200 physical lines,
  counting blank lines and comments. Check the limit before finishing,
  not just at the start (`wc -l` every file created or substantively
  changed).
- Split code by cohesive responsibility and stable interfaces, never by
  arbitrary line ranges. Avoid circular imports, duplicated logic,
  oversized modules, and cross-module private imports.
- Do not split files merely to satisfy the line limit if doing so
  creates artificial abstractions; design proper cohesive modules.
- Never resolve a line-limit violation by deleting tests,
  documentation, necessary comments, or functionality.
- Do not refactor unrelated pre-existing oversized files unless the
  task explicitly includes them. Do not add substantive changes to
  such files without explaining why they are necessary.

## 3. Preserve security and verdict integrity

Derive current requirements from the implementation, tests, and
`docs/security-model.md` — never invent guarantees the code does not
establish, and never claim isolation, authenticity, tamper resistance,
or security properties the code does not provide:

- The parent verification engine retains authority over final verdicts;
  workers report and models advise, but neither verdicts.
- Preserve PASSED, FAILED, and INCONCLUSIVE semantics, including the
  reproducibility policy FAILED requires (three violations under the
  same revision and configuration, each with evidence).
- Treat crashes, timeouts, malformed or incomplete evidence, snapshot
  drift, and infrastructure failures per existing fail-closed behavior.
- Preserve F1–F7 and S0/S1/S2 protections and explicitly documented
  residual limitations.
- Do not weaken tests, schemas, validation, or security controls to
  make a change pass.

## 4. Implement and validate

- Add or update focused tests for changed behavior, including relevant
  failure and adversarial paths.
- Run the appropriate focused regression tests, and the full suite when
  feasible. Run Ruff lint, Ruff format check, strict mypy, and
  `git diff --check` using the repository's actual configured commands
  (`uv run …` or the project venv).
- Inspect the final diff for unintended changes, accidental secrets,
  generated artifacts, and weakened assertions.
- Report checks as passed only when they were actually run and their
  results observed. Identify blocked or unrun checks honestly.

## 5. Git and approval boundary

Never stage, commit, or push unless the user explicitly authorizes the
specific action. Do not reset, stash, or discard user changes. Never
claim the working tree is clean if unrelated or pre-existing changes
remain.

## 6. Implementation report

1. Original branch, HEAD, and working-tree status.
2. Agreed scope and acceptance criteria.
3. Files created, modified, and removed.
4. Physical line counts for every Python file created or substantively
   changed.
5. Tests and static checks actually run, with observed results.
6. Security implications and remaining limitations.
7. Diff summary and any unrelated changes preserved.
8. Explicit confirmation that nothing was staged, committed, or pushed.

Stop after the report and wait for explicit approval.
