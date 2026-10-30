# Testing Standards

## Test tree

`tests/` mirrors the source hierarchy for unit tests. Cross-cutting
tests live in explicitly named directories instead of being forced
into a single module mirror:

- `tests/test_src/test_attest_core/` — one module per `attest_core`
  unit (plus `supervision_harness.py`, used only there).
- `tests/test_src/test_apps/` — `apps` units.
- `tests/test_src/test_integrations/` — `integrations` units; a
  subpackage covered by one module keeps the subpackage name
  (`test_meta_models.py`), split into a subdirectory if subdivided.
- `tests/test_cli/` — subprocess CLI end-to-end runs (staged trees).
- `tests/test_integration/` — in-process cross-package runs.
- `tests/` root — `conftest.py` (shared fixtures), `line_limit.py`
  (200-line checker), `test_line_limit.py` and `test_docs.py`
  (quality gates collected by the normal suite).

No `__init__.py` under `tests/` (rootdir import mode; keep basenames
unique). No directories for packages without tests (`attest_spec`,
`examples`). New unit tests go to the mirror; new cross-package
tests go to `test_cli/` or `test_integration/`. The M1 containment
battery lives in `tests/test_src/test_attest_core/test_contain.py`,
the M2 lifecycle battery in `test_pidns.py`, and the
bootstrap/import-boundary battery in `test_bootstrap.py`; all run
checks via `run_bounded(..., contained=True)` (or invoke the real
launcher bootstrap directly), and tests needing namespaces skip
explicitly where `supports_containment()` is false. The M3-A quota
batteries live in `test_scopes.py` (scope mechanics plus live
throttle/OOM/tasks counters), `test_quotas.py` (fail-closed
lifecycle), and `test_quota_live.py` (end-to-end enforcement via
`run_bounded(..., contained=True, quotas=True)`); tests needing
scopes skip explicitly where `supports_quotas()` is false, and
`scope_helpers.py` holds the shared skip marker plus the
scope-ready poll (a scope is not queryable the instant `Popen`
returns). The M3-B network battery lives in `test_netns.py`
(route/DNS/metadata/loopback/abstract/fd-audit probes, all via
`run_bounded(..., contained=True)`); the abstract-socket test
skips where that fixture is unavailable, and the
quotas-composition test skips with the quota marker. The M4
seccomp battery lives in `test_seccomp.py` (builder byte tests,
per-rule live SIGSYS evidence, allowed/inherit/fallback
controls, ddmin diagnostic) plus `test_seccomp_compat.py` (9
enforced reruns of earlier batteries via `run_bounded(...,
contained=True, seccomp=True)`); the quota-composition test
skips with the quota marker. In-namespace exec cannot succeed
(no loader is mounted), so exec-dependent controls are written
as fork/ENOENT equivalents instead. A failed exec is not
enforcement evidence — it fails identically without the
filter — so only fork-inheritance and the ENOENT-pinned
execve claim are asserted.

## Executable documentation

Enforced by `tests/test_docs.py` on every suite run (stdlib
`doctest` only; no extra dependency):

- `src/**/*.py` docstring `>>>` examples execute via module import.
  They must be deterministic: no network, secrets, or side effects.
- Markdown ` ```python ` fences in `README.md` and `docs/*.md` must
  carry `>>>` examples and execute self-contained.
- A ` ```python ` fence without `>>>`, an unclosed fence, or `>>>`
  in a `tests/` docstring fails loudly. Doc examples live in `src/`
  or Markdown, nowhere else.
- `sh`/plain/other fences are illustrative and never executed (the
  README shell blocks mutate the operator environment). YAML
  validity rides the suite (conftest loads the real invariant
  files through `load_definitions`); no JSON snippets exist today.

## Consolidated gate

One command runs every required check, cheapest first so trivial
breaks fail before the minutes-long suite:

```sh
./scripts/quality-gate.sh
```

Gates, in execution order (stops at the first failure, exits with
that gate's status, names the failed gate on stderr):

1. `line-limit` — `python tests/line_limit.py`: the 200-line rule
   with its shrink-only baseline (also self-enforced in-suite).
2. `ruff-check` — `ruff check src tests` (project configuration).
3. `ruff-format` — `ruff format --check src tests`; verifies only,
   never rewrites.
4. `mypy` — `mypy src tests` (project strict configuration).
5. `pytest` — the full suite: source-module, CLI, integration,
   security, and documentation tests. One skip is expected (the
   usercustomize-interpreter test, inactive on some interpreters).

Prerequisite: the project venv (README: `uv sync --group dev`); a
missing interpreter fails the run with exit 2 before any gate.
`QUALITY_GATE_PYTHON` overrides the interpreter. The script resolves
the repository root from its own location, so it runs from any
working directory. When debugging a failure, re-run the gate's own
command above directly.

## Commands

```sh
uv run pytest                        # everything, incl. quality gates
uv run pytest tests/test_docs.py -q  # docs policy only
uv run pytest tests/test_line_limit.py -q  # 200-line gate only
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src tests
uv run python tests/line_limit.py    # line-limit report (exit 1 on breach)
```

Focused runs take a directory: `uv run pytest tests/test_cli -q`.

## CI wiring (when CI is introduced)

No CI exists yet; wire the commands above as required gates. No new
harness is needed: collection, gates, and the line-limit baseline
(`tests/line_limit.py`, shrink-only) all run through stock pytest
plus the existing lint/type commands.
