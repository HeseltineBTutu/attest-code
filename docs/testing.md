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
execve claim are asserted. The S3 execution-profile battery
lives in `test_exec_profile.py` (profile mapping, lazy
preflight, digest binding, enforcement derivation — all
unit-level with mocked detectors), `test_resource_evidence.py`
(counter formatting, unavailable markers, per-attempt
association, plus `run_bounded` wiring with mocked scopes),
`test_quota_failures.py` (timeout/crash/cleanup annotation via
mocked supervision, no systemd needed),
`test_runner_protocol.py` (version probing against synthetic
snapshots, strict argv parsing, mismatch-is-INFRA),
`test_scope_metrics.py` (peak-reader units and failure modes,
teardown marks, resources-parser round trips, verdict
independence), and
`tests/test_cli/test_exec_cli.py` (parser behaviour, staged
standard/contained runs, pre-attempt hardened refusal, and
one live hardened run gated on the quota marker).

Mocked and unit tests prove wiring, formatting, and fail-closed
branching; only tests that actually place a workload in a scope,
namespace, or filter prove enforcement. A skipped quota,
namespace, or abstract-socket test is an untested claim, never
a pass — count skips separately and re-run them on a capable
host (Linux with user namespaces, a working systemd user
manager with D-Bus session, cgroup v2 with the cpu/memory/pids
controllers, and x86_64/aarch64 KILL_PROCESS-capable seccomp)
before citing enforcement evidence.

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
Validation runs, from cheapest to most demanding:

```sh
# full suite incl. gates (skips live enforcement without a user bus)
uv run pytest -q
# live quota/scope enforcement (needs the capable host above)
uv run pytest tests/test_src/test_attest_core/test_quota_live.py \
  tests/test_src/test_attest_core/test_scopes.py -q
# live hardened CLI (same host; asserts verified + per-attempt counters)
uv run pytest tests/test_cli/test_exec_cli.py::test_hardened_live_reports_verified_resources -q
# adversarial production scenarios (default profile here; repeat the
# same scenarios with --exec hardened on the capable host for evidence)
uv run pytest tests/test_cli/test_verify_cli.py -q
```

## Workload measurement protocol (S3)

Collects per-attempt resource metrics for the four production
targets so the provisional quotas can be evaluated against real
evidence. It measures only; it never changes limits, verdicts, or
enforcement.

Prerequisites: a capable Linux host (namespaces, systemd user
manager with D-Bus session, cgroup v2 cpu/memory/pids, seccomp
KILL_PROCESS), a clean committed tree (the snapshot gate refuses
dirty scope), and a valid human approval for the invariant under
test. Every run below must pass hardened preflight first; a
refusal is a blocked measurement, never a sample.

Metric semantics (all read from the attempt's own live scope
before teardown; independently observed, never runner-reported):

- `mem_peak`: `memory.peak`, bytes, high-water mark.
- `pids_peak`: `pids.peak`, count, high-water mark of tasks.
- `cpu_usec`: `cpu.stat usage_usec`, microseconds, cumulative CPU.
- `oom`, `oom_kill`, `pids_max`, `throttled_usec`: event counters.
- `teardown`: `empty-verified` when the scope stopped and verified
  empty, else `failed(reason)`.

Unavailable data renders as `unavailable(reason)`, never zero.
Metrics ride the per-attempt `resources` evidence field; they are
diagnostic only and cannot select a verdict.

Procedure — five repetitions per target (each run is three
attempts, so fifteen samples per target), JSON output retained:

```sh
# from a clean tree with approvals in place; repeat each 5x, keep every JSON
attest verify invariants/auth-admin-001.yaml --revision HEAD \
  --target repaired --exec hardened --format json > meas-repaired-N.json
attest verify invariants/auth-admin-001.yaml --revision HEAD \
  --target vulnerable --exec hardened --format json > meas-vulnerable-N.json
attest verify invariants/auth-admin-001.yaml --revision HEAD \
  --target hanging --timeout 2 --exec hardened --format json > meas-hanging-N.json
attest verify invariants/auth-admin-001.yaml --revision HEAD \
  --target crashing --exec hardened --format json > meas-crashing-N.json
```

Then parse each run's `attempts[].resources` with
`attest_core.resource_evidence.parse_resources` and compare peak
columns against the provisional limits (512 MiB, 64 tasks, 200%
CPU, swap disabled). Report termination classifications alongside
the metrics: repaired PASSED, vulnerable FAILED, hanging/crashing
INCONCLUSIVE. Quota suitability is a separate evaluation step
after the samples exist — passing runs alone do not declare it.

## CI wiring (when CI is introduced)

No CI exists yet; wire the commands above as required gates. No new
harness is needed: collection, gates, and the line-limit baseline
(`tests/line_limit.py`, shrink-only) all run through stock pytest
plus the existing lint/type commands.
