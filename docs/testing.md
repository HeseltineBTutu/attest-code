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
tests go to `test_cli/` or `test_integration/`.

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
