#!/usr/bin/env bash
# Consolidated engineering quality gate for Attest Code.
#
# Runs the five required gates in cheap-first documented order and
# stops at the first failure, exiting with that gate's status:
#   1. line-limit  - python tests/line_limit.py (200-line rule + baseline)
#   2. ruff-check  - ruff check src tests
#   3. ruff-format - ruff format --check src tests (never rewrites)
#   4. mypy        - mypy src tests (project strict configuration)
#   5. pytest      - full suite, incl. docs and line-limit gate tests
#
# Usage: ./scripts/quality-gate.sh  (from anywhere; root is resolved
# from this script's location, and commands run from the root).
# Prerequisite: project venv at .venv (see README: uv sync --group dev).
# QUALITY_GATE_PYTHON overrides the interpreter (default .venv python).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${QUALITY_GATE_PYTHON:-$ROOT/.venv/bin/python}"

if [ ! -x "$PYTHON" ]; then
    echo "quality-gate: missing interpreter: $PYTHON" >&2
    echo "quality-gate: prerequisite: create the project venv (uv sync --group dev)" >&2
    exit 2
fi

cd "$ROOT" || exit 2

run_gate() {
    name="$1"
    shift
    echo "=== gate: $name ==="
    "$@"
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "FAIL: gate '$name' exited $status" >&2
        exit "$status"
    fi
}

run_gate "1/5 line-limit" "$PYTHON" tests/line_limit.py
run_gate "2/5 ruff-check" "$PYTHON" -m ruff check src tests
run_gate "3/5 ruff-format" "$PYTHON" -m ruff format --check src tests
run_gate "4/5 mypy" "$PYTHON" -m mypy src tests
run_gate "5/5 pytest" "$PYTHON" -m pytest tests/ -q

echo "PASS: all 5 quality gates"
