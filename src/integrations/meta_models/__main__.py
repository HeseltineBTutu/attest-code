"""Operator entry point: `python -m integrations.meta_models`.

`list-models` shows the account's models. `diagnose` accepts a FAILED
`attest verify --format json` report plus an operator-selected excerpt
file and prints the model proposal for human review. Diagnosis requires
FAILED; INCONCLUSIVE and PASSED are refused, and nothing is applied.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from attest_core.invariants import load_definitions
from integrations.meta_models.client import DEFAULT_MODEL, MetaModelsClient
from integrations.meta_models.diagnose import (
    DiagnosisError,
    build_verdict_summary,
    diagnose,
    render_for_review,
    summarize_failed_report,
)
from integrations.meta_models.errors import MetaModelsError
from integrations.meta_models.protocol import MAX_CODE_EXCERPT

EXIT_OK = 0
EXIT_ERROR = 3
"""Failure exit mirrors the `attest` execution-error contract."""

MAX_EXCERPT_FILE_BYTES = 1_000_000


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DiagnosisError(f"cannot read report file: {exc}") from exc
    except ValueError as exc:
        raise DiagnosisError(f"report file is not valid JSON: {exc}") from exc


def _read_excerpt(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_EXCERPT_FILE_BYTES:
            raise DiagnosisError(f"excerpt file exceeds {MAX_EXCERPT_FILE_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DiagnosisError(f"cannot read excerpt file: {exc}") from exc
    except ValueError as exc:
        raise DiagnosisError(f"excerpt file is not valid UTF-8: {exc}") from exc
    if len(text) > MAX_CODE_EXCERPT:
        raise DiagnosisError(
            f"excerpt exceeds {MAX_CODE_EXCERPT} characters; select a smaller excerpt"
        )
    return text


def _invariant_text(invariant_file: Path, invariant_id: str | None, version: int) -> str:
    try:
        definitions = load_definitions(invariant_file)
    except (OSError, ValueError) as exc:
        raise DiagnosisError(f"cannot load invariant file: {exc}") from exc
    matches = [d for d in definitions if invariant_id is None or d.invariant_id == invariant_id]
    if not matches:
        raise DiagnosisError(f"invariant {invariant_id!r} not found in {invariant_file}")
    if len(matches) > 1:
        raise DiagnosisError("invariant file matches multiple definitions; pass --id")
    definition = matches[0]
    if definition.version != version:
        raise DiagnosisError(
            f"invariant file has v{definition.version} but the report verified v{version}"
        )
    return definition.requirement


def _run_list_models(client: MetaModelsClient) -> int:
    for model in client.list_models():
        print(model)
    return EXIT_OK


def _run_diagnose(client: MetaModelsClient, args: argparse.Namespace) -> int:
    report = _read_json(args.report)
    if not isinstance(report, dict):
        raise DiagnosisError("report file must contain a JSON object")
    summary = summarize_failed_report(report)
    requirement = _invariant_text(
        args.invariant_file, args.id or summary.invariant_id, summary.invariant_version
    )
    if args.id is not None and args.id != summary.invariant_id:
        raise DiagnosisError("selected invariant differs from the report's invariant")
    excerpt = _read_excerpt(args.excerpt)
    result = diagnose(
        client,
        invariant_id=summary.invariant_id,
        invariant_version=summary.invariant_version,
        invariant_text=requirement,
        verdict_summary=build_verdict_summary(summary),
        code_excerpt=excerpt,
    )
    print(render_for_review(result))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attest-diagnose")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="model (standard variants only)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list-models", help="list models available to the account")
    diag = sub.add_parser("diagnose", help="diagnose a FAILED verify report")
    diag.add_argument(
        "--report", type=Path, required=True, help="attest verify --format json output"
    )
    diag.add_argument("--invariant-file", type=Path, required=True)
    diag.add_argument("--id", default=None, help="select one invariant from the file")
    diag.add_argument("--excerpt", type=Path, required=True, help="operator-selected code excerpt")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        client = MetaModelsClient(model=args.model)
        if args.command == "list-models":
            return _run_list_models(client)
        return _run_diagnose(client, args)
    except (MetaModelsError, DiagnosisError, ValueError) as exc:
        # ValueError covers input-bound violations (oversized or malformed
        # operator/model inputs); at this CLI boundary every such failure
        # is an execution error under the exit-code contract.
        print(f"attest-diagnose: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
