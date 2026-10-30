"""Operator CLI: `attest review` and `attest verify` (argparse, no framework).

Exit-code contract:
- 0: review approved (or already approved); verification PASSED.
- 1: verification FAILED.
- 2: verification INCONCLUSIVE.
- 3: usage errors, declined review, missing/invalid approval, unsafe source
  snapshot, or any other execution error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from apps.approvals import DEFAULT_APPROVALS_FILE
from apps.review import ReviewStatus, run_review
from apps.verify import run_verify
from attest_spec import Verdict
from examples.admin_authorization import TARGETS

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_INCONCLUSIVE = 2
EXIT_ERROR = 3

_VERDICT_EXITS = {
    Verdict.PASSED: EXIT_OK,
    Verdict.FAILED: EXIT_FAILED,
    Verdict.INCONCLUSIVE: EXIT_INCONCLUSIVE,
}

_REVIEW_EXITS = {
    ReviewStatus.APPROVED: EXIT_OK,
    ReviewStatus.ALREADY_APPROVED: EXIT_OK,
    ReviewStatus.DECLINED: EXIT_ERROR,
    ReviewStatus.ERROR: EXIT_ERROR,
}


class _Parser(argparse.ArgumentParser):
    """Argument parser whose usage errors follow the exit-code contract."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="attest", description="Attest Code operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    review = sub.add_parser("review", help="inspect and approve an invariant")
    review.add_argument("invariant_file", type=Path)
    review.add_argument("--approvals", type=Path, default=Path(DEFAULT_APPROVALS_FILE))
    review.add_argument("--approver", required=True, help="name of the human reviewer")
    review.add_argument("--id", default=None, help="select one invariant from the file")
    verify = sub.add_parser("verify", help="verify a target against an approved invariant")
    verify.add_argument("invariant_file", type=Path)
    verify.add_argument("--revision", required=True, help="git revision under test")
    verify.add_argument("--approvals", type=Path, default=Path(DEFAULT_APPROVALS_FILE))
    verify.add_argument("--id", default=None, help="select one invariant from the file")
    verify.add_argument(
        "--repo",
        type=Path,
        default=Path.cwd(),
        help="repository root under test (must be the work-tree top level)",
    )
    verify.add_argument("--target", choices=TARGETS, default="repaired")
    verify.add_argument("--timeout", type=float, default=60.0)
    verify.add_argument("--format", choices=("text", "json"), default="text")
    verify.add_argument(
        "--exec",
        choices=("standard", "contained", "hardened"),
        default="standard",
        help="worker isolation: standard (S1/S2 supervision), contained "
        "(+ namespaces/filesystem), hardened (+ quotas/seccomp where "
        "the host supports them; refused otherwise)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "review":
            status = run_review(
                invariant_file=args.invariant_file,
                approvals_file=args.approvals,
                approver=args.approver,
                invariant_id=args.id,
            )
            return _REVIEW_EXITS[status]
        verdict = run_verify(
            invariant_file=args.invariant_file,
            approvals_file=args.approvals,
            invariant_id=args.id,
            revision=args.revision,
            repo=args.repo,
            target=args.target,
            timeout_seconds=args.timeout,
            output_format=args.format,
            exec_profile=args.exec,
        )
        return _VERDICT_EXITS[verdict]
    except Exception as exc:
        print(f"attest: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
