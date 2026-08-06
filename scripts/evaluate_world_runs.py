#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from datalox_gated_runtime.world_v1.evaluation import (
    EvaluationInputError,
    build_evaluation_report,
    load_completed_runs,
    write_evaluation_report,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate completed Datalox run exports into Agent-CI JSON and Markdown."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Run directories or concrete run_export.json files.",
    )
    parser.add_argument("--json-out", required=True, type=Path, help="Source-of-truth JSON output.")
    parser.add_argument(
        "--markdown-out", required=True, type=Path, help="Markdown report derived from JSON."
    )
    parser.add_argument(
        "-k",
        "--k",
        action="append",
        type=int,
        dest="k_values",
        help="Reliability sample size; repeat for several values. Defaults to 1.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        runs = load_completed_runs(args.inputs)
        report = build_evaluation_report(runs, k_values=args.k_values or [1])
        write_evaluation_report(
            report,
            json_path=args.json_out,
            markdown_path=args.markdown_out,
        )
    except EvaluationInputError as exc:
        print(json.dumps({"error": exc.to_dict()}, sort_keys=True), file=sys.stderr)
        return 1
    except ValueError as exc:
        print(
            json.dumps(
                {"error": {"code": "agent_ci_report_invalid", "message": str(exc)}},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "json_report": str(args.json_out),
                "markdown_report": str(args.markdown_out),
                "attempts": len(runs),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
