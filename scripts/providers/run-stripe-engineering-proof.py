#!/usr/bin/env python3
"""Run the reviewed Stripe acquisition-to-OCI/HUD/Harbor proof offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from datalox_gated_runtime.provider_proofs.stripe import (  # noqa: E402
    StripeEngineeringProofError,
    run_stripe_engineering_proof,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--capture",
        default=str(
            ROOT
            / "envs"
            / "stripe_billing_ops_v0"
            / "evidence"
            / "testmode_transition_capture_v1.json"
        ),
    )
    parser.add_argument("--expected-capture-sha256", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    try:
        result = run_stripe_engineering_proof(
            repo_root=ROOT,
            env_dir=ROOT / "envs" / "stripe_billing_ops_v0",
            capture_path=Path(arguments.capture),
            expected_capture_sha256=arguments.expected_capture_sha256,
            expected_account_id=arguments.expected_account_id,
            out_dir=Path(arguments.out),
        )
    except StripeEngineeringProofError as error:
        print(
            json.dumps(
                {
                    "schema_version": "datalox_stripe_engineering_proof_failure_v1",
                    "status": "blocked",
                    "provider_requests_sent": False,
                    "error": {
                        "code": "stripe_engineering_proof_input_invalid",
                        "message": str(error),
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
