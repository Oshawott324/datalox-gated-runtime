#!/usr/bin/env python3
"""Build the OpenLMIS selected-write coverage declaration from retained evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "envs/openlmis_supply_chain_v0/evidence/behavior_harvest"
COVERAGE = EVIDENCE / "core_program_coverage.json"
INVENTORY = EVIDENCE / "restricted/inventory.json"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain an object")
    return value


def build() -> dict[str, Any]:
    previous = _load(COVERAGE)
    inventory = _load(INVENTORY)
    previous_rows = {row["operation_id"]: row for row in previous["operations"]}
    failures = {row["operation_id"]: row for row in inventory["fresh_reset_observations"]}
    rows: list[dict[str, Any]] = []
    for retained in inventory["operations"]:
        operation_id = retained["operation_id"]
        old = previous_rows[operation_id]
        classification = retained["classification"]
        complete = classification == "generic_reloadable_complete"
        differential_status = retained["differential"]["status"]
        row = {
            "operation_id": operation_id,
            "family": old["family"],
            "method": old["method"],
            "classification": classification,
            "acceptance": (
                "provider_observed_complete_program"
                if complete
                else "provider_write_observed_partial"
            ),
            "evidence_state": classification,
            "source_refs": old.get("source_refs", []),
            "differential": retained["differential"],
            "reason": (
                "The exact retained generic capture reloads and compiles offline through the "
                "existing behavior-harvest compiler. The provider-neutral target executes its "
                "declared per-step principals; exact equivalence is claimed only when the "
                f"retained differential status is passed (actual: {differential_status})."
                if complete
                else "The provider write, provider-native outcome, and resulting state were "
                "observed directly, but safe response headers/content type were not retained; "
                "this remains partial evidence and is not relabeled as a complete capture."
            ),
        }
        if complete:
            row.update(
                {
                    "capture_path": retained["capture_path"],
                    "capture_sha256": retained["capture_sha256"],
                    "connector_path": retained["connector_path"],
                    "connector_sha256": retained["connector_sha256"],
                    "recipe_path": retained["recipe_path"],
                    "recipe_sha256": retained["recipe_sha256"],
                    "compiled_step_count": retained["compiled_step_count"],
                }
            )
        else:
            row.update(
                {
                    "sequence_path": retained["sequence_path"],
                    "sequence_sha256": retained["sequence_sha256"],
                    "observed_step_count": retained["step_count"],
                }
            )
        if operation_id in failures:
            row["fresh_reset_observation"] = failures[operation_id]
        rows.append(row)
    counts = inventory["classification_counts"]
    differential_pass_count = sum(
        row["differential"].get("status") == "passed"
        for row in inventory["operations"]
        if row["classification"] == "generic_reloadable_complete"
    )
    return {
        "schema_id": "datalox_openlmis_behavior_program_coverage_v2",
        "environment_id": "openlmis_supply_chain_v0",
        "provider_id": "openlmis",
        "provider_version": "Reference Distribution v3.19.2",
        "selected_write_count": len(rows),
        "provider_observed_write_count": len(rows),
        "provider_observed_complete_program_count": counts["generic_reloadable_complete"],
        "provider_observed_partial_write_count": counts["direct_observed_partial"],
        "differential_pass_count": differential_pass_count,
        "classification_counts": counts,
        "classification_contract": {
            "generic_reloadable_complete": (
                "Exact connector, recipe, static inputs, and capture are retained and compile "
                "offline through the existing generic compiler."
            ),
            "direct_observed_partial": (
                "A real provider write transition is retained with request/response bodies and "
                "status, but one or more exact header/content-type/duplicate receipts are missing."
            ),
            "provider_native_reset_failure": (
                "A fresh official demo-data reset produced a provider 500 and an exact post-read "
                "proved no observable mutation. This does not invalidate an earlier successful "
                "provider observation."
            ),
            "executed_mismatch": (
                "The provider-neutral target executed the retained trace, including explicit "
                "per-step principals, but exact provider/world comparison found mismatches."
            ),
        },
        "claim_boundary": inventory["claim_boundary"],
        "state_reset": inventory["state_reset"],
        "functional_reset_equivalence": inventory["functional_reset_equivalence"],
        "authoring_readiness": {
            "checker": "scripts/providers/check-openlmis-authoring-readiness.py",
            "retained_evidence_checker": ("scripts/providers/check-openlmis-retained-evidence.py"),
            "all_selected_writes_observed": True,
            "ready_for_complete_capture": False,
            "missing_write_observation_count": 0,
            "missing_complete_program_count": counts["direct_observed_partial"],
            "local_differential_ready_count": differential_pass_count,
        },
        "operations": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    body = json.dumps(build(), ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"
    if args.check:
        if COVERAGE.read_text(encoding="utf-8") != body:
            raise SystemExit("OpenLMIS behavior coverage is stale")
        print("OpenLMIS behavior coverage is current")
        return 0
    COVERAGE.write_text(body, encoding="utf-8")
    print(COVERAGE.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
