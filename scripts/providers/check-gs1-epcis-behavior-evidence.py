#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "envs/gs1_epcis_2_0_1_v0"
EVIDENCE = ENV / "evidence/behavior_harvest"
REPORT = EVIDENCE / "differential_report.json"
sys.path.insert(0, str(ROOT / "src"))

from datalox_gated_runtime.behavior_harvest.engines import v3  # noqa: E402
from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (  # noqa: E402
    sha256_digest,
)
from datalox_gated_runtime.engineering_proof import (  # noqa: E402
    PathPrefixMapping,
    WorldTargetSpec,
)
from datalox_gated_runtime.engineering_proof.world_target import (  # noqa: E402
    WorldBundleTraceTarget,
)

ROLES = {
    "commissioning": "manufacturer",
    "aggregation": "manufacturer",
    "shipping": "logistics",
    "receiving": "retailer",
    "transformation": "manufacturer",
    "correction": "retailer",
    "decommission": "manufacturer",
}


def _digest(path: Path) -> str:
    return sha256_digest(path.read_bytes())


def _authorization() -> bytes:
    value = os.environ.get("DATALOX_GS1_REFERENCE_AUTHORIZATION")
    if value is None or not value.startswith("Basic "):
        raise RuntimeError(
            "DATALOX_GS1_REFERENCE_AUTHORIZATION must contain the exact synthetic Basic "
            "Authorization value used for the disposable reference captures"
        )
    return value.encode("ascii")


def _target(name: str) -> WorldBundleTraceTarget:
    return WorldBundleTraceTarget(
        env_dir=ENV,
        spec=WorldTargetSpec(
            target_id="gs1_epcis_local_world",
            target_version="1.0.0",
            episode_id="cold-chain-trace-001",
            actor_id=f"proof-{name}",
            actor_role=ROLES[name],
            path_mappings=(PathPrefixMapping("/", "/"),),
            operation_mappings=(),
        ),
    )


def compute_report() -> dict[str, Any]:
    coverage = json.loads((EVIDENCE / "core_program_coverage.json").read_bytes())
    connector = EVIDENCE / coverage["connector"]
    reference = EVIDENCE / coverage["reference_system"]
    authorization = _authorization()
    reports: dict[str, Any] = {}
    for program in coverage["programs"]:
        name = program["transition"]
        recipe = EVIDENCE / program["recipe"]
        capture = EVIDENCE / program["capture"]
        if _digest(recipe) != program["recipe_sha256"]:
            raise RuntimeError(f"recipe digest mismatch: {name}")
        if _digest(capture) != program["capture_sha256"]:
            raise RuntimeError(f"capture digest mismatch: {name}")
        v3.load_capture(
            capture,
            expected_sha256=program["capture_sha256"],
            connector_path=connector,
            expected_connector_sha256=_digest(connector),
            recipe_path=recipe,
            expected_recipe_sha256=program["recipe_sha256"],
            expected_engine=v3.current_engine_identity(),
            sensitive_values={"authorization": authorization},
            static_input_paths={"reference_system": reference},
            expected_static_input_sha256={"reference_system": _digest(reference)},
        )
        target = _target(name)
        try:
            report = v3.run_compiled_behavior_trace(
                target=target,
                capture_path=capture,
                expected_capture_sha256=program["capture_sha256"],
                connector_path=connector,
                expected_connector_sha256=_digest(connector),
                recipe_path=recipe,
                expected_recipe_sha256=program["recipe_sha256"],
                expected_engine=v3.current_engine_identity(),
                sensitive_values={"authorization": authorization},
                static_input_paths={"reference_system": reference},
                expected_static_input_sha256={"reference_system": _digest(reference)},
            )
        finally:
            target.close()
        reports[name] = report.to_dict()
    return {
        "schema_id": "datalox_epcis_exact_differential_report_v1",
        "provider_id": "gs1_epcis",
        "reference_system": "FasTnT EPCIS v2.8.2 release image",
        "target": "gs1_epcis_2_0_1_v0 local world",
        "comparison_profile": "behavior_binding_exact_v1",
        "passed": all(report["passed"] for report in reports.values()),
        "claim_boundary": (
            "Exact reference-versus-local comparison. A false verdict is retained as "
            "mismatch evidence and must not be relabeled as behavior equivalence."
        ),
        "programs": reports,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    computed = compute_report()
    body = (
        json.dumps(computed, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"
    )
    if args.write_report:
        REPORT.write_text(body, encoding="utf-8")
        print(f"wrote {REPORT.relative_to(ROOT)}")
        return 0
    if not REPORT.exists() or REPORT.read_text(encoding="utf-8") != body:
        print("GS1 EPCIS exact differential report is stale.", file=sys.stderr)
        return 1
    print(
        "GS1 EPCIS captures are valid and the exact differential report is current "
        f"(passed={computed['passed']})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
