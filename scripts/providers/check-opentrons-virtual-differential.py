#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "envs/probed_opentrons_local_v0"
EVIDENCE = ENV / "evidence/behavior_harvest"
CAPTURE_MANIFEST = EVIDENCE / "captures/capture_manifest.json"
REPORT = EVIDENCE / "differential_report.json"
IDENTITY = EVIDENCE / "simulator_identity.json"
PROTOCOL = ROOT / "tests/fixtures/opentrons/minimal_protocol.py"
PROTOCOL_PROGRAMS = {"analysis_create", "protocol_create", "protocol_delete"}
sys.path.insert(0, str(ROOT / "src"))

from datalox_gated_runtime.behavior_harvest.engines import v3  # noqa: E402
from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (  # noqa: E402
    sha256_digest,
)
from datalox_gated_runtime.engineering_proof import (  # noqa: E402
    PathPrefixMapping,
    PrincipalBoundTraceTarget,
    PrincipalMapping,
    WorldTargetSpec,
    principal_bindings_from_recipe_steps,
)
from datalox_gated_runtime.engineering_proof.world_target import (  # noqa: E402
    WorldBundleTraceTarget,
)
from datalox_gated_runtime.reference import ReferenceCall  # noqa: E402


def _digest(path: Path) -> str:
    return sha256_digest(path.read_bytes())


class OpentronsWorldTraceTarget(WorldBundleTraceTarget):
    """Map provider multipart upload semantics to the local tool projection."""

    def execute(self, call: ReferenceCall, *, principal_context_id: str):
        body = call.body
        if (
            call.operation_id == "protocol.create"
            and isinstance(body, Mapping)
            and body.get("kind") == "multipart_form_data"
        ):
            body = {
                "files": [
                    {
                        "contentSha256": _digest(PROTOCOL),
                        "fileName": PROTOCOL.name,
                        "metadata": {
                            "apiLevel": "2.20",
                            "author": "Datalox",
                            "description": (
                                "Self-authored virtual lifecycle protocol with no physical "
                                "movement."
                            ),
                            "protocolName": "Datalox virtual lifecycle fixture",
                        },
                    }
                ]
            }
            call = ReferenceCall(
                method=call.method,
                path=call.path,
                query=call.query,
                body=body,
                headers=call.headers,
                operation_id=call.operation_id,
            )
        return super().execute(call, principal_context_id=principal_context_id)


def _target() -> WorldBundleTraceTarget:
    return OpentronsWorldTraceTarget(
        env_dir=ENV,
        spec=WorldTargetSpec(
            target_id="opentrons_virtual_lifecycle_local_world",
            target_version="1.0.0",
            episode_id="opentrons-virtual-lifecycle-001",
            principal_mappings=(
                PrincipalMapping("simulator", "opentrons-differential", "lab_operator"),
            ),
            path_mappings=(PathPrefixMapping("/", "/"),),
        ),
    )


def compute_report() -> dict[str, Any]:
    manifest = json.loads(CAPTURE_MANIFEST.read_text(encoding="utf-8"))
    identity_digest = _digest(IDENTITY)
    reports: dict[str, Any] = {}
    for program in manifest["programs"]:
        name = program["program"]
        connector = EVIDENCE / (
            "sandbox_connector_protocol.v3.json"
            if name in PROTOCOL_PROGRAMS
            else "sandbox_connector_json.v3.json"
        )
        recipe = EVIDENCE / "recipes" / f"{name}.behavior_recipe_v3.json"
        capture = ROOT / program["capture_path"]
        target = _target()
        try:
            recipe_contract = v3.load_recipe(
                recipe,
                expected_sha256=_digest(recipe),
            ).value
            report = v3.run_compiled_behavior_trace(
                target=PrincipalBoundTraceTarget(
                    target=target,
                    bindings=principal_bindings_from_recipe_steps(recipe_contract.steps),
                ),
                capture_path=capture,
                expected_capture_sha256=program["sha256"],
                connector_path=connector,
                expected_connector_sha256=_digest(connector),
                recipe_path=recipe,
                expected_recipe_sha256=_digest(recipe),
                expected_engine=v3.current_engine_identity(),
                sensitive_values={},
                static_input_paths={"deployment": IDENTITY},
                expected_static_input_sha256={"deployment": identity_digest},
                static_artifact_paths=({"protocol": PROTOCOL} if name in PROTOCOL_PROGRAMS else {}),
            )
        finally:
            target.close()
        reports[name] = report.to_dict()
    return {
        "claim_boundary": (
            "Exact binding-aware official-simulator capture versus local-world comparison. "
            "A false result and every mismatch are retained; this report is not a "
            "physical-robot or production-equivalence claim."
        ),
        "comparison_profile": "behavior_binding_exact_with_declared_request_projection_v1",
        "passed": all(report["passed"] for report in reports.values()),
        "programs": reports,
        "provider_id": "opentrons_robot_server",
        "reference_system": "official Opentrons robot-server v9.1.1 disposable simulator",
        "request_projections": [
            {
                "operation_id": "protocol.create",
                "projection": (
                    "Captured multipart artifact reference to the local semantic files record; "
                    "the fixture SHA-256 remains exact."
                ),
            }
        ],
        "schema_id": "datalox_opentrons_exact_differential_report_v1",
        "source_capture_manifest_sha256": _digest(CAPTURE_MANIFEST),
        "target": "probed_opentrons_local_v0 admitted world",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    computed = compute_report()
    body = (
        json.dumps(
            computed,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if args.write_report:
        REPORT.write_text(body, encoding="utf-8")
        REPORT.chmod(0o600)
        print(f"wrote {REPORT.relative_to(ROOT)}")
        return 0
    if not REPORT.exists() or REPORT.read_text(encoding="utf-8") != body:
        print("Opentrons exact differential report is stale.", file=sys.stderr)
        return 1
    print(
        "Opentrons captures are valid and the exact differential report is current "
        f"(passed={computed['passed']})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
