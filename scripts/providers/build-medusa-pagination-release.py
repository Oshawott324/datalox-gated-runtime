#!/usr/bin/env python3
"""Rebuild the complete admitted Medusa pagination slice from retained G2 facts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from datalox_gated_runtime.provider_runtime import (
    admit_provider_runtime,
    build_provider_runtime_from_gate_config,
)
from datalox_gated_runtime.provider_runtime.release import (
    ProviderReleaseProfileInput,
    build_provider_release,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / "envs" / "medusa_store_pagination_v0" / "evidence"
AUTHORITY = "api.medusa.local"
BUNDLE_VERSION = "2.16.0-pagination-v0"
ADMITTED_AT = datetime(2026, 9, 1, 12, 30, tzinfo=UTC)


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _load_builder():
    path = ROOT / "scripts" / "providers" / "build-medusa-pagination-runtime.py"
    spec = importlib.util.spec_from_file_location("build_medusa_pagination_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load runtime builder: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(limit: str, offset: str) -> dict[str, Any]:
    return {
        "authority": AUTHORITY,
        "body": None,
        "headers": {},
        "method": "GET",
        "path": "/store/products",
        "query": {"limit": limit, "offset": offset},
        "scheme": "https",
    }


def _step(
    step_id: str,
    *,
    limit: str,
    offset: str,
    status: int,
    behavior: str,
) -> dict[str, Any]:
    return {
        "covers": [
            {
                "behavior": behavior,
                "operation_id": "medusa.store.products.list",
            }
        ],
        "expected_decision_kind": "replay",
        "expected_status_code": status,
        "operation_id": "medusa.store.products.list",
        "receipt_predicate_refs": ["response_is_object", "call_was_recorded"],
        "request": _request(limit, offset),
        "step_id": step_id,
    }


def _claims(observations_path: Path) -> dict[str, Any]:
    return {
        "behavior_probes": [
            {
                "probe_id": "medusa_store_products_pagination",
                "reset_profile": "default",
                "steps": [
                    _step("first_page", limit="10", offset="0", status=200, behavior="success"),
                    _step(
                        "identical_repeat", limit="10", offset="0", status=200, behavior="duplicate"
                    ),
                    _step(
                        "middle_page", limit="10", offset="20", status=200, behavior="pagination"
                    ),
                    _step(
                        "terminal_partial_page",
                        limit="10",
                        offset="45",
                        status=200,
                        behavior="pagination",
                    ),
                    _step(
                        "beyond_terminal_page",
                        limit="10",
                        offset="60",
                        status=200,
                        behavior="pagination",
                    ),
                    _step(
                        "invalid_limit", limit="invalid", offset="0", status=400, behavior="failure"
                    ),
                ],
            }
        ],
        "bundle_version": BUNDLE_VERSION,
        "evidence_sources": [
            {
                "artifact_ref": "observations.json",
                "artifact_sha256": _sha256(observations_path),
                "distribution_label": "public",
                "evidence_id": "medusa_pagination_g2",
                "grounding_level": "G2_SELF_HOSTED_REFERENCE",
                "observed_at": "2026-09-01T12:24:33Z",
                "rights_basis": "Self-authored factual measurement summary from a locally deployed MIT-licensed Medusa 2.16.0 reference system; it contains no provider payload bytes, response text, credentials, or provider-generated identifiers.",
                "valid_through": "2027-09-01T12:24:33Z",
            }
        ],
        "operations": [
            {
                "behavior_program": "medusa_store_products_limit_offset",
                "covered_behaviors": ["success", "failure", "duplicate", "pagination"],
                "grounding": {
                    "evidence_refs": ["medusa_pagination_g2"],
                    "level": "G2_SELF_HOSTED_REFERENCE",
                },
                "mutability": "read",
                "native_surface": {
                    "authority": AUTHORITY,
                    "method": "GET",
                    "path_template": "/store/products",
                    "scheme": "https",
                    "type": "http",
                },
                "operation_id": "medusa.store.products.list",
                "rights": {
                    "behavior_distribution_basis": "Runtime values and response text are self-authored. Pagination semantics are factual measurements from an MIT-licensed reference deployment, recorded without provider payload bytes or identifiers.",
                    "distribution_label": "public",
                },
                "state_effects": [],
            }
        ],
        "provider_id": "medusa",
        "provider_invariants": [
            {
                "expected": "gate_config_v1",
                "operator": "equals",
                "pointer": "/protocol",
                "predicate_id": "runtime_protocol_is_gate_config_v1",
                "source": "provider_state",
            }
        ],
        "receipt_predicates": [
            {
                "expected_type": "object",
                "operator": "type",
                "pointer": "",
                "predicate_id": "response_is_object",
                "source": "response_body",
            },
            {
                "expected_type": "array",
                "operator": "type",
                "pointer": "/events",
                "predicate_id": "call_was_recorded",
                "source": "call_evidence",
            },
        ],
        "reset_profiles": [{"kind": "compiled_seed", "profile_id": "default"}],
        "schema_version": "datalox_provider_operation_claims_v1",
    }


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build(source_evidence: Path, output_root: Path) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"output root already exists: {output_root}")
    source_evidence = source_evidence.resolve(strict=True)
    observations = source_evidence / "observations.json"
    provenance = source_evidence / "provenance.json"
    output_root.mkdir(parents=True)
    evidence = output_root / "evidence"
    evidence.mkdir()
    shutil.copy2(observations, evidence / "observations.json")
    shutil.copy2(provenance, evidence / "provenance.json")

    gate_config = output_root / "gate_config.json"
    _load_builder().build(evidence / "observations.json", gate_config)
    claims_path = evidence / "operation-claims.json"
    _write_json(claims_path, _claims(evidence / "observations.json"))

    bundle = output_root / "provider-runtime"
    build_provider_runtime_from_gate_config(
        source_gate_config=gate_config,
        output_dir=bundle,
        provider_id="medusa",
        authorities=(AUTHORITY,),
        bundle_version=BUNDLE_VERSION,
    )
    admission_path = output_root / "provider-admission.json"
    admission = admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims_path,
        output_path=admission_path,
        admitted_at=ADMITTED_AT,
    )
    release = build_provider_release(
        profiles=(
            ProviderReleaseProfileInput(
                profile_id="default",
                bundle_dir=bundle,
                admission_path=admission_path,
            ),
        ),
        release_version=BUNDLE_VERSION,
        output_dir=output_root / "provider-release",
    )
    return {
        "output_root": str(output_root),
        "admission_sha256": admission.sha256,
        "release_manifest_digest": release.manifest_descriptor["digest"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = build(args.evidence, args.out.resolve())
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else report["output_root"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
