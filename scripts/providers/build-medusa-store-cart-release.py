#!/usr/bin/env python3
"""Build the admitted Medusa 2.16.0 Store cart provider release."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from datalox_gated_runtime.provider_runtime import (
    admit_provider_runtime,
    build_provider_runtime_from_world,
)
from datalox_gated_runtime.provider_runtime.release import (
    ProviderReleaseProfileInput,
    build_provider_release,
)
from datalox_gated_runtime.world_v1.bundle import compute_bundle_hashes, validate_world_bundle

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / "envs" / "medusa_store_cart_v0"
AUTHORITY = "api.medusa.local"
PROVIDER_ID = "medusa"
BUNDLE_VERSION = "2.16.0-store-cart-v0"
EPISODE_ID = "medusa_store_cart_reference"
PUBLISHABLE_KEY = "pk_datalox_local_store"

LIST = "medusa.store.products.list"
CREATE = "medusa.store.carts.create"
RETRIEVE = "medusa.store.carts.retrieve"
ADD = "medusa.store.carts.line_items.add"
UPDATE = "medusa.store.carts.line_items.update"
DELETE = "medusa.store.carts.line_items.delete"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _evidence_window(evidence: Path) -> tuple[str, str, datetime]:
    provenance = json.loads((evidence / "provenance.json").read_text(encoding="utf-8"))
    if (
        provenance.get("provider") != "Medusa"
        or provenance.get("provider_version") != "2.16.0"
        or provenance.get("reference_kind") != "self_hosted_exact_release"
    ):
        raise ValueError("Medusa evidence provenance does not identify the exact reference")
    observed_text = provenance.get("observed_at")
    if not isinstance(observed_text, str) or not observed_text.endswith("Z"):
        raise ValueError("Medusa evidence observed_at must be a UTC timestamp")
    observed = datetime.fromisoformat(observed_text)
    valid_through = observed.replace(year=observed.year + 1)
    admitted_at = observed + timedelta(minutes=1)
    return (
        observed_text,
        valid_through.isoformat().replace("+00:00", "Z"),
        admitted_at,
    )


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _identity_policy() -> dict[str, Any]:
    error = {
        "status_code": 400,
        "body": {
            "type": "not_allowed",
            "message": "A valid publishable API key is required.",
        },
        "headers": {},
    }
    return {
        "schema_version": "datalox_provider_identity_v1",
        "mode": "credential_map",
        "principals": [
            {
                "principal_context_id": "store_public_client",
                "actor_id": "store_agent",
                "actor_role": "store_operator",
                "credentials": [
                    {
                        "location": "header",
                        "name": "x-publishable-api-key",
                        "value_sha256": "sha256:32ba5333f501bf144a27382cd04786729f5ec03bacde8918864c7e98fa266fdc",
                    }
                ],
            }
        ],
        "missing_identity": error,
        "invalid_identity": error,
    }


def _lifecycle_checker() -> Any:
    path = ROOT / "scripts" / "providers" / "check-medusa-store-cart-lifecycle.py"
    spec = importlib.util.spec_from_file_location("check_medusa_store_cart_lifecycle", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load lifecycle checker: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_json_object(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise TypeError(f"expected a JSON object: {path}")
    return value


def _validate_public_grounding_evidence(evidence: Path) -> None:
    """Validate the immutable public attestation without requiring restricted bytes.

    Re-deriving the attestation from the exact receipt is a separate authoring gate
    implemented by ``check-medusa-store-cart-grounding.py``. The public release
    builder validates only the promoted artifacts that are intentionally present in
    public source.
    """

    provenance = _load_json_object(evidence / "provenance.json")
    observations = _load_json_object(evidence / "observations.json")
    report = _load_json_object(evidence / "grounding-report.json")
    receipt = provenance.get("grounding_receipt")
    if not isinstance(receipt, dict) or observations.get("grounding_receipt") != receipt:
        raise ValueError("public Medusa evidence does not bind one grounding receipt")
    required_receipt = {
        "schema_version",
        "manifest_sha256",
        "tree_sha256",
        "record_count",
    }
    if set(receipt) != required_receipt:
        raise ValueError("public Medusa grounding receipt binding is invalid")
    if receipt["schema_version"] != "datalox_provider_grounding_receipt_v1":
        raise ValueError("public Medusa grounding receipt schema is unsupported")
    if not all(
        isinstance(receipt[name], str) and _SHA256.fullmatch(receipt[name])
        for name in ("manifest_sha256", "tree_sha256")
    ):
        raise ValueError("public Medusa grounding receipt digests are invalid")
    if not isinstance(receipt["record_count"], int) or receipt["record_count"] < 1:
        raise ValueError("public Medusa grounding receipt record count is invalid")

    checked_flags = {
        "cart_state_projection_continuity_checked",
        "cart_state_projection_relations_checked",
        "duplicate_safe_request_identity_checked",
        "failure_atomicity_within_cart_state_projection_checked",
        "generated_identifier_relations_checked",
        "raw_bodies_and_framing_checked",
        "raw_statuses_checked",
    }
    expected_report_keys = checked_flags | {
        "schema_version",
        "status",
        "manifest_sha256",
        "tree_sha256",
        "record_count",
        "promoted_lifecycle_steps",
    }
    if set(report) != expected_report_keys:
        raise ValueError("public Medusa grounding report has an unexpected shape")
    if (
        report["schema_version"] != "datalox_medusa_store_cart_grounding_check_v1"
        or report["status"] != "passed"
        or any(report[name] is not True for name in checked_flags)
        or report["manifest_sha256"] != receipt["manifest_sha256"]
        or report["tree_sha256"] != receipt["tree_sha256"]
        or report["record_count"] != receipt["record_count"]
    ):
        raise ValueError("public Medusa grounding report does not match its receipt binding")
    lifecycle = observations.get("lifecycle")
    if not isinstance(lifecycle, list) or report["promoted_lifecycle_steps"] != len(lifecycle):
        raise ValueError("public Medusa grounding report does not match promoted observations")


def _request(
    method: str,
    path: str,
    *,
    body: Any = None,
    headers: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "authority": AUTHORITY,
        "body": body,
        "headers": {"x-publishable-api-key": PUBLISHABLE_KEY} if headers is None else headers,
        "method": method,
        "path": path,
        "query": {} if query is None else query,
        "scheme": "https",
    }


def _step(
    step_id: str,
    operation_id: str,
    request: dict[str, Any],
    status: int,
    covers: list[tuple[str, str]],
    *,
    decision: str,
    state_change: bool | None = None,
) -> dict[str, Any]:
    result = {
        "covers": [
            {"behavior": behavior, "operation_id": covered_operation}
            for covered_operation, behavior in covers
        ],
        "expected_decision_kind": decision,
        "expected_status_code": status,
        "operation_id": operation_id,
        "receipt_predicate_refs": ["response_is_object", "call_was_recorded"],
        "request": request,
        "step_id": step_id,
    }
    if state_change is not None:
        result["expected_state_change"] = state_change
    return result


def _operation(
    operation_id: str,
    method: str,
    path_template: str,
    *,
    mutability: str,
    behaviors: list[str],
    effects: list[str],
) -> dict[str, Any]:
    return {
        "behavior_program": "medusa_2_16_0_store_cart_lifecycle_v1",
        "covered_behaviors": behaviors,
        "grounding": {
            "evidence_refs": [
                "medusa_store_cart_g2",
                "medusa_store_cart_provenance",
            ],
            "level": "G2_SELF_HOSTED_REFERENCE",
        },
        "mutability": mutability,
        "native_surface": {
            "authority": AUTHORITY,
            "method": method,
            "path_template": path_template,
            "scheme": "https",
            "type": "http",
        },
        "operation_id": operation_id,
        "rights": {
            "behavior_distribution_basis": "Only self-authored runtime payloads and sanitized factual measurements from an exact MIT-licensed Medusa 2.16.0 self-hosted reference are distributed.",
            "distribution_label": "public",
        },
        "state_effects": effects,
    }


def _claims(evidence: Path) -> dict[str, Any]:
    observed_at, valid_through, _ = _evidence_window(evidence)
    create_body = {"email": "admission@example.test", "region_id": "region_datalox_us"}
    add_body = {"variant_id": "variant_datalox_pagination_001", "quantity": 1}
    update_body = {"quantity": 3}
    steps = [
        _step(
            "missing_publishable_key",
            LIST,
            _request("GET", "/store/products", headers={}, query={"limit": "10", "offset": "0"}),
            400,
            [(LIST, "failure")],
            decision="deny",
        ),
        _step(
            "invalid_publishable_key",
            LIST,
            _request(
                "GET",
                "/store/products",
                headers={"x-publishable-api-key": "pk_invalid"},
                query={"limit": "10", "offset": "0"},
            ),
            400,
            [(LIST, "failure")],
            decision="deny",
        ),
        _step(
            "initial_product_read",
            LIST,
            _request("GET", "/store/products", query={"limit": "10", "offset": "0"}),
            200,
            [(LIST, "success")],
            decision="replay",
        ),
        _step(
            "product_page",
            LIST,
            _request("GET", "/store/products", query={"limit": "10", "offset": "20"}),
            200,
            [(LIST, "pagination")],
            decision="replay",
        ),
        _step(
            "create_cart",
            CREATE,
            _request("POST", "/store/carts", body=create_body),
            200,
            [(CREATE, "success")],
            decision="shadow_write",
            state_change=True,
        ),
        _step(
            "duplicate_create",
            CREATE,
            _request("POST", "/store/carts", body=create_body),
            200,
            [(CREATE, "duplicate")],
            decision="shadow_write",
            state_change=True,
        ),
        _step(
            "create_missing_publishable_key",
            CREATE,
            _request("POST", "/store/carts", body=create_body, headers={}),
            400,
            [(CREATE, "failure")],
            decision="deny",
            state_change=False,
        ),
        _step(
            "create_invalid_publishable_key",
            CREATE,
            _request(
                "POST",
                "/store/carts",
                body=create_body,
                headers={"x-publishable-api-key": "pk_invalid"},
            ),
            400,
            [(CREATE, "failure")],
            decision="deny",
            state_change=False,
        ),
        _step(
            "create_invalid_region",
            CREATE,
            _request("POST", "/store/carts", body={"region_id": "region_missing"}),
            404,
            [(CREATE, "failure")],
            decision="deny",
            state_change=False,
        ),
        _step(
            "create_readback",
            RETRIEVE,
            _request("GET", "/store/carts/cart_datalox_000001"),
            200,
            [(CREATE, "readback"), (RETRIEVE, "success")],
            decision="replay",
        ),
        _step(
            "retrieve_missing_cart",
            RETRIEVE,
            _request("GET", "/store/carts/cart_missing"),
            404,
            [(RETRIEVE, "failure")],
            decision="deny",
        ),
        _step(
            "add_line_item",
            ADD,
            _request("POST", "/store/carts/cart_datalox_000001/line-items", body=add_body),
            200,
            [(ADD, "success")],
            decision="shadow_write",
            state_change=True,
        ),
        _step(
            "duplicate_add",
            ADD,
            _request("POST", "/store/carts/cart_datalox_000001/line-items", body=add_body),
            200,
            [(ADD, "duplicate")],
            decision="shadow_write",
            state_change=True,
        ),
        _step(
            "invalid_variant_add",
            ADD,
            _request(
                "POST",
                "/store/carts/cart_datalox_000001/line-items",
                body={"variant_id": "variant_missing", "quantity": 1},
            ),
            400,
            [(ADD, "failure")],
            decision="deny",
            state_change=False,
        ),
        _step(
            "add_readback",
            RETRIEVE,
            _request("GET", "/store/carts/cart_datalox_000001"),
            200,
            [(ADD, "readback")],
            decision="replay",
        ),
        _step(
            "update_line_item",
            UPDATE,
            _request(
                "POST",
                "/store/carts/cart_datalox_000001/line-items/cali_datalox_000001",
                body=update_body,
            ),
            200,
            [(UPDATE, "success")],
            decision="shadow_write",
            state_change=True,
        ),
        _step(
            "duplicate_update",
            UPDATE,
            _request(
                "POST",
                "/store/carts/cart_datalox_000001/line-items/cali_datalox_000001",
                body=update_body,
            ),
            200,
            [(UPDATE, "duplicate")],
            decision="replay",
            state_change=False,
        ),
        _step(
            "invalid_quantity_update",
            UPDATE,
            _request(
                "POST",
                "/store/carts/cart_datalox_000001/line-items/cali_datalox_000001",
                body={"quantity": "three"},
            ),
            400,
            [(UPDATE, "failure")],
            decision="deny",
            state_change=False,
        ),
        _step(
            "update_readback",
            RETRIEVE,
            _request("GET", "/store/carts/cart_datalox_000001"),
            200,
            [(UPDATE, "readback")],
            decision="replay",
        ),
        _step(
            "delete_line_item",
            DELETE,
            _request("DELETE", "/store/carts/cart_datalox_000001/line-items/cali_datalox_000001"),
            200,
            [(DELETE, "success")],
            decision="shadow_write",
            state_change=True,
        ),
        _step(
            "duplicate_delete",
            DELETE,
            _request("DELETE", "/store/carts/cart_datalox_000001/line-items/cali_datalox_000001"),
            200,
            [(DELETE, "duplicate")],
            decision="replay",
            state_change=False,
        ),
        _step(
            "delete_from_missing_cart",
            DELETE,
            _request("DELETE", "/store/carts/cart_missing/line-items/cali_missing"),
            500,
            [(DELETE, "failure")],
            decision="deny",
            state_change=False,
        ),
        _step(
            "delete_readback",
            RETRIEVE,
            _request("GET", "/store/carts/cart_datalox_000001"),
            200,
            [(DELETE, "readback")],
            decision="replay",
        ),
    ]
    return {
        "schema_version": "datalox_provider_operation_claims_v1",
        "provider_id": PROVIDER_ID,
        "bundle_version": BUNDLE_VERSION,
        "evidence_sources": [
            {
                "evidence_id": "medusa_store_cart_g2",
                "artifact_ref": "observations.json",
                "artifact_sha256": _sha256(evidence / "observations.json"),
                "grounding_level": "G2_SELF_HOSTED_REFERENCE",
                "observed_at": observed_at,
                "valid_through": valid_through,
                "distribution_label": "public",
                "rights_basis": "Self-authored sanitized factual measurements from an exact local MIT-licensed Medusa 2.16.0 release; no credentials, raw payload bodies, provider-generated ids, or tenant ids are retained.",
            },
            {
                "evidence_id": "medusa_store_cart_provenance",
                "artifact_ref": "provenance.json",
                "artifact_sha256": _sha256(evidence / "provenance.json"),
                "grounding_level": "G2_SELF_HOSTED_REFERENCE",
                "observed_at": observed_at,
                "valid_through": valid_through,
                "distribution_label": "public",
                "rights_basis": "Self-authored provenance manifest containing only release metadata, exact source digests, and retention declarations for an MIT-licensed local reference.",
            },
        ],
        "operations": [
            _operation(
                LIST,
                "GET",
                "/store/products",
                mutability="read",
                behaviors=["success", "failure", "pagination"],
                effects=[],
            ),
            _operation(
                CREATE,
                "POST",
                "/store/carts",
                mutability="write",
                behaviors=["success", "failure", "duplicate", "readback"],
                effects=["cart_created"],
            ),
            _operation(
                RETRIEVE,
                "GET",
                "/store/carts/{cart_id}",
                mutability="read",
                behaviors=["success", "failure"],
                effects=[],
            ),
            _operation(
                ADD,
                "POST",
                "/store/carts/{cart_id}/line-items",
                mutability="write",
                behaviors=["success", "failure", "duplicate", "readback"],
                effects=["line_item_created_or_incremented"],
            ),
            _operation(
                UPDATE,
                "POST",
                "/store/carts/{cart_id}/line-items/{line_item_id}",
                mutability="write",
                behaviors=["success", "failure", "duplicate", "readback"],
                effects=["line_item_quantity_set"],
            ),
            _operation(
                DELETE,
                "DELETE",
                "/store/carts/{cart_id}/line-items/{line_item_id}",
                mutability="write",
                behaviors=["success", "failure", "duplicate", "readback"],
                effects=["line_item_removed_if_present"],
            ),
        ],
        "provider_invariants": [
            {
                "expected": "region_datalox_us",
                "operator": "equals",
                "pointer": "/state/region_id",
                "predicate_id": "region_seed_is_fixed",
                "source": "provider_state",
            },
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
        "behavior_probes": [
            {"probe_id": "medusa_store_cart_lifecycle", "reset_profile": "default", "steps": steps}
        ],
    }


def _world_manifest(source_world: Path) -> dict[str, Any]:
    return {
        "schema_version": "datalox_world_bundle_v1",
        "world_id": "medusa_store_cart_v0",
        "bundle_version": BUNDLE_VERSION,
        "implementation": "world/v1/implementation.py:create_world",
        "episodes_path": "world/v1/episodes.jsonl",
        "roles_path": "world/v1/roles.json",
        "tools_path": "world/v1/tools.json",
        "verifier_path": "world/v1/verifier.json",
        "sources_path": "world/v1/sources.json",
        "default_actor_role": "store_operator",
        "required_runtime_capabilities": ["actors", "role_scoped_tools", "transactions"],
        "trajectory_paths": [],
        "content_hashes": compute_bundle_hashes(source_world),
    }


def build(source: Path, output: Path) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"output already exists: {output}")
    source = source.resolve(strict=True)
    _validate_public_grounding_evidence(source / "evidence")
    output.mkdir(parents=True)
    shutil.copytree(
        source / "evidence",
        output / "evidence",
        ignore=shutil.ignore_patterns("operation-claims.json", "restricted"),
    )
    shutil.copytree(
        source / "source-world",
        output / "source-world",
        ignore=shutil.ignore_patterns("manifest.json", "__pycache__", "*.pyc"),
    )
    manifest = output / "source-world" / "world" / "manifest.json"
    _write_json(manifest, _world_manifest(output / "source-world"))
    validate_world_bundle(output / "source-world")
    claims_path = output / "evidence" / "operation-claims.json"
    _write_json(claims_path, _claims(output / "evidence"))
    identity_policy = output / "identity-policy.json"
    _write_json(identity_policy, _identity_policy())
    runtime = output / "provider-runtime"
    build_provider_runtime_from_world(
        source_world_dir=output / "source-world",
        output_dir=runtime,
        provider_id=PROVIDER_ID,
        authorities=(AUTHORITY,),
        episode_id=EPISODE_ID,
        identity_policy_path=identity_policy,
    )
    admission_path = output / "provider-admission.json"
    _, _, admitted_at = _evidence_window(output / "evidence")
    admission = admit_provider_runtime(
        bundle_dir=runtime,
        claims_path=claims_path,
        output_path=admission_path,
        admitted_at=admitted_at,
    )
    release = build_provider_release(
        profiles=(
            ProviderReleaseProfileInput(
                profile_id="default", bundle_dir=runtime, admission_path=admission_path
            ),
        ),
        release_version=BUNDLE_VERSION,
        output_dir=output / "provider-release",
    )
    differential = _lifecycle_checker().check(output)
    _write_json(output / "evidence" / "differential-report.json", differential)
    return {
        "admission_sha256": admission.sha256,
        "output": str(output),
        "release_manifest_digest": release.manifest_descriptor["digest"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.out), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
