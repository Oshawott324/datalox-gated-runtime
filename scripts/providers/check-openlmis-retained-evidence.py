#!/usr/bin/env python3
"""Validate retained OpenLMIS behavior evidence without contacting OpenLMIS."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "envs/openlmis_supply_chain_v0/evidence/behavior_harvest"
RESTRICTED = EVIDENCE / "restricted"
INVENTORY = RESTRICTED / "inventory.json"
sys.path.insert(0, str(ROOT / "src"))

from datalox_gated_runtime.behavior_harvest import (  # noqa: E402
    compile_reference_trace,
    current_engine_identity,
    load_connector,
    run_compiled_behavior_trace,
)
from datalox_gated_runtime.engineering_proof import (  # noqa: E402
    PathPrefixMapping,
    PrincipalBoundTraceTarget,
    PrincipalMapping,
    StateRecordOverride,
    StaticValueMapping,
    WorldBundleTraceTarget,
    WorldTargetSpec,
    principal_bindings_from_recipe_steps,
)

GENERIC_OPERATIONS = {
    "notification_update_contact": "notification.update_contact_details",
    "requisition_approve": "requisition.approve",
    "requisition_authorize": "requisition.authorize",
    "requisition_initiate": "requisition.initiate",
    "requisition_reject": "requisition.reject",
    "requisition_skip": "requisition.skip",
    "requisition_submit": "requisition.submit",
    "stock_create_event": "stock.create_event",
    "stock_create_physical_inventory": "stock.create_physical_inventory",
    "stock_delete_physical_inventory": "stock.delete_physical_inventory",
    "stock_update_physical_inventory": "stock.update_physical_inventory",
}
WORLD = ROOT / "envs/openlmis_supply_chain_v0"
EPISODE_ID = "openlmis-supply-chain-001"
PROVIDER_ADMIN_USER_ID = "a337ec45-31a0-4f2b-9b2e-a105c4b669bb"
WORLD_ADMIN_USER_ID = "00000000-0000-4000-8000-000000000001"


def _principal_mappings(name: str) -> tuple[PrincipalMapping, ...]:
    administrator_role = (
        "program_authorizer" if name == "requisition_authorize" else "administrator"
    )
    srmanager_role = "stock_manager" if name.startswith("stock_") else "facility_clerk"
    return (
        PrincipalMapping("administrator", "openlmis-administrator", administrator_role),
        PrincipalMapping("srmanager2", "openlmis-srmanager2", srmanager_role),
        PrincipalMapping("psupervisor", "openlmis-psupervisor", "program_approver"),
    )


def _world_target_spec(name: str) -> WorldTargetSpec:
    static_mappings: tuple[StaticValueMapping, ...] = ()
    state_overrides: tuple[StateRecordOverride, ...] = ()
    if name == "notification_update_contact":
        static_mappings = (StaticValueMapping(PROVIDER_ADMIN_USER_ID, WORLD_ADMIN_USER_ID),)
        state_overrides = (
            StateRecordOverride(
                collection="contact_details",
                record_id=WORLD_ADMIN_USER_ID,
                value={
                    "allowNotify": True,
                    "emailDetails": {
                        "email": "administrator@openlmis.org",
                        "emailVerified": True,
                    },
                    "phoneNumber": None,
                    "referenceDataUserId": WORLD_ADMIN_USER_ID,
                },
            ),
        )
    return WorldTargetSpec(
        target_id="openlmis_supply_chain_local_world",
        target_version="1.0.0",
        episode_id=EPISODE_ID,
        principal_mappings=_principal_mappings(name),
        path_mappings=(PathPrefixMapping("/", "/"),),
        static_value_mappings=static_mappings,
        state_record_overrides=state_overrides,
    )


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"{_relative(path)} must contain an object")
    return value


def _sentinel_secrets(connector_path: Path) -> dict[str, bytes]:
    connector = load_connector(connector_path, expected_sha256=_digest(connector_path)).value
    return {
        item.name: f"offline-retained-evidence-sentinel-{item.name}".encode()
        for item in connector.auth.secret_sources
    }


def _static_inputs(capture: dict[str, Any]) -> tuple[dict[str, Path], dict[str, str]]:
    by_digest = {
        _digest(path): path for path in sorted((RESTRICTED / "static_inputs").glob("*.json"))
    }
    paths: dict[str, Path] = {}
    digests: dict[str, str] = {}
    for receipt in capture["static_input_receipts"]:
        input_id = receipt["input_id"]
        digest = receipt["body_sha256"]
        try:
            paths[input_id] = by_digest[digest]
        except KeyError as error:
            raise RuntimeError(f"retained static input is missing: {input_id} {digest}") from error
        digests[input_id] = digest
    return paths, digests


def _generic_rows() -> list[dict[str, Any]]:
    connector_paths = sorted((RESTRICTED / "connectors").glob("*.json"))
    connectors = {_digest(path): path for path in connector_paths}
    rows: list[dict[str, Any]] = []
    for name, operation_id in sorted(GENERIC_OPERATIONS.items()):
        capture_path = RESTRICTED / "captures" / f"{name}.capture_v1.json"
        recipe_path = RESTRICTED / "recipes" / f"{name}.recipe_v1.json"
        capture = _json(capture_path)
        connector_digest = capture["connector_sha256"]
        try:
            connector_path = connectors[connector_digest]
        except KeyError as error:
            raise RuntimeError(f"connector missing for {name}: {connector_digest}") from error
        static_paths, static_digests = _static_inputs(capture)
        trace = compile_reference_trace(
            capture_path=capture_path,
            expected_capture_sha256=_digest(capture_path),
            connector_path=connector_path,
            expected_connector_sha256=connector_digest,
            recipe_path=recipe_path,
            expected_recipe_sha256=capture["recipe_sha256"],
            expected_engine=current_engine_identity(),
            sensitive_values=_sentinel_secrets(connector_path),
            static_input_paths=static_paths,
            expected_static_input_sha256=static_digests,
        )
        if not capture.get("complete") or not any(
            step.operation_id == operation_id for step in trace.steps
        ):
            raise RuntimeError(f"capture does not contain its selected operation: {name}")
        target = WorldBundleTraceTarget(env_dir=WORLD, spec=_world_target_spec(name))
        try:
            report = run_compiled_behavior_trace(
                target=PrincipalBoundTraceTarget(
                    target=target,
                    bindings=principal_bindings_from_recipe_steps(trace.recipe.steps),
                ),
                capture_path=capture_path,
                expected_capture_sha256=_digest(capture_path),
                connector_path=connector_path,
                expected_connector_sha256=connector_digest,
                recipe_path=recipe_path,
                expected_recipe_sha256=capture["recipe_sha256"],
                expected_engine=current_engine_identity(),
                sensitive_values=_sentinel_secrets(connector_path),
                static_input_paths=static_paths,
                expected_static_input_sha256=static_digests,
            )
        finally:
            target.close()
        rows.append(
            {
                "operation_id": operation_id,
                "classification": "generic_reloadable_complete",
                "capture_path": _relative(capture_path),
                "capture_sha256": _digest(capture_path),
                "connector_path": _relative(connector_path),
                "connector_sha256": connector_digest,
                "recipe_path": _relative(recipe_path),
                "recipe_sha256": capture["recipe_sha256"],
                "compiled_step_count": len(trace.steps),
                "differential": {
                    "status": "passed" if report.passed else "executed_mismatch",
                    "report": report.to_dict(),
                },
            }
        )
    return rows


def _scan_forbidden(value: Any, *, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = key.lower()
            if lowered in {"authorization", "cookie", "set-cookie", "access_token", "password"}:
                raise RuntimeError(f"forbidden retained evidence key at {path}/{key}")
            _scan_forbidden(item, path=f"{path}/{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_forbidden(item, path=f"{path}/{index}")
    elif isinstance(value, str) and ("/private/tmp" in value or "/tmp/" in value):
        raise RuntimeError(f"temporary path leaked into retained evidence at {path}")


def _direct_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((RESTRICTED / "direct_sequences").glob("*.sequence_v1.json")):
        value = _json(path)
        _scan_forbidden(value)
        if (
            value.get("schema_id") != "datalox_provider_direct_http_sequence_v1"
            or value.get("complete") is not False
            or value.get("claim") != "direct_observed_partial"
        ):
            raise RuntimeError(f"invalid direct sequence contract: {_relative(path)}")
        roles = {step.get("role") for step in value.get("steps", [])}
        if "success" not in roles or not any(role.startswith("resulting_") for role in roles):
            raise RuntimeError(f"direct sequence lacks success/resulting state: {_relative(path)}")
        for step in value["steps"]:
            for side in ("request", "response"):
                payload = step[side]
                encoded = payload.get("body_base64")
                if encoded is None:
                    continue
                raw = base64.b64decode(encoded, validate=True)
                if payload.get("body_bytes") != len(raw) or payload.get(
                    "body_sha256"
                ) != _digest_bytes(raw):
                    raise RuntimeError(
                        f"embedded body digest mismatch: {_relative(path)} {step['step_id']} {side}"
                    )
        rows.append(
            {
                "operation_id": value["operation_id"],
                "classification": "direct_observed_partial",
                "sequence_path": _relative(path),
                "sequence_sha256": _digest(path),
                "step_count": len(value["steps"]),
                "differential": {
                    "status": "differential_not_executable",
                    "reason_code": "direct_sequence_not_compiler_capture",
                    "reason": (
                        "The sequence predates a complete generic capture and is retained as "
                        "direct HTTP evidence; it is not relabeled as a compiler trace."
                    ),
                },
            }
        )
    return rows


def _journal_records(name: str) -> list[dict[str, Any]]:
    path = RESTRICTED / "failures" / name
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _fresh_reset_observations() -> list[dict[str, Any]]:
    specs = (
        (
            "requisition.update",
            "requisition_update_fresh_reset.partial.jsonl",
            "requisition_update_fresh_reset.after.json",
            500,
            "INITIATED",
            "provider_native_reset_failure",
        ),
        (
            "requisition.skip",
            "requisition_skip_fresh_reset.partial.jsonl",
            "requisition_skip_fresh_reset.after.json",
            500,
            "INITIATED",
            "provider_native_reset_failure",
        ),
        (
            "fulfillment.create_requisitionless_order",
            "fulfillment_create_order_fresh_reset.partial.jsonl",
            "fulfillment_create_order_fresh_reset.after.json",
            500,
            None,
            "provider_native_reset_failure",
        ),
        (
            "notification.create_notification",
            "notification_create_empty_body.partial.jsonl",
            "notification_create_empty_body.after.json",
            None,
            None,
            "generic_capture_engine_limitation",
        ),
    )
    rows: list[dict[str, Any]] = []
    for operation_id, journal_name, after_name, status, expected_state, classification in specs:
        journal_path = RESTRICTED / "failures" / journal_name
        after_path = RESTRICTED / "failures" / after_name
        records = _journal_records(journal_name)
        terminal = [record for record in records if record.get("state") == "terminal_unknown"]
        if len(terminal) != 1:
            raise RuntimeError(f"failure journal lacks one terminal_unknown: {journal_name}")
        validated = [
            record
            for record in records
            if record.get("state") == "response_validated" and record.get("status_code") == status
        ]
        if status is not None and not validated:
            raise RuntimeError(f"failure journal lacks expected {status}: {journal_name}")
        after = _json(after_path)
        if expected_state is not None and after.get("status") != expected_state:
            raise RuntimeError(f"failure post-read state changed: {after_name}")
        before_hashes = [
            record.get("body_sha256")
            for record in records
            if record.get("state") == "response_validated" and record.get("status_code") == 200
        ]
        post_read_unchanged = _digest(after_path) in before_hashes
        if classification == "provider_native_reset_failure" and not post_read_unchanged:
            raise RuntimeError(f"failure post-read is not byte-identical to pre-read: {after_name}")
        rows.append(
            {
                "operation_id": operation_id,
                "classification": classification,
                "observed_status_code": status,
                "post_read_unchanged": post_read_unchanged,
                "journal_path": _relative(journal_path),
                "journal_sha256": _digest(journal_path),
                "post_read_path": _relative(after_path),
                "post_read_sha256": _digest(after_path),
            }
        )
    return rows


def _state_reset() -> dict[str, Any]:
    reset_dir = RESTRICTED / "reset"
    values = {
        path.name: _json(path)
        for path in sorted(reset_dir.glob("*.json"))
        if path.name != "reset_admin_roles.json"
    }
    admin_roles = json.loads((reset_dir / "reset_admin_roles.json").read_bytes())
    checks = {
        "generated_order_removed": values["reset_order_generated.json"].get("messageKey")
        == "fulfillment.error.order.notFound",
        "generated_shipment_removed": values["reset_shipment_generated.json"].get("messageKey")
        == "fulfillment.error.shipment.notFound",
        "baseline_pod_restored": values["reset_pod_baseline.json"].get("status") == "INITIATED",
        "baseline_order_restored": values["reset_pod_order_baseline.json"].get("status")
        == "IN_ROUTE",
        "baseline_requisition_restored": values["reset_req6167_probe.json"].get("status")
        == "INITIATED",
        "generated_destination_removed": values["reset_wh01_destinations.json"].get("totalElements")
        == 0,
        "generated_role_assignment_removed": not any(
            isinstance(item, dict)
            and isinstance(item.get("role"), dict)
            and item["role"].get("name") == "Warehouse Clerk"
            and isinstance(item.get("facility"), dict)
            and item["facility"].get("code") == "HC01"
            for item in admin_roles
        ),
    }
    if not all(checks.values()):
        raise RuntimeError(f"functional reset evidence failed: {checks}")
    return {
        "classification": "state_reset_observed",
        "method": "docker-compose down -v followed by exact pinned demo-data recreation",
        "passed": True,
        "checks": checks,
        "artifacts": {
            name: {
                "path": _relative(reset_dir / name),
                "sha256": _digest(reset_dir / name),
            }
            for name in sorted([*values, "reset_admin_roles.json"])
        },
    }


def compute_inventory() -> dict[str, Any]:
    operations = sorted(_generic_rows() + _direct_rows(), key=lambda row: row["operation_id"])
    if len(operations) != 20 or len({row["operation_id"] for row in operations}) != 20:
        raise RuntimeError("retained evidence must cover exactly 20 unique selected writes")
    counts: dict[str, int] = {}
    for row in operations:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    fresh_reset = _fresh_reset_observations()
    return {
        "schema_id": "datalox_openlmis_retained_evidence_inventory_v1",
        "environment_id": "openlmis_supply_chain_v0",
        "provider_id": "openlmis",
        "selected_write_count": 20,
        "classification_counts": dict(sorted(counts.items())),
        "claim_boundary": (
            "Generic reloadability, exact direct provider observation, and executable local "
            "differential equivalence are separate claims. Per-step principals are executed; "
            "only rows with a passed differential claim exact behavior equivalence."
        ),
        "state_reset": _state_reset(),
        "functional_reset_equivalence": {
            "passed": False,
            "reason_code": "fresh_reset_behavior_differs_from_observed_provider_behavior",
            "reason": (
                "Fixture and generated-state restoration passed, but fresh-reset behavioral "
                "probes for requisition update, requisition skip, and requisitionless-order "
                "creation returned provider 500 responses where earlier runs observed successful "
                "writes. State restoration is not functional reset equivalence."
            ),
            "affected_operations": sorted(
                row["operation_id"]
                for row in fresh_reset
                if row["classification"] == "provider_native_reset_failure"
            ),
        },
        "fresh_reset_observations": fresh_reset,
        "operations": operations,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-inventory", action="store_true")
    args = parser.parse_args()
    value = compute_inventory()
    body = json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"
    if args.write_inventory:
        INVENTORY.write_text(body, encoding="utf-8")
        print(f"wrote {_relative(INVENTORY)}")
        return 0
    if not INVENTORY.is_file() or INVENTORY.read_text(encoding="utf-8") != body:
        print("OpenLMIS retained evidence inventory is stale.", file=sys.stderr)
        return 1
    print(
        "OpenLMIS retained evidence valid: "
        f"{value['classification_counts']} "
        "(20 selected writes; 11 differentials executed; 1 exact pass)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
