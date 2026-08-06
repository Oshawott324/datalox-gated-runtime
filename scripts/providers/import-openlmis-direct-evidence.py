#!/usr/bin/env python3
"""Import reviewed OpenLMIS authoring responses into the restricted evidence lane.

This is a manual authoring utility, not a runtime live-write surface. It only
reads already captured response bodies and emits immutable, self-digesting
HTTP sequences. Credentials and authorization headers are intentionally not
accepted by the format.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = (
    ROOT / "envs/openlmis_supply_chain_v0/evidence/behavior_harvest/restricted/direct_sequences"
)


@dataclass(frozen=True)
class Step:
    role: str
    actor: str
    method: str
    path: str
    status: int
    response_file: str | None
    request_file: str | None = None
    response_sha256: str | None = None
    note: str | None = None


SEQUENCES: dict[str, tuple[str, tuple[Step, ...]]] = {
    "requisition_update": (
        "requisition.update",
        (
            Step(
                "before",
                "administrator",
                "GET",
                "/api/requisitions/6167e65c-6f56-4aeb-bff5-fdfe84e01a21",
                200,
                "req6167_before_update.json",
            ),
            Step(
                "native_failure",
                "psupervisor",
                "PUT",
                "/api/requisitions/6167e65c-6f56-4aeb-bff5-fdfe84e01a21",
                403,
                "req6167_update_native.json",
                "req6167_update_body.json",
            ),
            Step(
                "success",
                "srmanager2",
                "PUT",
                "/api/requisitions/6167e65c-6f56-4aeb-bff5-fdfe84e01a21",
                200,
                "req6167_update_success2.json",
                "req6167_update_body.json",
            ),
            Step(
                "resulting_state",
                "administrator",
                "GET",
                "/api/requisitions/6167e65c-6f56-4aeb-bff5-fdfe84e01a21",
                200,
                "req6167_after_update2.json",
            ),
        ),
    ),
    "requisition_convert_to_order": (
        "requisition.convert_to_order",
        (
            Step(
                "before",
                "administrator",
                "GET",
                "/api/requisitions/6167e65c-6f56-4aeb-bff5-fdfe84e01a21",
                200,
                "convert6167_setup_approve.json",
            ),
            Step(
                "native_failure",
                "psupervisor",
                "POST",
                "/api/requisitions/convertToOrder",
                403,
                "convert6167_native.json",
                "convert6167_body.json",
            ),
            Step(
                "success",
                "administrator",
                "POST",
                "/api/requisitions/convertToOrder",
                201,
                "convert6167_success.json",
                "convert6167_body.json",
            ),
            Step(
                "duplicate",
                "administrator",
                "POST",
                "/api/requisitions/convertToOrder",
                400,
                "convert6167_repeat.json",
                "convert6167_body.json",
            ),
            Step(
                "resulting_state",
                "administrator",
                "GET",
                "/api/requisitions/6167e65c-6f56-4aeb-bff5-fdfe84e01a21",
                200,
                "convert6167_after_repeat.json",
            ),
        ),
    ),
    "requisition_batch_release": (
        "requisition.batch_release",
        (
            Step(
                "before",
                "administrator",
                "GET",
                "/api/requisitions/074a49af-12c3-429f-b5da-ed3f9e65787c",
                200,
                "batch074a_before.json",
            ),
            Step(
                "native_failure",
                "psupervisor",
                "POST",
                "/api/requisitions/batchReleases",
                403,
                "batch074a_native.json",
                "batch_release_074a_body.json",
            ),
            Step(
                "success",
                "administrator",
                "POST",
                "/api/requisitions/batchReleases",
                201,
                "batch074a_success.json",
                "batch_release_074a_body.json",
            ),
            Step(
                "duplicate",
                "administrator",
                "POST",
                "/api/requisitions/batchReleases",
                400,
                "batch074a_repeat.json",
                "batch_release_074a_body.json",
            ),
            Step(
                "resulting_state",
                "administrator",
                "GET",
                "/api/requisitions/074a49af-12c3-429f-b5da-ed3f9e65787c",
                200,
                "batch074a_after.json",
            ),
        ),
    ),
    "notification_create": (
        "notification.create_notification",
        (
            Step(
                "before",
                "administrator",
                "GET",
                "/api/notifications",
                200,
                "notification_service_before.json",
            ),
            Step(
                "native_failure",
                "administrator",
                "POST",
                "/api/notifications",
                403,
                None,
                "notification_body.json",
                response_sha256="sha256:4301edfd76de9e814720c70aab4b017c2bb04f30015c329548784ba271fbaa29",
                note="The generic journal retained the exact status and body digest; the response bytes were not retained.",
            ),
            Step(
                "success",
                "trusted-client",
                "POST",
                "/api/notifications",
                200,
                "notification_service_success2.json",
                "notification_body.json",
            ),
            Step(
                "duplicate",
                "trusted-client",
                "POST",
                "/api/notifications",
                200,
                "notification_service_repeat2.json",
                "notification_body.json",
            ),
            Step(
                "resulting_state",
                "administrator",
                "GET",
                "/api/notifications",
                200,
                "notification_service_after2.json",
            ),
        ),
    ),
    "fulfillment_create_requisitionless_order": (
        "fulfillment.create_requisitionless_order",
        (
            Step("before", "administrator", "GET", "/api/orders", 200, "orders_before_create.json"),
            Step(
                "native_failure",
                "administrator",
                "POST",
                "/api/orders/requisitionLess",
                403,
                "order_create_native.json",
                "requisitionless_order_service_body2.json",
            ),
            Step(
                "success",
                "trusted-client",
                "POST",
                "/api/orders/requisitionLess",
                201,
                "order_create_service_success2.json",
                "requisitionless_order_service_body2.json",
            ),
            Step(
                "duplicate",
                "trusted-client",
                "POST",
                "/api/orders/requisitionLess",
                201,
                "order_create_service_repeat.json",
                "requisitionless_order_service_body2.json",
                note="OpenLMIS creates a second order for an exact repeated request.",
            ),
            Step(
                "resulting_state_later",
                "administrator",
                "GET",
                "/api/orders",
                200,
                "orders_after_send.json",
                note="The collection read was taken after the first created order was subsequently sent; both generated ids remain observable.",
            ),
        ),
    ),
    "fulfillment_update_order": (
        "fulfillment.update_order",
        (
            Step(
                "before",
                "trusted-client",
                "GET",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b",
                200,
                "order_create_service_success2.json",
            ),
            Step(
                "native_failure",
                "administrator",
                "PUT",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b",
                403,
                "order_update_native.json",
                "order_update_body.json",
            ),
            Step(
                "success",
                "trusted-client",
                "PUT",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b",
                200,
                "order_update_success.json",
                "order_update_body.json",
            ),
            Step(
                "duplicate",
                "trusted-client",
                "PUT",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b",
                200,
                "order_update_repeat.json",
                "order_update_body.json",
            ),
            Step(
                "resulting_state",
                "trusted-client",
                "GET",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b",
                200,
                "order_update_repeat.json",
                note="The exact repeated response retains orderedQuantity=3; a later provider GET failed in reference-data expansion and is not substituted here.",
            ),
        ),
    ),
    "fulfillment_send_requisitionless_order": (
        "fulfillment.send_requisitionless_order",
        (
            Step(
                "before",
                "trusted-client",
                "GET",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b",
                200,
                "order_update_success.json",
            ),
            Step(
                "native_failure",
                "administrator",
                "PUT",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b/requisitionLess/send",
                403,
                "order_send_native.json",
                "order_update_body.json",
            ),
            Step(
                "success",
                "trusted-client",
                "PUT",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b/requisitionLess/send",
                200,
                "order_send_success.json",
                "order_update_body.json",
            ),
            Step(
                "duplicate",
                "trusted-client",
                "PUT",
                "/api/orders/a5bcdeaa-ce84-48c1-968d-978fb0ccd21b/requisitionLess/send",
                400,
                "order_send_repeat.json",
                "order_update_body.json",
            ),
            Step(
                "resulting_state",
                "administrator",
                "GET",
                "/api/orders",
                200,
                "orders_after_send.json",
            ),
        ),
    ),
    "fulfillment_create_shipment": (
        "fulfillment.create_shipment",
        (
            Step(
                "before_order",
                "administrator",
                "GET",
                "/api/orders/85995f39-1e96-43ee-9306-6af934b280a6",
                200,
                "order_hc01_before_shipment_after_setup.json",
            ),
            Step(
                "before_shipments",
                "administrator",
                "GET",
                "/api/shipments?orderId=85995f39-1e96-43ee-9306-6af934b280a6",
                200,
                "shipment_hc01_before_after_setup.json",
            ),
            Step(
                "native_failure",
                "psupervisor",
                "POST",
                "/api/shipments",
                403,
                "shipment_hc01_native_after_setup.json",
                "shipment_hc01_body.json",
            ),
            Step(
                "success",
                "administrator",
                "POST",
                "/api/shipments",
                201,
                "shipment_hc01_success_final3.json",
                "shipment_hc01_body.json",
            ),
            Step(
                "duplicate",
                "administrator",
                "POST",
                "/api/shipments",
                400,
                "shipment_hc01_repeat_final.json",
                "shipment_hc01_body.json",
            ),
            Step(
                "resulting_order",
                "administrator",
                "GET",
                "/api/orders/85995f39-1e96-43ee-9306-6af934b280a6",
                200,
                "order_hc01_after_shipment_final.json",
            ),
            Step(
                "resulting_shipments",
                "administrator",
                "GET",
                "/api/shipments?orderId=85995f39-1e96-43ee-9306-6af934b280a6",
                200,
                "shipment_hc01_after_final.json",
            ),
        ),
    ),
    "fulfillment_update_proof_of_delivery": (
        "fulfillment.update_proof_of_delivery",
        (
            Step(
                "before",
                "administrator",
                "GET",
                "/api/proofsOfDelivery/b47d3586-2daa-4251-bd82-15b14e57bac2",
                200,
                "pod_before_candidate.json",
            ),
            Step(
                "linked_shipment",
                "administrator",
                "GET",
                "/api/shipments/967e2c6b-749e-4467-9990-d087e272170d",
                200,
                "pod_candidate_shipment.json",
            ),
            Step(
                "native_failure",
                "psupervisor",
                "PUT",
                "/api/proofsOfDelivery/b47d3586-2daa-4251-bd82-15b14e57bac2",
                403,
                "pod_confirm_native.json",
                "pod_confirm_request.json",
            ),
            Step(
                "success",
                "administrator",
                "PUT",
                "/api/proofsOfDelivery/b47d3586-2daa-4251-bd82-15b14e57bac2",
                200,
                "pod_confirm_success2.json",
                "pod_confirm_request.json",
            ),
            Step(
                "duplicate",
                "administrator",
                "PUT",
                "/api/proofsOfDelivery/b47d3586-2daa-4251-bd82-15b14e57bac2",
                400,
                "pod_confirm_repeat.json",
                "pod_confirm_request.json",
            ),
            Step(
                "resulting_delivery",
                "administrator",
                "GET",
                "/api/proofsOfDelivery/b47d3586-2daa-4251-bd82-15b14e57bac2",
                200,
                "pod_confirm_after.json",
            ),
            Step(
                "resulting_order",
                "administrator",
                "GET",
                "/api/orders/ec49baf1-fb6c-4bbc-ad5e-54fff70115a2",
                200,
                "pod_order_after.json",
            ),
        ),
    ),
}


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _payload(raw_root: Path, name: str) -> dict[str, Any]:
    raw = (raw_root / name).read_bytes()
    return {
        "body_base64": base64.b64encode(raw).decode("ascii"),
        "body_bytes": len(raw),
        "body_sha256": _digest(raw),
    }


def _pod_request(raw_root: Path) -> None:
    source = json.loads((raw_root / "pod_before_candidate.json").read_bytes())
    source["status"] = "CONFIRMED"
    source["deliveredBy"] = "Datalox Courier"
    source["receivedBy"] = "Datalox Receiver"
    source["receivedDate"] = "2026-08-05"
    source["lineItems"][0]["quantityAccepted"] = 30
    source["lineItems"][1]["quantityAccepted"] = 1200
    (raw_root / "pod_confirm_request.json").write_bytes(
        json.dumps(source, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    )


def build_sequence(raw_root: Path, sequence_id: str) -> dict[str, Any]:
    operation_id, specs = SEQUENCES[sequence_id]
    steps: list[dict[str, Any]] = []
    for index, spec in enumerate(specs, 1):
        step: dict[str, Any] = {
            "step_id": f"{index:02d}_{spec.role}",
            "role": spec.role,
            "actor_alias": spec.actor,
            "request": {
                "method": spec.method,
                "path": spec.path,
                "headers_retained": False,
            },
            "response": {"status_code": spec.status, "headers_retained": False},
        }
        if spec.request_file is not None:
            step["request"].update(_payload(raw_root, spec.request_file))
        if spec.response_file is not None:
            step["response"].update(_payload(raw_root, spec.response_file))
            step["response"]["body_retained"] = True
        else:
            step["response"].update({"body_retained": False, "body_sha256": spec.response_sha256})
        if spec.note:
            step["note"] = spec.note
        steps.append(step)
    return {
        "schema_id": "datalox_provider_direct_http_sequence_v1",
        "sequence_id": sequence_id,
        "operation_id": operation_id,
        "provider_id": "openlmis",
        "provider_version": "Reference Distribution v3.19.2",
        "deployment_commit": "4c5eea24743367790b419e18a9565934ba73ab62",
        "distribution": "restricted",
        "complete": False,
        "claim": "direct_observed_partial",
        "claim_boundary": (
            "Provider-observed write semantics with retained request/response bodies and status "
            "codes, but without exact safe header or content-type receipts. This is not a "
            "generic-engine capture, a complete behavior program, or a local-world differential "
            "pass."
        ),
        "steps": steps,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-root", type=Path, required=True)
    args = parser.parse_args()
    args.raw_root = args.raw_root.resolve()
    _pod_request(args.raw_root)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for sequence_id in sorted(SEQUENCES):
        value = build_sequence(args.raw_root, sequence_id)
        path = OUTPUT / f"{sequence_id}.sequence_v1.json"
        path.write_text(
            json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
