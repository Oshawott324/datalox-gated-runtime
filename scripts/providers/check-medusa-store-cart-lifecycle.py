#!/usr/bin/env python3
"""Differentially check the local Medusa cart lifecycle against retained G2 facts."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import ProviderRuntime

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV = ROOT / "envs" / "medusa_store_cart_v0"
AUTHORITY = "api.medusa.local"
KEY = "pk_datalox_local_store"


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _file_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _request(
    method: str,
    path: str,
    *,
    body: Any = None,
    headers: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
) -> CallRequest:
    return CallRequest(
        method=method,
        scheme="https",
        authority=AUTHORITY,
        path=path,
        query={} if query is None else query,
        headers={"x-publishable-api-key": KEY} if headers is None else headers,
        body=body,
    )


def _state(runtime: ProviderRuntime) -> dict[str, Any]:
    state = runtime.export()["provider_state"].get("state")
    if not isinstance(state, dict):
        raise TypeError("world-backed provider must export an object state")
    return deepcopy(state)


def _call(
    runtime: ProviderRuntime,
    step: str,
    request: CallRequest,
    *,
    expected_status: int,
) -> tuple[Any, dict[str, Any]]:
    before = _state(runtime)
    response = runtime.handle(request)
    after = _state(runtime)
    if response.status_code != expected_status:
        raise AssertionError(
            f"{step}: expected status {expected_status}, received {response.status_code}"
        )
    return response, {
        "step": step,
        "status": response.status_code,
        "state_changed": before != after,
    }


def _cycle(runtime: ProviderRuntime) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    response, row = _call(
        runtime,
        "missing_publishable_key",
        _request("GET", "/store/products", headers={}, query={"limit": "10", "offset": "0"}),
        expected_status=400,
    )
    row["error_type"] = response.body.get("type")
    results.append(row)
    response, row = _call(
        runtime,
        "invalid_publishable_key",
        _request(
            "GET",
            "/store/products",
            headers={"x-publishable-api-key": "pk_invalid"},
            query={"limit": "10", "offset": "0"},
        ),
        expected_status=400,
    )
    row["error_type"] = response.body.get("type")
    results.append(row)
    response, row = _call(
        runtime,
        "initial_product_read",
        _request("GET", "/store/products", query={"limit": "10", "offset": "0"}),
        expected_status=200,
    )
    variant_id = response.body["products"][0]["variants"][0]["id"]
    row["facts"] = {
        "limit_offset_envelope": all(
            key in response.body for key in ("products", "count", "limit", "offset")
        ),
        "published_variant_available": isinstance(variant_id, str),
    }
    results.append(row)
    first_product_ids = {product["id"] for product in response.body["products"]}
    response, row = _call(
        runtime,
        "product_page",
        _request("GET", "/store/products", query={"limit": "10", "offset": "20"}),
        expected_status=200,
    )
    second_product_ids = {product["id"] for product in response.body["products"]}
    row["facts"] = {
        "returned_offset": response.body["offset"],
        "page_size": len(response.body["products"]),
        "distinct_from_first_page": not bool(first_product_ids & second_product_ids),
    }
    results.append(row)

    create = {"email": "differential@example.test", "region_id": "region_datalox_us"}
    response, row = _call(
        runtime,
        "create_missing_publishable_key",
        _request("POST", "/store/carts", body=create, headers={}),
        expected_status=400,
    )
    row["error_type"] = response.body.get("type")
    results.append(row)
    response, row = _call(
        runtime,
        "create_invalid_publishable_key",
        _request(
            "POST",
            "/store/carts",
            body=create,
            headers={"x-publishable-api-key": "pk_invalid"},
        ),
        expected_status=400,
    )
    row["error_type"] = response.body.get("type")
    results.append(row)
    response, row = _call(
        runtime,
        "create_cart",
        _request("POST", "/store/carts", body=create),
        expected_status=200,
    )
    cart_id = response.body["cart"]["id"]
    row["relations"] = {"returned_cart": True, "items_empty": response.body["cart"]["items"] == []}
    results.append(row)
    response, row = _call(
        runtime,
        "duplicate_create",
        _request("POST", "/store/carts", body=create),
        expected_status=200,
    )
    row["relations"] = {
        "same_request_as_create": True,
        "distinct_cart": response.body["cart"]["id"] != cart_id,
    }
    results.append(row)
    response, row = _call(
        runtime,
        "invalid_region_create",
        _request("POST", "/store/carts", body={"region_id": "region_missing"}),
        expected_status=404,
    )
    row["error_type"] = response.body.get("type")
    results.append(row)
    response, row = _call(
        runtime,
        "cart_readback",
        _request("GET", f"/store/carts/{cart_id}"),
        expected_status=200,
    )
    row["relations"] = {"returned_created_cart": response.body["cart"]["id"] == cart_id}
    results.append(row)
    response, row = _call(
        runtime,
        "retrieve_missing_cart",
        _request("GET", "/store/carts/cart_missing"),
        expected_status=404,
    )
    row["error_type"] = response.body.get("type")
    results.append(row)

    add = {"variant_id": variant_id, "quantity": 1}
    response, row = _call(
        runtime,
        "add_line_item",
        _request("POST", f"/store/carts/{cart_id}/line-items", body=add),
        expected_status=200,
    )
    line = response.body["cart"]["items"][0]
    line_id = line["id"]
    row["relations"] = {
        "returned_line": True,
        "quantity": line["quantity"],
        "unit_price": line["unit_price"],
        "cart_total": response.body["cart"]["total"],
    }
    results.append(row)
    response, row = _call(
        runtime,
        "duplicate_add",
        _request("POST", f"/store/carts/{cart_id}/line-items", body=add),
        expected_status=200,
    )
    line = response.body["cart"]["items"][0]
    row["relations"] = {
        "same_request_as_add": True,
        "same_line": line["id"] == line_id,
        "quantity": line["quantity"],
        "unit_price": line["unit_price"],
        "cart_total": response.body["cart"]["total"],
    }
    results.append(row)
    response, row = _call(
        runtime,
        "invalid_variant_add",
        _request(
            "POST",
            f"/store/carts/{cart_id}/line-items",
            body={"variant_id": "variant_missing", "quantity": 1},
        ),
        expected_status=400,
    )
    row["error_type"] = response.body.get("type")
    row["relations"] = {"quantity_after": _state(runtime)["carts"][cart_id]["items"][0]["quantity"]}
    results.append(row)
    response, row = _call(
        runtime,
        "add_readback",
        _request("GET", f"/store/carts/{cart_id}"),
        expected_status=200,
    )
    readback_line = response.body["cart"]["items"][0]
    row["relations"] = {
        "cart": True,
        "line": readback_line["id"] == line_id,
        "quantity": readback_line["quantity"],
    }
    results.append(row)

    update = {"quantity": 3}
    response, row = _call(
        runtime,
        "set_quantity",
        _request("POST", f"/store/carts/{cart_id}/line-items/{line_id}", body=update),
        expected_status=200,
    )
    line = response.body["cart"]["items"][0]
    row["relations"] = {
        "same_line": line["id"] == line_id,
        "quantity": line["quantity"],
        "unit_price": line["unit_price"],
        "cart_total": response.body["cart"]["total"],
    }
    results.append(row)
    response, row = _call(
        runtime,
        "duplicate_set_quantity",
        _request("POST", f"/store/carts/{cart_id}/line-items/{line_id}", body=update),
        expected_status=200,
    )
    line = response.body["cart"]["items"][0]
    row["relations"] = {
        "same_request_as_set": True,
        "same_line": line["id"] == line_id,
        "quantity": line["quantity"],
    }
    results.append(row)
    response, row = _call(
        runtime,
        "invalid_quantity_type",
        _request(
            "POST", f"/store/carts/{cart_id}/line-items/{line_id}", body={"quantity": "three"}
        ),
        expected_status=400,
    )
    row["error_type"] = response.body.get("type")
    row["relations"] = {"quantity_after": _state(runtime)["carts"][cart_id]["items"][0]["quantity"]}
    results.append(row)
    response, row = _call(
        runtime,
        "update_readback",
        _request("GET", f"/store/carts/{cart_id}"),
        expected_status=200,
    )
    readback_line = response.body["cart"]["items"][0]
    row["relations"] = {
        "cart": True,
        "line": readback_line["id"] == line_id,
        "quantity": readback_line["quantity"],
    }
    results.append(row)

    response, row = _call(
        runtime,
        "delete_line_item",
        _request("DELETE", f"/store/carts/{cart_id}/line-items/{line_id}"),
        expected_status=200,
    )
    row["relations"] = {
        "deleted": response.body["deleted"],
        "items_after": len(response.body["parent"]["items"]),
    }
    results.append(row)
    response, row = _call(
        runtime,
        "duplicate_delete",
        _request("DELETE", f"/store/carts/{cart_id}/line-items/{line_id}"),
        expected_status=200,
    )
    row["relations"] = {
        "same_request_as_delete": True,
        "deleted": response.body["deleted"],
        "items_after": len(response.body["parent"]["items"]),
    }
    results.append(row)
    response, row = _call(
        runtime,
        "delete_from_missing_cart",
        _request("DELETE", "/store/carts/cart_missing/line-items/cali_missing"),
        expected_status=500,
    )
    row["error_type"] = response.body.get("type")
    results.append(row)
    response, row = _call(
        runtime,
        "delete_readback",
        _request("GET", f"/store/carts/{cart_id}"),
        expected_status=200,
    )
    row["relations"] = {
        "cart": response.body["cart"]["id"] == cart_id,
        "items_after": len(response.body["cart"]["items"]),
    }
    results.append(row)
    return results


def _expected_projection(observations: dict[str, Any]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for row in observations["lifecycle"]:
        result = {
            "step": row["step"],
            "status": row["status"],
            "state_changed": row["state_changed"],
        }
        if "error_type" in row:
            result["error_type"] = row["error_type"]
        if row["step"] in {"initial_product_read", "product_page"}:
            result["facts"] = row["facts"]
        relation_maps = {
            "create_cart": {"returned_cart": True, "items_empty": True},
            "duplicate_create": {"same_request_as_create": True, "distinct_cart": True},
            "cart_readback": {"returned_created_cart": True},
            "add_line_item": {
                "returned_line": True,
                "quantity": 1,
                "unit_price": 1000,
                "cart_total": 1000,
            },
            "duplicate_add": {
                "same_request_as_add": True,
                "same_line": True,
                "quantity": 2,
                "unit_price": 1000,
                "cart_total": 2000,
            },
            "invalid_variant_add": {"quantity_after": 2},
            "add_readback": {"cart": True, "line": True, "quantity": 2},
            "set_quantity": {
                "same_line": True,
                "quantity": 3,
                "unit_price": 1000,
                "cart_total": 3000,
            },
            "duplicate_set_quantity": {
                "same_request_as_set": True,
                "same_line": True,
                "quantity": 3,
            },
            "invalid_quantity_type": {"quantity_after": 3},
            "update_readback": {"cart": True, "line": True, "quantity": 3},
            "delete_line_item": {"deleted": True, "items_after": 0},
            "duplicate_delete": {"same_request_as_delete": True, "deleted": True, "items_after": 0},
            "delete_readback": {"cart": True, "items_after": 0},
        }
        if row["step"] in relation_maps:
            result["relations"] = relation_maps[row["step"]]
        projected.append(result)
    return projected


def check(env: Path = DEFAULT_ENV) -> dict[str, Any]:
    env = env.resolve(strict=True)
    observations_path = env / "evidence" / "observations.json"
    observations = json.loads(observations_path.read_text(encoding="utf-8"))
    expected = _expected_projection(observations)
    with tempfile.TemporaryDirectory(prefix="datalox-medusa-cart-differential-") as temporary:
        runtime = ProviderRuntime(
            bundle_dir=env / "provider-runtime",
            admission_path=env / "provider-admission.json",
            run_dir=Path(temporary) / "run",
        )
        try:
            initial = _state(runtime)
            first = _cycle(runtime)
            reset_export = runtime.reset()
            reset_state = reset_export["provider_state"]["state"]
            second = _cycle(runtime)
        finally:
            runtime.close()
    if first != expected or second != expected:
        raise AssertionError("local lifecycle does not match retained provider relations")
    if reset_state != initial or reset_state["carts"] != {}:
        raise AssertionError("reset did not remove created provider resources")
    if first != second:
        raise AssertionError("lifecycle differs after functional reset")
    return {
        "schema_version": "datalox_medusa_store_cart_differential_v1",
        "status": "passed",
        "provider_version": observations["provider_version"],
        "observations_sha256": _file_digest(observations_path),
        "provider_runtime_sha256": _file_digest(env / "provider-runtime" / "provider-runtime.json"),
        "provider_admission_sha256": _file_digest(env / "provider-admission.json"),
        "cycles": 2,
        "observed_step_count": len(expected),
        "reset_removed_created_resources": True,
        "cycle_semantics_sha256": _digest(first),
        "symbolic_relations_checked": True,
        "failure_atomicity_checked": True,
        "steps": first,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = check(args.env)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else "passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
