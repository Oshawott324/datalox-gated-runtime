#!/usr/bin/env python3
"""Verify Medusa public lifecycle facts from the exact restricted receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from itertools import pairwise
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV = ROOT / "envs" / "medusa_store_cart_v0"
DEFAULT_RECEIPT = DEFAULT_ENV / "evidence" / "restricted" / "medusa_2_16_0_store_cart_20260902"
EXPECTED_CHANGED_LABELS = {
    "create_cart",
    "duplicate_create",
    "add_line_item",
    "duplicate_add",
    "set_quantity",
    "delete_line_item",
}
EXPECTED_CART_STATE_PROJECTION = {
    "cart": {
        "id",
        "region_id",
        "customer_id",
        "sales_channel_id",
        "email",
        "currency_code",
        "shipping_address_id",
        "billing_address_id",
        "metadata",
        "locale",
        "completed_at_is_not_null",
        "deleted_at_is_not_null",
    },
    "cart_line_item": {
        "id",
        "cart_id",
        "title",
        "subtitle",
        "thumbnail",
        "quantity",
        "variant_id",
        "product_id",
        "product_title",
        "product_description",
        "product_subtitle",
        "product_type",
        "product_collection",
        "product_handle",
        "variant_sku",
        "variant_barcode",
        "variant_title",
        "variant_option_values",
        "requires_shipping",
        "is_discountable",
        "is_tax_inclusive",
        "compare_at_unit_price",
        "raw_compare_at_unit_price",
        "unit_price",
        "raw_unit_price",
        "metadata",
        "product_type_id",
        "is_custom_price",
        "is_giftcard",
        "deleted_at_is_not_null",
    },
}


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _strict_json(raw: bytes, *, source: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssertionError(f"{source}: expected UTF-8 JSON") from error

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AssertionError(f"{source}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{source}: invalid JSON") from error


def _file(receipt: Path, metadata: dict[str, Any], *, role: str) -> bytes:
    relative = metadata.get("path")
    if not isinstance(relative, str):
        raise TypeError(f"{role}: missing path")
    path = (receipt / relative).resolve(strict=True)
    try:
        path.relative_to(receipt)
    except ValueError as error:
        raise AssertionError(f"{role}: path escapes receipt") from error
    raw = path.read_bytes()
    if metadata.get("length") != len(raw) or metadata.get("sha256") != _digest_bytes(raw):
        raise AssertionError(f"{role}: byte length or digest mismatch")
    return raw


def _object(value: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{source}: expected object")
    return value


def _record_payload(receipt: Path, row: dict[str, Any]) -> dict[str, Any]:
    request = _object(row.get("request"), source=f"{row.get('label')}.request")
    response = _object(row.get("response"), source=f"{row.get('label')}.response")
    cart_state_projection = _object(
        row.get("cart_state_projection"),
        source=f"{row.get('label')}.cart_state_projection",
    )
    request_body_raw = _file(receipt, request["body"], role="request_body")
    response_body_raw = _file(receipt, response["body"], role="response_body")
    response_headers = _strict_json(
        _file(receipt, response["headers"], role="response_headers"),
        source="response_headers",
    )
    state_before = _strict_json(
        _file(receipt, cart_state_projection["before"], role="state_before"),
        source="state_before",
    )
    state_after = _strict_json(
        _file(receipt, cart_state_projection["after"], role="state_after"),
        source="state_after",
    )
    if not isinstance(response_headers, list) or not all(
        isinstance(pair, list) and len(pair) == 2 and all(isinstance(item, str) for item in pair)
        for pair in response_headers
    ):
        raise AssertionError("response headers are not ordered name/value pairs")
    by_name: dict[str, list[str]] = {}
    for name, value in response_headers:
        by_name.setdefault(name.lower(), []).append(value)
    content_types = by_name.get("content-type", [])
    content_lengths = by_name.get("content-length", [])
    transfer_encodings = by_name.get("transfer-encoding", [])
    if len(content_types) != 1 or "application/json" not in content_types[0].lower():
        raise AssertionError(f"{row.get('label')}: response is not declared JSON")
    if (
        len(content_lengths) != 1
        or not content_lengths[0].isascii()
        or not content_lengths[0].isdigit()
    ):
        raise AssertionError(f"{row.get('label')}: invalid Content-Length framing")
    if int(content_lengths[0]) != len(response_body_raw):
        raise AssertionError(f"{row.get('label')}: Content-Length does not match raw body")
    if transfer_encodings:
        raise AssertionError(f"{row.get('label')}: conflicting Transfer-Encoding framing")
    state_changed = state_before != state_after
    if cart_state_projection.get("changed") is not state_changed:
        raise AssertionError(f"{row.get('label')}: recorded state relation is false")
    if response.get("http_version") not in {10, 11}:
        raise AssertionError(f"{row.get('label')}: unsupported HTTP version")
    return {
        **row,
        "request_body": (
            None
            if request_body_raw == b""
            else _strict_json(request_body_raw, source="request_body")
        ),
        "request_body_raw": request_body_raw,
        "response_body": (
            None
            if response_body_raw == b""
            else _strict_json(response_body_raw, source="response_body")
        ),
        "state_before": state_before,
        "state_after": state_after,
        "state_changed": state_changed,
    }


def _safe_request_identity(row: dict[str, Any]) -> dict[str, Any]:
    request = row["request"]
    return {
        "method": request["method"],
        "path_and_query": request["path_and_query"],
        "content_type": request["content_type"],
        "publishable_key": request["publishable_key"],
        "body_sha256": _digest_bytes(row["request_body_raw"]),
        "body_length": len(row["request_body_raw"]),
    }


def _error_type(row: dict[str, Any]) -> str:
    body = _object(row["response_body"], source=f"{row['label']}.response_body")
    value = body.get("type")
    if not isinstance(value, str):
        raise TypeError(f"{row['label']}: missing error type")
    return value


def _cart(row: dict[str, Any]) -> dict[str, Any]:
    body = _object(row["response_body"], source=f"{row['label']}.response_body")
    return _object(body.get("cart"), source=f"{row['label']}.cart")


def _line(cart: dict[str, Any], *, source: str) -> dict[str, Any]:
    items = cart.get("items")
    if not isinstance(items, list) or len(items) != 1:
        raise AssertionError(f"{source}: expected exactly one line item")
    return _object(items[0], source=f"{source}.items[0]")


def _lifecycle(records: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    def row(label: str) -> dict[str, Any]:
        try:
            return records[label]
        except KeyError as error:
            raise AssertionError(f"receipt is missing {label}") from error

    initial = row("initial_product_read")
    page = row("product_page")
    initial_body = _object(initial["response_body"], source="initial_product_read")
    page_body = _object(page["response_body"], source="product_page")
    initial_products = initial_body.get("products")
    page_products = page_body.get("products")
    if not isinstance(initial_products, list) or not isinstance(page_products, list):
        raise TypeError("product collection payloads must contain arrays")
    first_ids = {_object(item, source="product").get("id") for item in initial_products}
    second_ids = {_object(item, source="product").get("id") for item in page_products}

    create = row("create_cart")
    duplicate_create = row("duplicate_create")
    create_cart = _cart(create)
    duplicate_cart = _cart(duplicate_create)
    cart_id = create_cart.get("id")
    if not isinstance(cart_id, str) or duplicate_cart.get("id") == cart_id:
        raise AssertionError("duplicate create did not return a distinct cart")
    if _safe_request_identity(create) != _safe_request_identity(duplicate_create):
        raise AssertionError("duplicate create did not repeat the complete safe request")

    cart_readback = row("cart_readback")
    if not cart_readback["request"]["path_and_query"].endswith(cart_id):
        raise AssertionError("cart readback did not request the created cart")
    if _cart(cart_readback).get("id") != cart_id:
        raise AssertionError("cart readback returned a different cart")

    add = row("add_line_item")
    duplicate_add = row("duplicate_add")
    add_cart = _cart(add)
    add_line = _line(add_cart, source="add_line_item")
    duplicate_add_cart = _cart(duplicate_add)
    duplicate_line = _line(duplicate_add_cart, source="duplicate_add")
    line_id = add_line.get("id")
    unit_price = add_line.get("unit_price")
    if not isinstance(line_id, str) or type(unit_price) is not int:
        raise AssertionError("line-item response lacks a stable id or integer unit price")
    if duplicate_line.get("id") != line_id:
        raise AssertionError("duplicate add did not preserve the generated line id")
    if _safe_request_identity(add) != _safe_request_identity(duplicate_add):
        raise AssertionError("duplicate add did not repeat the complete safe request")
    variant_id = _object(add["request_body"], source="add request").get("variant_id")
    complete_products: list[dict[str, Any]] = []
    for candidate in records.values():
        if candidate["label"] in {
            "initial_product_read",
            "product_page",
        } or candidate["label"].startswith("supporting_product_page_"):
            products = _object(candidate["response_body"], source=candidate["label"]).get(
                "products"
            )
            if not isinstance(products, list):
                raise AssertionError(f"{candidate['label']}: products is not an array")
            complete_products.extend(_object(item, source="product") for item in products)
    if not any(
        any(
            _object(variant, source="variant").get("id") == variant_id
            for variant in product.get("variants", [])
        )
        for product in complete_products
    ):
        raise AssertionError("the written variant was not present in the captured collection")

    add_readback = row("add_readback")
    add_readback_line = _line(_cart(add_readback), source="add_readback")
    if add_readback_line.get("id") != line_id:
        raise AssertionError("add readback did not preserve the generated line id")
    update = row("set_quantity")
    duplicate_update = row("duplicate_set_quantity")
    update_cart = _cart(update)
    update_line = _line(update_cart, source="set_quantity")
    duplicate_update_line = _line(_cart(duplicate_update), source="duplicate_set_quantity")
    if update_line.get("id") != line_id or duplicate_update_line.get("id") != line_id:
        raise AssertionError("quantity updates did not preserve the generated line id")
    if _safe_request_identity(update) != _safe_request_identity(duplicate_update):
        raise AssertionError("duplicate update did not repeat the complete safe request")

    invalid_update_readback = row("update_readback")
    update_readback_line = _line(_cart(invalid_update_readback), source="update_readback")
    if update_readback_line.get("id") != line_id:
        raise AssertionError("update readback did not preserve the generated line id")
    delete = row("delete_line_item")
    duplicate_delete = row("duplicate_delete")
    delete_body = _object(delete["response_body"], source="delete_line_item")
    duplicate_delete_body = _object(duplicate_delete["response_body"], source="duplicate_delete")
    if _safe_request_identity(delete) != _safe_request_identity(duplicate_delete):
        raise AssertionError("duplicate delete did not repeat the complete safe request")
    delete_parent = _object(delete_body.get("parent"), source="delete parent")
    duplicate_delete_parent = _object(
        duplicate_delete_body.get("parent"), source="duplicate delete parent"
    )
    delete_readback_cart = _cart(row("delete_readback"))
    if delete_readback_cart.get("id") != cart_id:
        raise AssertionError("delete readback did not preserve the generated cart id")

    operation = {
        "products": "medusa.store.products.list",
        "create": "medusa.store.carts.create",
        "retrieve": "medusa.store.carts.retrieve",
        "add": "medusa.store.carts.line_items.add",
        "update": "medusa.store.carts.line_items.update",
        "delete": "medusa.store.carts.line_items.delete",
    }

    def base(label: str, operation_id: str) -> dict[str, Any]:
        captured = row(label)
        return {
            "step": label,
            "operation_id": operation_id,
            "status": captured["response"]["status"],
            "state_changed": captured["state_changed"],
        }

    lifecycle: list[dict[str, Any]] = []
    for label in ("missing_publishable_key", "invalid_publishable_key"):
        lifecycle.append(
            {**base(label, operation["products"]), "error_type": _error_type(row(label))}
        )
    lifecycle.extend(
        [
            {
                **base("initial_product_read", operation["products"]),
                "facts": {
                    "limit_offset_envelope": all(
                        key in initial_body for key in ("products", "count", "limit", "offset")
                    ),
                    "published_variant_available": isinstance(variant_id, str),
                },
            },
            {
                **base("product_page", operation["products"]),
                "facts": {
                    "returned_offset": page_body.get("offset"),
                    "page_size": len(page_products),
                    "distinct_from_first_page": not bool(first_ids & second_ids),
                },
            },
        ]
    )
    for label in ("create_missing_publishable_key", "create_invalid_publishable_key"):
        lifecycle.append(
            {**base(label, operation["create"]), "error_type": _error_type(row(label))}
        )
    lifecycle.extend(
        [
            {
                **base("create_cart", operation["create"]),
                "relations": {
                    "returned_cart": "$cart_1",
                    "items_empty": create_cart.get("items") == [],
                },
            },
            {
                **base("duplicate_create", operation["create"]),
                "relations": {
                    "same_request_as": "create_cart",
                    "returned_cart": "$cart_2",
                    "distinct_from": "$cart_1",
                },
            },
            {
                **base("invalid_region_create", operation["create"]),
                "error_type": _error_type(row("invalid_region_create")),
            },
            {
                **base("cart_readback", operation["retrieve"]),
                "relations": {"requested": "$cart_1", "returned": "$cart_1"},
            },
            {
                **base("retrieve_missing_cart", operation["retrieve"]),
                "error_type": _error_type(row("retrieve_missing_cart")),
            },
            {
                **base("add_line_item", operation["add"]),
                "relations": {
                    "cart": "$cart_1",
                    "returned_line": "$line_1",
                    "quantity": add_line.get("quantity"),
                    "unit_price": unit_price,
                    "cart_total": add_cart.get("total"),
                },
            },
            {
                **base("duplicate_add", operation["add"]),
                "relations": {
                    "same_request_as": "add_line_item",
                    "same_line": "$line_1",
                    "quantity": duplicate_line.get("quantity"),
                    "unit_price": duplicate_line.get("unit_price"),
                    "cart_total": duplicate_add_cart.get("total"),
                },
            },
            {
                **base("invalid_variant_add", operation["add"]),
                "error_type": _error_type(row("invalid_variant_add")),
                "relations": {
                    "cart": "$cart_1",
                    "quantity_after": add_readback_line.get("quantity"),
                },
            },
            {
                **base("add_readback", operation["retrieve"]),
                "relations": {
                    "cart": "$cart_1",
                    "line": "$line_1",
                    "quantity": add_readback_line.get("quantity"),
                },
            },
            {
                **base("set_quantity", operation["update"]),
                "relations": {
                    "line": "$line_1",
                    "quantity": update_line.get("quantity"),
                    "unit_price": update_line.get("unit_price"),
                    "cart_total": update_cart.get("total"),
                },
            },
            {
                **base("duplicate_set_quantity", operation["update"]),
                "relations": {
                    "same_request_as": "set_quantity",
                    "line": "$line_1",
                    "quantity": duplicate_update_line.get("quantity"),
                },
            },
            {
                **base("invalid_quantity_type", operation["update"]),
                "error_type": _error_type(row("invalid_quantity_type")),
                "relations": {
                    "line": "$line_1",
                    "quantity_after": update_readback_line.get("quantity"),
                },
            },
            {
                **base("update_readback", operation["retrieve"]),
                "relations": {
                    "cart": "$cart_1",
                    "line": "$line_1",
                    "quantity": update_readback_line.get("quantity"),
                },
            },
            {
                **base("delete_line_item", operation["delete"]),
                "relations": {
                    "line": "$line_1",
                    "deleted": delete_body.get("deleted"),
                    "items_after": len(delete_parent.get("items", [])),
                },
            },
            {
                **base("duplicate_delete", operation["delete"]),
                "relations": {
                    "same_request_as": "delete_line_item",
                    "line": "$line_1",
                    "deleted": duplicate_delete_body.get("deleted"),
                    "items_after": len(duplicate_delete_parent.get("items", [])),
                },
            },
            {
                **base("delete_from_missing_cart", operation["delete"]),
                "error_type": _error_type(row("delete_from_missing_cart")),
            },
            {
                **base("delete_readback", operation["retrieve"]),
                "relations": {
                    "cart": "$cart_1",
                    "items_after": len(delete_readback_cart.get("items", [])),
                },
            },
        ]
    )
    return lifecycle, unit_price


def check(env: Path = DEFAULT_ENV, receipt: Path = DEFAULT_RECEIPT) -> dict[str, Any]:
    env = env.resolve(strict=True)
    receipt = receipt.resolve(strict=True)
    if (receipt / "INCOMPLETE").exists():
        raise AssertionError("restricted receipt is incomplete")
    manifest_path = receipt / "manifest.json"
    manifest = _object(
        _strict_json(manifest_path.read_bytes(), source="manifest"), source="manifest"
    )
    if manifest.get("schema_version") != "datalox_provider_grounding_receipt_v1":
        raise AssertionError("unsupported receipt schema")
    projection = manifest.get("cart_state_projection")
    if (
        not isinstance(projection, dict)
        or {
            table: set(fields) if isinstance(fields, list) else set()
            for table, fields in projection.items()
        }
        != EXPECTED_CART_STATE_PROJECTION
    ):
        raise AssertionError("receipt cart-state projection declaration is invalid")
    rows = manifest.get("records")
    if not isinstance(rows, list) or manifest.get("record_count") != len(rows):
        raise AssertionError("receipt record count mismatch")
    loaded: list[dict[str, Any]] = []
    for expected_index, value in enumerate(rows, start=1):
        row = _object(value, source=f"record {expected_index}")
        if row.get("index") != expected_index or not isinstance(row.get("label"), str):
            raise AssertionError("receipt indexes or labels are invalid")
        loaded.append(_record_payload(receipt, row))
    for previous, following in pairwise(loaded):
        if previous["state_after"] != following["state_before"]:
            raise AssertionError(
                f"cart-state projection is discontinuous between {previous['label']} "
                f"and {following['label']}"
            )
    for row in loaded:
        expected_changed = row["label"] in EXPECTED_CHANGED_LABELS
        if row["state_changed"] is not expected_changed:
            raise AssertionError(f"{row['label']}: unexpected cart-state projection relation")
    labels = [row["label"] for row in loaded]
    if len(labels) != len(set(labels)):
        raise AssertionError("receipt labels are not unique")
    referenced = {"manifest.json"}
    for row in rows:
        referenced.add(row["request"]["body"]["path"])
        referenced.add(row["response"]["body"]["path"])
        referenced.add(row["response"]["headers"]["path"])
        referenced.add(row["cart_state_projection"]["before"]["path"])
        referenced.add(row["cart_state_projection"]["after"]["path"])
    actual = {path.relative_to(receipt).as_posix() for path in receipt.rglob("*") if path.is_file()}
    if actual != referenced:
        raise AssertionError("receipt contains missing or unreferenced files")
    file_rows = [
        {"path": relative, "sha256": _digest_bytes((receipt / relative).read_bytes())}
        for relative in sorted(actual)
    ]
    receipt_binding = {
        "schema_version": manifest["schema_version"],
        "manifest_sha256": _digest_bytes(manifest_path.read_bytes()),
        "tree_sha256": _digest_bytes(
            json.dumps(file_rows, sort_keys=True, separators=(",", ":")).encode()
        ),
        "record_count": len(rows),
    }

    observations_path = env / "evidence" / "observations.json"
    provenance_path = env / "evidence" / "provenance.json"
    observations = _object(
        _strict_json(observations_path.read_bytes(), source="observations"),
        source="observations",
    )
    provenance = _object(
        _strict_json(provenance_path.read_bytes(), source="provenance"),
        source="provenance",
    )
    if observations.get("grounding_receipt") != receipt_binding:
        raise AssertionError("public observations do not bind this exact restricted receipt")
    if provenance.get("grounding_receipt") != receipt_binding:
        raise AssertionError("public provenance does not bind this exact restricted receipt")
    if provenance.get("source_artifacts") != manifest.get("source_artifacts"):
        raise AssertionError("public provenance source digests differ from the receipt")
    if provenance.get("observed_at") != manifest.get("observed_at"):
        raise AssertionError("public provenance timestamp differs from the receipt")
    if provenance.get("source_artifacts_verified_at") != manifest.get(
        "source_artifacts_verified_at"
    ):
        raise AssertionError("source-artifact verification timestamp differs")
    source_roles = {
        row.get("path_role")
        for row in manifest.get("source_artifacts", [])
        if isinstance(row, dict)
    }
    if "installed_medusa_runtime_package" not in source_roles:
        raise AssertionError("installed Medusa runtime package is not digest-bound")

    records = {row["label"]: row for row in loaded}
    lifecycle, unit_price = _lifecycle(records)
    if observations.get("lifecycle") != lifecycle:
        raise AssertionError("public lifecycle is not derivable from the restricted receipt")
    if observations.get("fixed_reference_inputs", {}).get("unit_price") != unit_price:
        raise AssertionError("public unit price is not derivable from the restricted receipt")
    first_state = loaded[0]["state_before"]
    if first_state.get("carts") != [] or first_state.get("line_items") != []:
        raise AssertionError("reference did not begin with an empty cart state")
    return {
        "schema_version": "datalox_medusa_store_cart_grounding_check_v1",
        "status": "passed",
        "manifest_sha256": receipt_binding["manifest_sha256"],
        "tree_sha256": receipt_binding["tree_sha256"],
        "record_count": len(rows),
        "promoted_lifecycle_steps": len(lifecycle),
        "raw_statuses_checked": True,
        "raw_bodies_and_framing_checked": True,
        "cart_state_projection_continuity_checked": True,
        "cart_state_projection_relations_checked": True,
        "failure_atomicity_within_cart_state_projection_checked": True,
        "duplicate_safe_request_identity_checked": True,
        "generated_identifier_relations_checked": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = check(args.env, args.receipt)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else "passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
