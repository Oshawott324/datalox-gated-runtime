#!/usr/bin/env python3
"""Authoring-only acquisition for the Medusa 2.16.0 Store cart lifecycle.

The public output contains identifier-free factual assertions. The separately
required private receipt retains the exact request and response bodies, ordered
response headers, and canonical provider-state snapshots needed to audit those
assertions. It must run against a disposable, freshly seeded self-hosted
instance. Runtime execution never invokes this utility and cannot express
upstream forwarding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import urllib.error
import urllib.request
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

EXPECTED_VERSION = "2.16.0"
CART_STATE_PROJECTION = {
    "cart": [
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
    ],
    "cart_line_item": [
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
    ],
}


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _bytes_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _strict_json(raw: bytes, *, source: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{source}: response is not UTF-8 JSON") from error

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError(f"{source}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{source}: response is not strict JSON") from error


def _postgres_environment(database_url: str) -> dict[str, str]:
    parsed = urlparse(database_url)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname or not parsed.path:
        raise ValueError("database URL must be a PostgreSQL URL")
    return {
        **os.environ,
        "PGHOST": parsed.hostname,
        "PGPORT": str(parsed.port or 5432),
        "PGDATABASE": parsed.path.lstrip("/"),
        "PGUSER": parsed.username or "",
        "PGPASSWORD": parsed.password or "",
    }


def _cart_state_projection(database_url: str) -> dict[str, Any]:
    query = """
SELECT jsonb_build_object(
  'carts', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'id', id,
      'region_id', region_id,
      'customer_id', customer_id,
      'sales_channel_id', sales_channel_id,
      'email', email,
      'currency_code', currency_code,
      'shipping_address_id', shipping_address_id,
      'billing_address_id', billing_address_id,
      'metadata', metadata,
      'locale', locale,
      'completed', completed_at IS NOT NULL,
      'deleted', deleted_at IS NOT NULL
    ) ORDER BY id) FROM cart
  ), '[]'::jsonb),
  'line_items', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'id', id,
      'cart_id', cart_id,
      'title', title,
      'subtitle', subtitle,
      'thumbnail', thumbnail,
      'quantity', quantity,
      'variant_id', variant_id,
      'product_id', product_id,
      'product_title', product_title,
      'product_description', product_description,
      'product_subtitle', product_subtitle,
      'product_type', product_type,
      'product_collection', product_collection,
      'product_handle', product_handle,
      'variant_sku', variant_sku,
      'variant_barcode', variant_barcode,
      'variant_title', variant_title,
      'variant_option_values', variant_option_values,
      'requires_shipping', requires_shipping,
      'is_discountable', is_discountable,
      'is_tax_inclusive', is_tax_inclusive,
      'compare_at_unit_price', compare_at_unit_price,
      'raw_compare_at_unit_price', raw_compare_at_unit_price,
      'unit_price', unit_price,
      'raw_unit_price', raw_unit_price,
      'metadata', metadata,
      'product_type_id', product_type_id,
      'is_custom_price', is_custom_price,
      'is_giftcard', is_giftcard,
      'deleted', deleted_at IS NOT NULL
    ) ORDER BY id) FROM cart_line_item
  ), '[]'::jsonb)
)::text
"""
    completed = subprocess.run(
        ["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-c", query],
        check=True,
        capture_output=True,
        text=True,
        env=_postgres_environment(database_url),
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise TypeError("cart-state projection snapshot is not an object")
    return value


class _ReceiptRecorder:
    def __init__(self, root: Path, *, database_url: str, key: str, observed_at: str) -> None:
        if root.exists() or root.is_symlink():
            raise FileExistsError(f"private receipt output already exists: {root}")
        root.mkdir(parents=True)
        self.root = root
        self.database_url = database_url
        self.key_sha256 = _bytes_sha256(key.encode("utf-8"))
        self.observed_at = observed_at
        self.records: list[dict[str, Any]] = []
        (root / "INCOMPLETE").write_text("acquisition in progress\n", encoding="utf-8")

    def request(
        self,
        base_url: str,
        label: str,
        method: str,
        path: str,
        *,
        key: str | None,
        body: Any = None,
    ) -> tuple[int, Any]:
        index = len(self.records) + 1
        directory = self.root / "records" / f"{index:03d}-{label}"
        directory.mkdir(parents=True)
        request_body = b"" if body is None else json.dumps(body).encode("utf-8")
        state_before = _cart_state_projection(self.database_url)
        request_headers = {"content-type": "application/json"}
        if key is not None:
            request_headers["x-publishable-api-key"] = key
        request = urllib.request.Request(
            base_url.rstrip("/") + path,
            method=method,
            headers=request_headers,
            data=None if body is None else request_body,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=20) as response:
                status = response.status
                reason = response.reason
                http_version = response.version
                response_headers = list(response.headers.raw_items())
                response_body = response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            reason = error.reason
            http_version = error.version
            response_headers = list(error.headers.raw_items())
            response_body = error.read()
        state_after = _cart_state_projection(self.database_url)
        files: dict[str, dict[str, Any]] = {}
        payloads = {
            "request_body": ("request-body.bin", request_body),
            "response_body": ("response-body.bin", response_body),
            "response_headers": (
                "response-headers.json",
                (json.dumps(response_headers, indent=2) + "\n").encode("utf-8"),
            ),
            "state_before": (
                "state-before.json",
                (json.dumps(state_before, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            ),
            "state_after": (
                "state-after.json",
                (json.dumps(state_after, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            ),
        }
        for role, (filename, value) in payloads.items():
            target = directory / filename
            target.write_bytes(value)
            files[role] = {
                "path": target.relative_to(self.root).as_posix(),
                "length": len(value),
                "sha256": _bytes_sha256(value),
            }
        parsed_body = _strict_json(response_body, source=label) if response_body else None
        self.records.append(
            {
                "index": index,
                "label": label,
                "request": {
                    "method": method,
                    "path_and_query": path,
                    "body": files["request_body"],
                    "content_type": "application/json",
                    "publishable_key": {
                        "present": key is not None,
                        "matches_valid_reference_key": (
                            key is not None
                            and _bytes_sha256(key.encode("utf-8")) == self.key_sha256
                        ),
                        "value_sha256": None if key is None else _bytes_sha256(key.encode("utf-8")),
                    },
                },
                "response": {
                    "status": status,
                    "reason": reason,
                    "http_version": http_version,
                    "headers": files["response_headers"],
                    "body": files["response_body"],
                },
                "cart_state_projection": {
                    "before": files["state_before"],
                    "after": files["state_after"],
                    "changed": state_before != state_after,
                },
            }
        )
        return status, parsed_body

    def finalize(self, *, source_artifacts: list[dict[str, str]]) -> dict[str, Any]:
        manifest = {
            "schema_version": "datalox_provider_grounding_receipt_v1",
            "provider": "Medusa",
            "provider_version": EXPECTED_VERSION,
            "reference_kind": "self_hosted_exact_release",
            "observed_at": self.observed_at,
            "credential_retention": "sha256_commitment_only",
            "reference_publishable_key_sha256": self.key_sha256,
            "source_artifacts": source_artifacts,
            "source_artifacts_verified_at": self.observed_at,
            "cart_state_projection": CART_STATE_PROJECTION,
            "record_count": len(self.records),
            "records": self.records,
        }
        _write_json(self.root / "manifest.json", manifest)
        (self.root / "INCOMPLETE").unlink()
        file_rows = [
            {
                "path": path.relative_to(self.root).as_posix(),
                "sha256": _sha256(path),
            }
            for path in sorted(self.root.rglob("*"))
            if path.is_file()
        ]
        tree_bytes = json.dumps(file_rows, sort_keys=True, separators=(",", ":")).encode()
        return {
            "schema_version": manifest["schema_version"],
            "manifest_sha256": _sha256(self.root / "manifest.json"),
            "tree_sha256": _bytes_sha256(tree_bytes),
            "record_count": len(self.records),
        }


def _require(status: int, expected: int, body: Any, step: str) -> dict[str, Any]:
    if status != expected or not isinstance(body, dict):
        raise RuntimeError(f"{step}: expected object response with status {expected}, got {status}")
    return body


def _cart_count(database_url: str) -> int:
    completed = subprocess.run(
        [
            "psql",
            "-X",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "SELECT count(*) FROM cart WHERE deleted_at IS NULL",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=_postgres_environment(database_url),
    )
    return int(completed.stdout.strip())


def _source_artifacts(backend_root: Path) -> list[dict[str, str]]:
    package = json.loads((backend_root / "package.json").read_text(encoding="utf-8"))
    if package.get("dependencies", {}).get("@medusajs/medusa") != EXPECTED_VERSION:
        raise RuntimeError("backend does not pin @medusajs/medusa exactly to 2.16.0")
    project_root = backend_root.parents[1] if backend_root.parent.name == "apps" else backend_root
    installed_package = project_root / "node_modules" / "@medusajs" / "medusa" / "package.json"
    installed = json.loads(installed_package.read_text(encoding="utf-8"))
    if installed.get("version") != EXPECTED_VERSION:
        raise RuntimeError("installed @medusajs/medusa runtime is not exactly 2.16.0")
    route_root = (
        project_root / "node_modules" / "@medusajs" / "medusa" / "dist" / "api" / "store" / "carts"
    )
    paths = [
        ("reference_backend_package", backend_root / "package.json"),
        ("reference_backend_lockfile", project_root / "package-lock.json"),
        ("installed_medusa_runtime_package", installed_package),
        ("installed_store_carts_route", route_root / "route.js"),
        ("installed_store_cart_route", route_root / "[id]" / "route.js"),
        ("installed_store_line_item_add_route", route_root / "[id]" / "line-items" / "route.js"),
        (
            "installed_store_line_item_update_delete_route",
            route_root / "[id]" / "line-items" / "[line_id]" / "route.js",
        ),
    ]
    return [
        {"path_role": role, "sha256": _sha256(path.resolve(strict=True))} for role, path in paths
    ]


def acquire(
    *,
    base_url: str,
    publishable_key: str,
    region_id: str,
    variant_id: str,
    backend_root: Path,
    database_url: str,
    observed_at: str,
    private_receipt_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("authoring acquisition accepts only a local HTTP reference instance")
    if _cart_count(database_url) != 0:
        raise RuntimeError("reference database must begin with zero non-deleted carts")
    recorder = _ReceiptRecorder(
        private_receipt_dir,
        database_url=database_url,
        key=publishable_key,
        observed_at=observed_at,
    )
    request = recorder.request
    status, body = request(
        base_url,
        "missing_publishable_key",
        "GET",
        "/store/products?limit=10&offset=0",
        key=None,
    )
    missing = _require(status, 400, body, "missing_publishable_key")
    status, body = request(
        base_url,
        "invalid_publishable_key",
        "GET",
        "/store/products?limit=10&offset=0",
        key="pk_invalid",
    )
    invalid_key = _require(status, 400, body, "invalid_publishable_key")
    if missing.get("type") != "not_allowed" or invalid_key.get("type") != "not_allowed":
        raise RuntimeError("publishable-key failures do not match the observed Store shape")
    status, products_body = request(
        base_url,
        "initial_product_read",
        "GET",
        "/store/products?limit=10&offset=0",
        key=publishable_key,
    )
    products_body = _require(status, 200, products_body, "initial_product_read")
    first_product_ids = {row.get("id") for row in products_body.get("products", [])}
    status, second_page_body = request(
        base_url,
        "product_page",
        "GET",
        "/store/products?limit=10&offset=20",
        key=publishable_key,
    )
    second_page_body = _require(status, 200, second_page_body, "product_page")
    second_product_ids = {row.get("id") for row in second_page_body.get("products", [])}
    if (
        second_page_body.get("offset") != 20
        or second_page_body.get("limit") != 10
        or len(second_product_ids) != 10
        or first_product_ids & second_product_ids
    ):
        raise RuntimeError("second provider page does not preserve the observed distinct window")
    pages = [products_body, second_page_body]
    count = products_body.get("count")
    if type(count) is not int or count < 1:
        raise RuntimeError("product collection does not expose an integer count")
    for offset in range(10, count, 10):
        if offset == 20:
            continue
        status, page = request(
            base_url,
            f"supporting_product_page_{offset}",
            "GET",
            f"/store/products?limit=10&offset={offset}",
            key=publishable_key,
        )
        pages.append(_require(status, 200, page, f"product_page_{offset}"))
    selected_product_id: str | None = None
    for page in pages:
        for product in page.get("products", []):
            for variant in product.get("variants", []):
                if variant.get("id") == variant_id:
                    selected_product_id = product["id"]
    if selected_product_id is None:
        raise RuntimeError("configured variant is absent from the complete provider collection")
    create_body = {"email": "datalox-acquisition@example.test", "region_id": region_id}
    before_auth_failures = _cart_count(database_url)
    status, missing_create_key = request(
        base_url,
        "create_missing_publishable_key",
        "POST",
        "/store/carts",
        key=None,
        body=create_body,
    )
    missing_create_key = _require(status, 400, missing_create_key, "create_missing_publishable_key")
    status, invalid_create_key = request(
        base_url,
        "create_invalid_publishable_key",
        "POST",
        "/store/carts",
        key="pk_invalid",
        body=create_body,
    )
    invalid_create_key = _require(status, 400, invalid_create_key, "create_invalid_publishable_key")
    if (
        missing_create_key.get("type") != "not_allowed"
        or invalid_create_key.get("type") != "not_allowed"
        or _cart_count(database_url) != before_auth_failures
    ):
        raise RuntimeError("cart-create publishable-key failures do not match atomically")
    status, first_body = request(
        base_url,
        "create_cart",
        "POST",
        "/store/carts",
        key=publishable_key,
        body=create_body,
    )
    first_cart = _require(status, 200, first_body, "create_cart")["cart"]
    cart_id = first_cart["id"]
    status, second_body = request(
        base_url,
        "duplicate_create",
        "POST",
        "/store/carts",
        key=publishable_key,
        body=create_body,
    )
    second_cart = _require(status, 200, second_body, "duplicate_create")["cart"]
    if second_cart["id"] == cart_id:
        raise RuntimeError("duplicate create did not issue a distinct cart id")
    before_invalid_create = _cart_count(database_url)
    status, invalid_create = request(
        base_url,
        "invalid_region_create",
        "POST",
        "/store/carts",
        key=publishable_key,
        body={"region_id": "region_datalox_missing"},
    )
    invalid_create = _require(status, 404, invalid_create, "invalid_region_create")
    if (
        invalid_create.get("type") != "not_found"
        or _cart_count(database_url) != before_invalid_create
    ):
        raise RuntimeError("invalid cart create was not state-atomic")
    status, readback_body = request(
        base_url,
        "cart_readback",
        "GET",
        f"/store/carts/{cart_id}",
        key=publishable_key,
    )
    readback = _require(status, 200, readback_body, "cart_readback")["cart"]
    if readback["id"] != cart_id:
        raise RuntimeError("cart readback id differs from create response")
    status, missing_retrieve = request(
        base_url,
        "retrieve_missing_cart",
        "GET",
        "/store/carts/cart_datalox_missing",
        key=publishable_key,
    )
    missing_retrieve = _require(status, 404, missing_retrieve, "retrieve_missing_cart")
    if missing_retrieve.get("type") != "not_found":
        raise RuntimeError("missing-cart retrieve error shape changed")
    add_body = {"variant_id": variant_id, "quantity": 1}
    status, add_response = request(
        base_url,
        "add_line_item",
        "POST",
        f"/store/carts/{cart_id}/line-items",
        key=publishable_key,
        body=add_body,
    )
    add_cart = _require(status, 200, add_response, "add_line_item")["cart"]
    line = add_cart["items"][0]
    line_id = line["id"]
    unit_price = line.get("unit_price")
    if type(unit_price) is not int or add_cart.get("total") != unit_price:
        raise RuntimeError(
            "line-item add did not expose the expected integer unit price and cart total"
        )
    status, duplicate_add = request(
        base_url,
        "duplicate_add",
        "POST",
        f"/store/carts/{cart_id}/line-items",
        key=publishable_key,
        body=add_body,
    )
    duplicate_cart = _require(status, 200, duplicate_add, "duplicate_add")["cart"]
    duplicated_line = duplicate_cart["items"][0]
    if (
        duplicated_line["id"] != line_id
        or duplicated_line["quantity"] != 2
        or duplicate_cart.get("total") != 2 * unit_price
    ):
        raise RuntimeError("duplicate add did not increment the existing line")
    before_invalid_add = deepcopy(duplicated_line)
    status, invalid_add = request(
        base_url,
        "invalid_variant_add",
        "POST",
        f"/store/carts/{cart_id}/line-items",
        key=publishable_key,
        body={"variant_id": "variant_datalox_missing", "quantity": 1},
    )
    invalid_add = _require(status, 400, invalid_add, "invalid_variant_add")
    status, readback_body = request(
        base_url,
        "add_readback",
        "GET",
        f"/store/carts/{cart_id}",
        key=publishable_key,
    )
    after_invalid_add = _require(status, 200, readback_body, "invalid_variant_readback")["cart"][
        "items"
    ][0]
    if invalid_add.get("type") != "invalid_data" or after_invalid_add != before_invalid_add:
        raise RuntimeError("invalid add was not state-atomic")
    update_body = {"quantity": 3}
    status, update_response = request(
        base_url,
        "set_quantity",
        "POST",
        f"/store/carts/{cart_id}/line-items/{line_id}",
        key=publishable_key,
        body=update_body,
    )
    updated_cart = _require(status, 200, update_response, "set_quantity")["cart"]
    updated_line = updated_cart["items"][0]
    status, duplicate_update = request(
        base_url,
        "duplicate_set_quantity",
        "POST",
        f"/store/carts/{cart_id}/line-items/{line_id}",
        key=publishable_key,
        body=update_body,
    )
    duplicate_updated_line = _require(status, 200, duplicate_update, "duplicate_set_quantity")[
        "cart"
    ]["items"][0]
    if (
        updated_line != duplicate_updated_line
        or updated_line["quantity"] != 3
        or updated_cart.get("total") != 3 * unit_price
    ):
        raise RuntimeError("duplicate quantity set changed the line")
    status, invalid_update = request(
        base_url,
        "invalid_quantity_type",
        "POST",
        f"/store/carts/{cart_id}/line-items/{line_id}",
        key=publishable_key,
        body={"quantity": "three"},
    )
    invalid_update = _require(status, 400, invalid_update, "invalid_quantity_type")
    status, readback_body = request(
        base_url,
        "update_readback",
        "GET",
        f"/store/carts/{cart_id}",
        key=publishable_key,
    )
    after_invalid_update = _require(status, 200, readback_body, "invalid_quantity_readback")[
        "cart"
    ]["items"][0]
    if invalid_update.get("type") != "invalid_data" or after_invalid_update != updated_line:
        raise RuntimeError("invalid update was not state-atomic")
    status, delete_response = request(
        base_url,
        "delete_line_item",
        "DELETE",
        f"/store/carts/{cart_id}/line-items/{line_id}",
        key=publishable_key,
    )
    deleted = _require(status, 200, delete_response, "delete_line_item")
    status, duplicate_delete = request(
        base_url,
        "duplicate_delete",
        "DELETE",
        f"/store/carts/{cart_id}/line-items/{line_id}",
        key=publishable_key,
    )
    duplicate_deleted = _require(status, 200, duplicate_delete, "duplicate_delete")
    if (
        not deleted.get("deleted")
        or not duplicate_deleted.get("deleted")
        or duplicate_deleted["parent"]["items"]
    ):
        raise RuntimeError("duplicate delete does not match observed idempotent semantics")
    status, missing_delete = request(
        base_url,
        "delete_from_missing_cart",
        "DELETE",
        "/store/carts/cart_datalox_missing/line-items/cali_datalox_missing",
        key=publishable_key,
    )
    missing_delete = _require(status, 500, missing_delete, "delete_from_missing_cart")
    if missing_delete.get("type") != "unknown_error":
        raise RuntimeError("missing-cart delete error shape changed")
    status, delete_readback_body = request(
        base_url,
        "delete_readback",
        "GET",
        f"/store/carts/{cart_id}",
        key=publishable_key,
    )
    delete_readback = _require(status, 200, delete_readback_body, "delete_readback")["cart"]
    if delete_readback.get("items") != []:
        raise RuntimeError("post-delete cart readback is not empty")

    lifecycle = [
        {
            "step": "missing_publishable_key",
            "operation_id": "medusa.store.products.list",
            "status": 400,
            "error_type": "not_allowed",
            "state_changed": False,
        },
        {
            "step": "invalid_publishable_key",
            "operation_id": "medusa.store.products.list",
            "status": 400,
            "error_type": "not_allowed",
            "state_changed": False,
        },
        {
            "step": "initial_product_read",
            "operation_id": "medusa.store.products.list",
            "status": 200,
            "state_changed": False,
            "facts": {"limit_offset_envelope": True, "published_variant_available": True},
        },
        {
            "step": "product_page",
            "operation_id": "medusa.store.products.list",
            "status": 200,
            "state_changed": False,
            "facts": {"returned_offset": 20, "page_size": 10, "distinct_from_first_page": True},
        },
        {
            "step": "create_missing_publishable_key",
            "operation_id": "medusa.store.carts.create",
            "status": 400,
            "error_type": "not_allowed",
            "state_changed": False,
        },
        {
            "step": "create_invalid_publishable_key",
            "operation_id": "medusa.store.carts.create",
            "status": 400,
            "error_type": "not_allowed",
            "state_changed": False,
        },
        {
            "step": "create_cart",
            "operation_id": "medusa.store.carts.create",
            "status": 200,
            "state_changed": True,
            "relations": {"returned_cart": "$cart_1", "items_empty": True},
        },
        {
            "step": "duplicate_create",
            "operation_id": "medusa.store.carts.create",
            "status": 200,
            "state_changed": True,
            "relations": {
                "same_request_as": "create_cart",
                "returned_cart": "$cart_2",
                "distinct_from": "$cart_1",
            },
        },
        {
            "step": "invalid_region_create",
            "operation_id": "medusa.store.carts.create",
            "status": 404,
            "error_type": "not_found",
            "state_changed": False,
        },
        {
            "step": "cart_readback",
            "operation_id": "medusa.store.carts.retrieve",
            "status": 200,
            "state_changed": False,
            "relations": {"requested": "$cart_1", "returned": "$cart_1"},
        },
        {
            "step": "retrieve_missing_cart",
            "operation_id": "medusa.store.carts.retrieve",
            "status": 404,
            "error_type": "not_found",
            "state_changed": False,
        },
        {
            "step": "add_line_item",
            "operation_id": "medusa.store.carts.line_items.add",
            "status": 200,
            "state_changed": True,
            "relations": {
                "cart": "$cart_1",
                "returned_line": "$line_1",
                "quantity": 1,
                "unit_price": unit_price,
                "cart_total": unit_price,
            },
        },
        {
            "step": "duplicate_add",
            "operation_id": "medusa.store.carts.line_items.add",
            "status": 200,
            "state_changed": True,
            "relations": {
                "same_request_as": "add_line_item",
                "same_line": "$line_1",
                "quantity": 2,
                "unit_price": unit_price,
                "cart_total": 2 * unit_price,
            },
        },
        {
            "step": "invalid_variant_add",
            "operation_id": "medusa.store.carts.line_items.add",
            "status": 400,
            "error_type": "invalid_data",
            "state_changed": False,
            "relations": {"cart": "$cart_1", "quantity_after": 2},
        },
        {
            "step": "add_readback",
            "operation_id": "medusa.store.carts.retrieve",
            "status": 200,
            "state_changed": False,
            "relations": {"cart": "$cart_1", "line": "$line_1", "quantity": 2},
        },
        {
            "step": "set_quantity",
            "operation_id": "medusa.store.carts.line_items.update",
            "status": 200,
            "state_changed": True,
            "relations": {
                "line": "$line_1",
                "quantity": 3,
                "unit_price": unit_price,
                "cart_total": 3 * unit_price,
            },
        },
        {
            "step": "duplicate_set_quantity",
            "operation_id": "medusa.store.carts.line_items.update",
            "status": 200,
            "state_changed": False,
            "relations": {"same_request_as": "set_quantity", "line": "$line_1", "quantity": 3},
        },
        {
            "step": "invalid_quantity_type",
            "operation_id": "medusa.store.carts.line_items.update",
            "status": 400,
            "error_type": "invalid_data",
            "state_changed": False,
            "relations": {"line": "$line_1", "quantity_after": 3},
        },
        {
            "step": "update_readback",
            "operation_id": "medusa.store.carts.retrieve",
            "status": 200,
            "state_changed": False,
            "relations": {"cart": "$cart_1", "line": "$line_1", "quantity": 3},
        },
        {
            "step": "delete_line_item",
            "operation_id": "medusa.store.carts.line_items.delete",
            "status": 200,
            "state_changed": True,
            "relations": {"line": "$line_1", "deleted": True, "items_after": 0},
        },
        {
            "step": "duplicate_delete",
            "operation_id": "medusa.store.carts.line_items.delete",
            "status": 200,
            "state_changed": False,
            "relations": {
                "same_request_as": "delete_line_item",
                "line": "$line_1",
                "deleted": True,
                "items_after": 0,
            },
        },
        {
            "step": "delete_from_missing_cart",
            "operation_id": "medusa.store.carts.line_items.delete",
            "status": 500,
            "error_type": "unknown_error",
            "state_changed": False,
        },
        {
            "step": "delete_readback",
            "operation_id": "medusa.store.carts.retrieve",
            "status": 200,
            "state_changed": False,
            "relations": {"cart": "$cart_1", "items_after": 0},
        },
    ]
    source_artifacts = _source_artifacts(backend_root)
    receipt_binding = recorder.finalize(source_artifacts=source_artifacts)
    observations = {
        "schema_version": "datalox_medusa_store_cart_observations_v1",
        "provider": "Medusa",
        "provider_version": EXPECTED_VERSION,
        "reference_kind": "self_hosted_exact_release",
        "scope": "Store product reads plus cart and line-item lifecycle",
        "sanitization": "No credentials, raw payload bodies, provider-generated identifiers, or tenant identifiers are retained. Symbolic references express only observed relationships.",
        "fixed_reference_inputs": {
            "explicit_region": "one valid seeded region",
            "publishable_key": "required on the Store surface; no key value retained",
            "known_variant": "one published fixed-price variant",
            "unit_price": unit_price,
        },
        "lifecycle": lifecycle,
        "initial_reference_state": {
            "non_deleted_cart_count": 0,
            "verified_by": "authoring-only PostgreSQL count before lifecycle acquisition",
        },
        "grounding_receipt": receipt_binding,
    }
    provenance = {
        "schema_version": "datalox_medusa_store_cart_provenance_v1",
        "provider": "Medusa",
        "provider_version": EXPECTED_VERSION,
        "reference_kind": "self_hosted_exact_release",
        "observed_at": observed_at,
        "source_license": "MIT",
        "source_artifacts": source_artifacts,
        "source_artifacts_verified_at": observed_at,
        "grounding_receipt": receipt_binding,
        "retention": {
            "credentials": False,
            "credential_commitments": True,
            "provider_generated_identifiers_public": False,
            "raw_request_bodies_restricted": True,
            "raw_response_bodies_restricted": True,
            "cart_state_projection_snapshots_restricted": True,
            "tenant_identifiers": False,
            "retained_material": (
                "Public artifacts contain only self-authored factual assertions. "
                "The digest-bound restricted receipt retains exact request/response "
                "bodies and canonical state snapshots from the disposable reference."
            ),
        },
    }
    return observations, provenance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorize-disposable-writes", action="store_true")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--publishable-key-env", default="MEDUSA_PUBLISHABLE_API_KEY")
    parser.add_argument("--database-url-env", default="MEDUSA_DATABASE_URL")
    parser.add_argument("--region-id", required=True)
    parser.add_argument("--variant-id", required=True)
    parser.add_argument("--backend-root", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--private-receipt-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.authorize_disposable_writes:
        raise SystemExit(
            "pass --authorize-disposable-writes after confirming the instance is disposable"
        )
    if args.out.exists() or args.out.is_symlink():
        raise FileExistsError(f"output already exists: {args.out}")
    key = os.environ.get(args.publishable_key_env)
    database_url = os.environ.get(args.database_url_env)
    if not key or not database_url:
        raise RuntimeError(
            "publishable key and database URL must be supplied through environment variables"
        )
    observations, provenance = acquire(
        base_url=args.base_url,
        publishable_key=key,
        region_id=args.region_id,
        variant_id=args.variant_id,
        backend_root=args.backend_root.resolve(strict=True),
        database_url=database_url,
        observed_at=args.observed_at,
        private_receipt_dir=args.private_receipt_dir,
    )
    args.out.mkdir(parents=True)
    _write_json(args.out / "observations.json", observations)
    _write_json(args.out / "provenance.json", provenance)
    print(json.dumps({"status": "passed", "output": str(args.out)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
