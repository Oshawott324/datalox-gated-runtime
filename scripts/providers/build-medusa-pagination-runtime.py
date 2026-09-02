#!/usr/bin/env python3
"""Compile identifier-free G2 observations into a bounded replay source config."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _ordinal(handle: str) -> int:
    prefix = "datalox-pagination-item-"
    if not handle.startswith(prefix):
        raise ValueError(f"unexpected self-authored handle: {handle}")
    value = int(handle.removeprefix(prefix))
    if value < 1 or value > 50:
        raise ValueError(f"fixture ordinal out of range: {value}")
    return value


def _product(handle: str) -> dict[str, Any]:
    ordinal = _ordinal(handle)
    label = f"{ordinal:03d}"
    return {
        "id": f"prod_datalox_pagination_{label}",
        "title": f"Datalox Pagination Item {label}",
        "handle": handle,
        "description": "Self-authored synthetic product for a bounded Medusa pagination fixture.",
        "variants": [
            {
                "id": f"variant_datalox_pagination_{label}",
                "title": "Standard",
                "sku": f"DATALOX-PAGINATION-{label}",
                "calculated_price": {
                    "calculated_amount": 1000 + ordinal - 1,
                    "currency_code": "usd",
                },
            }
        ],
    }


def build(observations_path: Path, output_path: Path) -> None:
    evidence = json.loads(observations_path.read_text(encoding="utf-8"))
    rows = evidence.get("observations")
    if not isinstance(rows, list) or len(rows) != 16:
        raise ValueError("Medusa pagination evidence must contain the checked 16 observations")

    cases: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        query = row.get("query")
        response = row.get("response")
        if not isinstance(query, dict) or not isinstance(response, dict):
            raise TypeError("invalid observation")
        if row.get("gate_path") != "/medusa/store/products":
            raise ValueError("observation is not bound to the Medusa authoring gate path")
        upstream_path = row.get("upstream_path")
        if upstream_path != "/store/products":
            raise ValueError("observation is not bound to the native Medusa Store path")
        key = (str(query.get("limit")), str(query.get("offset")))
        body: dict[str, Any]
        handles = response.get("product_handles")
        if isinstance(handles, list):
            body = {
                "products": [_product(handle) for handle in handles],
                "count": response["count"],
                "offset": response["offset"],
                "limit": response["limit"],
            }
        else:
            body = {field: response[field] for field in ("code", "type") if field in response}
            body["message"] = (
                "Invalid pagination parameter."
                if response.get("type") == "invalid_data"
                else "The pagination parameter is outside this fixture's supported range."
            )
        case = {
            "case_id": f"medusa:store.products:list:limit-{key[0]}:offset-{key[1]}",
            "method": "GET",
            "path": upstream_path,
            "query": {"limit": key[0], "offset": key[1]},
            "status_code": row["status_code"],
            "body": body,
            "evidence_ref": f"medusa-pagination-g2:{row['request_index']}",
        }
        prior = cases.get(key)
        if prior is not None:
            if (prior["status_code"], prior["body"]) != (case["status_code"], case["body"]):
                raise ValueError(f"identical request changed during capture: {key}")
            continue
        cases[key] = case

    payload = {
        "config_id": "medusa_store_pagination_v0",
        "metadata": {
            "provider": "medusa",
            "provider_version": "2.16.0",
            "grounded_operation": "medusa.store.products.list",
            "grounding_level": "G2",
            "grounding_artifact_sha256": _sha256(observations_path),
            "fixture_data": "self_authored_synthetic",
            "scope": "bounded_store_products_limit_offset",
            "known_gaps": [
                "Product field values and identifiers are self-authored.",
                "Only the captured limit/offset query variants are executable.",
                "Provider auth, headers, raw bytes, writes, rate limits, and production behavior are outside this release.",
            ],
        },
        "response_cases": list(cases.values()),
        "audit_rules": [],
        "policy": {
            "deny": [
                {
                    "method": "POST",
                    "path_prefix": "/store/products",
                    "reason_code": "medusa_pagination_read_only",
                    "message": "This admitted provider release contains only the grounded Store product-list read slice.",
                },
                {
                    "method": "PATCH",
                    "path_prefix": "/store/products",
                    "reason_code": "medusa_pagination_read_only",
                    "message": "This admitted provider release contains only the grounded Store product-list read slice.",
                },
                {
                    "method": "DELETE",
                    "path_prefix": "/store/products",
                    "reason_code": "medusa_pagination_read_only",
                    "message": "This admitted provider release contains only the grounded Store product-list read slice.",
                },
            ],
            "shadow_write": [],
            "live_capture": [],
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    build(args.observations.resolve(strict=True), args.out.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
