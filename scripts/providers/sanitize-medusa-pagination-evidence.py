#!/usr/bin/env python3
"""Reduce a local Medusa probe run to the bounded, identifier-free evidence lane."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROBE_CONFIG = ROOT / "probes" / "medusa_pagination.json"


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _product_label(product: Any) -> str:
    if not isinstance(product, dict):
        raise TypeError("captured product is not an object")
    handle = product.get("handle")
    if not isinstance(handle, str) or not handle.startswith("datalox-pagination-item-"):
        raise ValueError("captured product is not one of the self-authored pagination fixtures")
    return handle


def sanitize(run_dir: Path, output_path: Path, probe_config_path: Path) -> None:
    rows = [
        json.loads(line)
        for line in (run_dir / "captures.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    probe_config = json.loads(probe_config_path.read_text(encoding="utf-8"))
    provider_id = probe_config.get("provider_id")
    probe_requests = probe_config.get("probe_requests")
    if provider_id != "medusa":
        raise ValueError("the pinned probe config is not for Medusa")
    if not isinstance(probe_requests, list) or len(probe_requests) != len(rows):
        raise ValueError("capture count does not match the pinned probe request sequence")

    observations: list[dict[str, Any]] = []
    for request_index, (row, probe_request) in enumerate(zip(rows, probe_requests, strict=True)):
        if not isinstance(probe_request, dict):
            raise TypeError(f"probe request {request_index} is not an object")
        upstream_path = probe_request.get("path")
        if not isinstance(upstream_path, str) or not upstream_path.startswith("/"):
            raise ValueError(f"probe request {request_index} has an invalid upstream path")
        gate_path = f"/{provider_id}{upstream_path}"
        if row.get("path") != gate_path:
            raise ValueError(
                f"capture {request_index} gate path does not match the pinned probe projection"
            )
        if row.get("method") != probe_request.get("method"):
            raise ValueError(f"capture {request_index} method does not match the pinned probe")
        if row.get("query") != probe_request.get("query"):
            raise ValueError(f"capture {request_index} query does not match the pinned probe")
        body = row.get("body")
        observation: dict[str, Any] = {
            "request_index": request_index,
            "method": row.get("method"),
            "gate_path": gate_path,
            "upstream_path": upstream_path,
            "query": row.get("query"),
            "status_code": row.get("status_code"),
            "canonical_body_sha256": _digest(body),
        }
        if isinstance(body, dict) and isinstance(body.get("products"), list):
            observation["response"] = {
                "top_level_fields": list(body),
                "count": body.get("count"),
                "offset": body.get("offset"),
                "limit": body.get("limit"),
                "product_handles": [_product_label(product) for product in body["products"]],
            }
        elif isinstance(body, dict):
            observation["response"] = {key: body[key] for key in ("code", "type") if key in body}
            message = body.get("message")
            observation["response"]["message_present"] = isinstance(message, str) and bool(message)
            observation["response"]["message_sha256"] = _digest(message)
        else:
            raise TypeError(f"captured body {request_index} is not an object")
        observations.append(observation)

    payload = {
        "schema_version": "datalox_medusa_pagination_observations_v2",
        "provider": "medusa",
        "provider_version": "2.16.0",
        "grounding_level": "G2",
        "capture_transport": "datalox_get_probe_v0",
        "capture_path_projection": {
            "gate_path_template": "/{provider_id}{upstream_path}",
            "provider_id": provider_id,
            "probe_config_path": "probes/medusa_pagination.json",
            "probe_config_sha256": _sha256(probe_config_path),
            "upstream_path_source": "probe_requests[*].path",
            "upstream_projection": "strip_first_gate_path_segment_v1",
        },
        "payload_policy": "provider-generated IDs and response text removed; self-authored product handles and factual measurements retained",
        "observations": observations,
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    forbidden = ("authorization", "publishable_api_key", "admin_jwt", "eyJ")
    lowered = encoded.lower()
    if any(term.lower() in lowered for term in forbidden):
        raise ValueError("sanitized evidence still contains an auth or secret marker")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(encoded, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--probe-config", type=Path, default=DEFAULT_PROBE_CONFIG)
    args = parser.parse_args()
    sanitize(
        args.run.resolve(strict=True),
        args.out.resolve(),
        args.probe_config.resolve(strict=True),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
