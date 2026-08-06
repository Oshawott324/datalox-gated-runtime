#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

from datalox_gated_runtime.capture import LiveCaptureClient
from datalox_gated_runtime.models import CallRequest, LiveGateConfig, LiveUpstream


ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "envs/federal_register_public_v0"
OUTPUT = ENV / "evidence/core_get_capture.json"
OPENAPI_OUTPUT = ENV / "evidence/official_openapi.json"
BASE = "https://www.federalregister.gov/api/v1"
HOST = "www.federalregister.gov"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
DOCUMENTS = ("2025-09274", "2025-09293")
PUBLICATION_DATE = "2025-05-23"
AGENCY = "environmental-protection-agency"


def spec(
    identifier: str,
    path: str,
    *,
    query: tuple[tuple[str, str], ...] = (),
    status: int = 200,
    accept: str = "application/json",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "path": path,
        "query_pairs": query,
        "expected_status": status,
        "accept": accept,
    }


DOCUMENT_FIELDS = tuple(
    ("fields[]", field)
    for field in (
        "document_number",
        "title",
        "abstract",
        "publication_date",
        "effective_on",
        "type",
        "agencies",
        "topics",
        "docket_ids",
        "regulation_id_numbers",
        "significant",
        "cfr_references",
        "president",
        "executive_order_number",
    )
)
FACET_RANGE = (
    ("conditions[publication_date][gte]", "2025-05-20"),
    ("conditions[publication_date][lte]", PUBLICATION_DATE),
    ("conditions[agencies][]", AGENCY),
)

REQUESTS = (
    spec("documents_batch_json", f"/documents/{','.join(DOCUMENTS)}.json"),
    spec("documents_batch_partial_missing", f"/documents/{DOCUMENTS[0]},9999-99999.json"),
    spec(
        "document_single_csv_repeated_fields",
        f"/documents/{DOCUMENTS[0]}.csv",
        query=(("fields[]", "document_number"), ("fields[]", "title")),
        accept="text/csv",
    ),
    spec(
        "documents_batch_csv_repeated_fields",
        f"/documents/{','.join(DOCUMENTS)}.csv",
        query=(("fields[]", "document_number"), ("fields[]", "title")),
        accept="text/csv",
    ),
    spec(
        "documents_bounded_fixture",
        "/documents.json",
        query=(
            ("per_page", "100"),
            ("page", "1"),
            ("order", "oldest"),
            *DOCUMENT_FIELDS,
            ("conditions[publication_date][is]", PUBLICATION_DATE),
            ("conditions[agencies][]", AGENCY),
        ),
    ),
    spec(
        "documents_search_csv_repeated_controls",
        "/documents.csv",
        query=(
            ("fields[]", "document_number"),
            ("fields[]", "title"),
            ("per_page", "2"),
            ("page", "1"),
            ("order", "oldest"),
            ("conditions[publication_date][is]", PUBLICATION_DATE),
            ("conditions[agencies][]", AGENCY),
            ("conditions[type][]", "PRORULE"),
            ("conditions[sections][]", "environment"),
        ),
        accept="text/csv",
    ),
    spec(
        "documents_repeated_filter_arrays",
        "/documents.json",
        query=(
            ("per_page", "5"),
            ("page", "1"),
            *DOCUMENT_FIELDS,
            ("conditions[publication_date][year]", "2025"),
            ("conditions[agencies][]", AGENCY),
            ("conditions[agencies][]", "federal-aviation-administration"),
            ("conditions[type][]", "PRORULE"),
            ("conditions[type][]", "RULE"),
            ("conditions[sections][]", "environment"),
            ("conditions[sections][]", "science-and-technology"),
            ("conditions[topics][]", "environmental-protection"),
            ("conditions[topics][]", "air-pollution-control"),
        ),
    ),
    spec(
        "documents_publication_range",
        "/documents.json",
        query=(
            ("per_page", "5"),
            *DOCUMENT_FIELDS,
            ("conditions[publication_date][gte]", "2025-05-20"),
            ("conditions[publication_date][lte]", PUBLICATION_DATE),
            ("conditions[agencies][]", AGENCY),
        ),
    ),
    spec(
        "documents_effective_range",
        "/documents.json",
        query=(
            ("per_page", "5"),
            *DOCUMENT_FIELDS,
            ("conditions[effective_date][gte]", "2025-05-20"),
            ("conditions[effective_date][lte]", "2025-06-30"),
        ),
    ),
    spec(
        "documents_docket_control",
        "/documents.json",
        query=(
            ("per_page", "5"),
            *DOCUMENT_FIELDS,
            ("conditions[docket_id]", "EPA-R01-OAR-2025-0142"),
        ),
    ),
    spec(
        "documents_rin_control",
        "/documents.json",
        query=(
            ("per_page", "5"),
            *DOCUMENT_FIELDS,
            ("conditions[regulation_id_number]", "2060-AV82"),
        ),
    ),
    spec(
        "documents_significant_control",
        "/documents.json",
        query=(("per_page", "5"), *DOCUMENT_FIELDS, ("conditions[significant]", "1")),
    ),
    spec(
        "documents_cfr_control",
        "/documents.json",
        query=(
            ("per_page", "5"),
            *DOCUMENT_FIELDS,
            ("conditions[cfr][title]", "40"),
            ("conditions[cfr][part]", "52"),
        ),
    ),
    spec(
        "documents_near_control",
        "/documents.json",
        query=(
            ("per_page", "5"),
            *DOCUMENT_FIELDS,
            ("conditions[near][location]", "Montpelier, VT"),
            ("conditions[near][within]", "200"),
        ),
    ),
    spec(
        "documents_presidential_repeated_controls",
        "/documents.json",
        query=(
            ("per_page", "5"),
            ("order", "executive_order_number"),
            *DOCUMENT_FIELDS,
            ("conditions[publication_date][year]", "2025"),
            ("conditions[type][]", "PRESDOCU"),
            ("conditions[presidential_document_type][]", "executive_order"),
            ("conditions[presidential_document_type][]", "proclamation"),
            ("conditions[president][]", "donald-trump"),
            ("conditions[president][]", "joe-biden"),
        ),
    ),
    *tuple(
        spec(f"documents_{facet}_facet", f"/documents/facets/{facet}.json", query=FACET_RANGE)
        for facet in (
            "daily",
            "weekly",
            "monthly",
            "quarterly",
            "yearly",
            "agency",
            "topic",
            "section",
            "type",
            "subtype",
        )
    ),
    spec(
        "public_inspection_batch_json", f"/public-inspection-documents/{','.join(DOCUMENTS)}.json"
    ),
    spec(
        "public_inspection_batch_partial_missing",
        f"/public-inspection-documents/{DOCUMENTS[0]},9999-99999.json",
    ),
    spec(
        "public_inspection_current_json",
        "/public-inspection-documents/current.json",
    ),
    spec(
        "public_inspection_current_csv",
        "/public-inspection-documents/current.csv",
        accept="text/csv",
    ),
    spec(
        "public_inspection_search_csv_repeated_fields",
        "/public-inspection-documents.csv",
        query=(
            ("fields[]", "document_number"),
            ("fields[]", "title"),
            ("fields[]", "filing_type"),
            ("conditions[available_on]", "2025-05-22"),
        ),
        accept="text/csv",
    ),
    spec(
        "public_inspection_single_csv_native_error",
        f"/public-inspection-documents/{DOCUMENTS[0]}.csv",
        status=500,
        accept="text/csv",
    ),
    spec(
        "public_inspection_batch_csv_native_error",
        f"/public-inspection-documents/{','.join(DOCUMENTS)}.csv",
        status=500,
        accept="text/csv",
    ),
    spec("image_valid", "/images/EN02MR23.004.json"),
    spec("image_missing", "/images/NOT-A-REAL-IMAGE.json", status=404),
    spec("suggested_searches_all", "/suggested_searches.json"),
)


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self._transport = httpx.HTTPTransport(retries=2)
        self.last_request: dict[str, Any] | None = None
        self.last_response: dict[str, Any] | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        parsed = urlparse(str(request.url))
        if request.method != "GET" or parsed.scheme != "https" or parsed.hostname != HOST:
            raise ValueError(
                f"unsafe Federal Register evidence request: {request.method} {request.url}"
            )
        self.last_request = {
            "method": request.method,
            "url": str(request.url),
            "authorization_present": "authorization" in request.headers,
            "cookie_present": "cookie" in request.headers,
        }
        response = self._transport.handle_request(request)
        self.last_response = {
            "status": response.status_code,
            "headers": {
                key: response.headers[key]
                for key in ("content-type", "content-length", "date", "etag", "last-modified")
                if key in response.headers
            },
        }
        return response

    def close(self) -> None:
        self._transport.close()


def serialized(body: Any) -> bytes:
    if isinstance(body, str):
        return body.encode()
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _resolve_openapi(document: dict[str, Any], value: Any) -> Any:
    if not isinstance(value, dict) or set(value) != {"$ref"}:
        return value
    reference = value["$ref"]
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise ValueError(f"unsupported OpenAPI reference: {reference!r}")
    resolved: Any = document
    for segment in reference[2:].split("/"):
        resolved = resolved[segment.replace("~1", "/").replace("~0", "~")]
    return resolved


def _schema_inventory(document: dict[str, Any], schema: Any) -> dict[str, Any]:
    schema = _resolve_openapi(document, schema)
    if not isinstance(schema, dict):
        return {}
    result = {
        key: schema[key]
        for key in ("type", "format", "enum", "pattern", "minimum", "maximum")
        if key in schema
    }
    if "items" in schema:
        result["items"] = _schema_inventory(document, schema["items"])
    return result


def openapi_inventory(document: dict[str, Any]) -> dict[str, Any]:
    inventory: dict[str, Any] = {}
    for path, raw_path_item in sorted(document.get("paths", {}).items()):
        path_item = _resolve_openapi(document, raw_path_item)
        if not isinstance(path_item, dict):
            continue
        shared_parameters = path_item.get("parameters", [])
        operations: dict[str, Any] = {}
        for method, raw_operation in sorted(path_item.items()):
            if method.lower() not in HTTP_METHODS:
                continue
            operation = _resolve_openapi(document, raw_operation)
            if not isinstance(operation, dict):
                continue
            parameters = []
            for raw_parameter in [*shared_parameters, *operation.get("parameters", [])]:
                parameter = _resolve_openapi(document, raw_parameter)
                if not isinstance(parameter, dict):
                    continue
                parameters.append(
                    {
                        "name": parameter.get("name"),
                        "in": parameter.get("in"),
                        "required": bool(parameter.get("required", False)),
                        "schema": _schema_inventory(document, parameter.get("schema", {})),
                    }
                )
            content_types = {
                content_type
                for response in operation.get("responses", {}).values()
                for content_type in (
                    _resolve_openapi(document, response).get("content", {})
                    if isinstance(_resolve_openapi(document, response), dict)
                    else {}
                )
            }
            format_values = {
                str(value)
                for parameter in parameters
                if parameter["name"] == "format"
                for value in parameter["schema"].get("enum", [])
            }
            operations[method.upper()] = {
                "parameters": sorted(
                    parameters,
                    key=lambda item: (str(item["in"]), str(item["name"])),
                ),
                "formats": sorted(content_types | format_values),
            }
        inventory[path] = operations
    return inventory


def _body_shape(body: Any) -> Any:
    if isinstance(body, dict):
        return {key: _body_shape(value) for key, value in sorted(body.items())}
    if isinstance(body, list):
        return {
            "type": "array",
            "item": _body_shape(body[0]) if body else None,
        }
    if isinstance(body, str):
        first_line = body.splitlines()[0] if body else ""
        return {"type": "text", "header": first_line if "," in first_line else None}
    if body is None:
        return "null"
    return type(body).__name__


def capture_inventory(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        item["id"]: {
            "status": item["status"],
            "content_type": str(item.get("response_headers", {}).get("content-type", ""))
            .split(";", 1)[0]
            .strip()
            .lower(),
            "body_representation": item["body_representation"],
            "body_shape": _body_shape(item["body"]),
        }
        for item in records
    }


def drift_report(records: list[dict[str, Any]], openapi: dict[str, Any]) -> dict[str, Any]:
    pinned_capture = json.loads(OUTPUT.read_text(encoding="utf-8"))
    pinned_openapi = json.loads(OPENAPI_OUTPUT.read_text(encoding="utf-8"))
    expected_api = openapi_inventory(pinned_openapi)
    actual_api = openapi_inventory(openapi)
    expected_paths = set(expected_api)
    actual_paths = set(actual_api)
    common_operations = {
        (path, method)
        for path in expected_paths & actual_paths
        for method in set(expected_api[path]) & set(actual_api[path])
    }
    expected_behavior = capture_inventory(pinned_capture["captures"])
    actual_behavior = capture_inventory(records)
    expected_ids = set(expected_behavior)
    actual_ids = set(actual_behavior)
    report = {
        "schema_version": "datalox_federal_register_drift_v1",
        "openapi": {
            "added_paths": sorted(actual_paths - expected_paths),
            "removed_paths": sorted(expected_paths - actual_paths),
            "method_changes": {
                path: {
                    "expected": sorted(expected_api[path]),
                    "actual": sorted(actual_api[path]),
                }
                for path in sorted(expected_paths & actual_paths)
                if set(expected_api[path]) != set(actual_api[path])
            },
            "parameter_changes": [
                {"path": path, "method": method}
                for path, method in sorted(common_operations)
                if expected_api[path][method]["parameters"]
                != actual_api[path][method]["parameters"]
            ],
            "format_changes": [
                {"path": path, "method": method}
                for path, method in sorted(common_operations)
                if expected_api[path][method]["formats"] != actual_api[path][method]["formats"]
            ],
        },
        "behavior": {
            "added_capture_ids": sorted(actual_ids - expected_ids),
            "removed_capture_ids": sorted(expected_ids - actual_ids),
            "status_changes": {
                identifier: {
                    "expected": expected_behavior[identifier]["status"],
                    "actual": actual_behavior[identifier]["status"],
                }
                for identifier in sorted(expected_ids & actual_ids)
                if expected_behavior[identifier]["status"] != actual_behavior[identifier]["status"]
            },
            "content_type_changes": sorted(
                identifier
                for identifier in expected_ids & actual_ids
                if expected_behavior[identifier]["content_type"]
                != actual_behavior[identifier]["content_type"]
            ),
            "shape_changes": sorted(
                identifier
                for identifier in expected_ids & actual_ids
                if expected_behavior[identifier]["body_representation"]
                != actual_behavior[identifier]["body_representation"]
                or expected_behavior[identifier]["body_shape"]
                != actual_behavior[identifier]["body_shape"]
            ),
        },
    }
    report["drift_detected"] = any(
        value for section in (report["openapi"], report["behavior"]) for value in section.values()
    )
    return report


def capture(item: dict[str, Any]) -> dict[str, Any]:
    transport = RecordingTransport()
    client = LiveCaptureClient(
        LiveGateConfig(
            upstreams={
                "fr": LiveUpstream(
                    base_url=BASE,
                    static_headers={
                        "accept": item["accept"],
                        "user-agent": "datalox-federal-register-core-evidence/1.0",
                    },
                )
            }
        ),
        timeout=120,
        transport=transport,
    )
    query: dict[str, str | list[str]] = {}
    for key, value in item["query_pairs"]:
        existing = query.get(key)
        if existing is None:
            query[key] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            query[key] = [existing, value]
    try:
        response = client.fetch(CallRequest("GET", f"/fr{item['path']}", query=query))  # type: ignore[arg-type]
    finally:
        client.close()
    if response.status_code != item["expected_status"]:
        raise ValueError(
            f"unexpected status for {item['id']}: {response.status_code} != {item['expected_status']}; "
            f"body={str(response.body)[:300]}"
        )
    if transport.last_request is None or transport.last_response is None:
        raise ValueError(f"transport record missing for {item['id']}")
    if transport.last_request["authorization_present"] or transport.last_request["cookie_present"]:
        raise ValueError(f"secret header observed for {item['id']}")
    content = serialized(response.body)
    suffix = urlencode(item["query_pairs"])
    return {
        "id": item["id"],
        "method": "GET",
        "url": f"{BASE}{item['path']}" + (f"?{suffix}" if suffix else ""),
        "path": item["path"],
        "query": query,
        "query_pairs": [list(pair) for pair in item["query_pairs"]],
        "request_headers": {"accept": item["accept"]},
        "status": response.status_code,
        "response_headers": transport.last_response["headers"],
        "captured_at": datetime.now(UTC).isoformat(),
        "body_sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
        "body_bytes": len(content),
        "body_representation": "decoded_text" if isinstance(response.body, str) else "parsed_json",
        "body": response.body,
        "redaction": {
            "agent_auth_cookie_or_secret_headers_forwarded": False,
            "cookies_persisted": False,
        },
        "provenance": {
            "authentication": "credential_free",
            "environment": "public_production_read",
            "grounding_level": "G3_PUBLIC_PRODUCTION",
            "sandbox": False,
            "capture_path": "datalox_gated_runtime.capture.LiveCaptureClient",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--refresh-pinned", action="store_true")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--openapi-out", type=Path)
    args = parser.parse_args()
    if (
        sum((args.check, args.refresh_pinned, args.out is not None or args.openapi_out is not None))
        != 1
    ):
        parser.error("choose exactly one of --check, --refresh-pinned, or explicit temp outputs")
    if (args.out is None) != (args.openapi_out is None):
        parser.error("--out and --openapi-out must be supplied together")
    requested_at = datetime.now(UTC).isoformat()
    records = [capture(dict(item)) for item in REQUESTS]
    openapi = capture(spec("official_openapi", "/documentation.json"))
    if not isinstance(openapi["body"], dict) or openapi["body"].get("openapi") != "3.0.0":
        raise ValueError("official Federal Register OpenAPI response is invalid")
    if args.check:
        report = drift_report(records, openapi["body"])
        print(json.dumps(report, indent=2, sort_keys=True))
        if report["drift_detected"]:
            raise SystemExit(1)
        return
    output = OUTPUT if args.refresh_pinned else args.out
    openapi_output = OPENAPI_OUTPUT if args.refresh_pinned else args.openapi_out
    assert output is not None and openapi_output is not None
    output.parent.mkdir(parents=True, exist_ok=True)
    openapi_output.parent.mkdir(parents=True, exist_ok=True)
    openapi_output.write_text(
        json.dumps(openapi["body"], separators=(",", ":"), sort_keys=False), encoding="utf-8"
    )
    payload = {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "federal_register",
        "implementation": "FederalRegister.gov API v1",
        "implementation_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": "GET",
        "secret_headers_forwarded": False,
        "cookies_persisted": False,
        "requested_at": requested_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "capture_count": len(records),
        "captures": records,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "path": str(output),
                "openapi_path": str(openapi_output),
                "capture_count": len(records),
            }
        )
    )


if __name__ == "__main__":
    main()
