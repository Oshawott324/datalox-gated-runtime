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
OUTPUT = ROOT / "envs/federal_register_public_v0/evidence/public_get_capture.json"
BASE = "https://www.federalregister.gov/api/v1"
HOST = "www.federalregister.gov"
DOCUMENT = "2025-09274"
OFF_CHAIN_DOCUMENT = "2025-09293"
AGENCY = "environmental-protection-agency"
PUBLICATION_DATE = "2025-05-23"
PUBLIC_INSPECTION_DATE = "2025-05-22"
SUGGESTED_SEARCH = "endangered-threatened-species"
JSON_ACCEPT = "application/json"


def request(
    capture_id: str,
    path: str,
    *,
    query: list[tuple[str, str]] | None = None,
    status: int = 200,
) -> dict[str, Any]:
    return {
        "id": capture_id,
        "path": path,
        "query": query or [],
        "accept": JSON_ACCEPT,
        "expected_status": status,
    }


FILTERED_DOCUMENTS = [
    ("per_page", "2"),
    ("order", "oldest"),
    ("conditions[publication_date][is]", PUBLICATION_DATE),
    ("conditions[agencies][]", AGENCY),
    ("conditions[type][]", "PRORULE"),
    ("conditions[sections][]", "environment"),
]
FACET_FILTERS = [
    ("conditions[publication_date][is]", PUBLICATION_DATE),
    ("conditions[agencies][]", AGENCY),
    ("conditions[sections][]", "environment"),
]
REQUESTS = (
    request(
        "documents_filtered_page_1", "/documents.json", query=[("page", "1"), *FILTERED_DOCUMENTS]
    ),
    request(
        "documents_filtered_page_2", "/documents.json", query=[("page", "2"), *FILTERED_DOCUMENTS]
    ),
    request(
        "documents_filtered_page_3", "/documents.json", query=[("page", "3"), *FILTERED_DOCUMENTS]
    ),
    request(
        "documents_filtered_page_4_empty",
        "/documents.json",
        query=[("page", "4"), *FILTERED_DOCUMENTS],
    ),
    request(
        "documents_single_field_projection",
        "/documents.json",
        query=[
            ("per_page", "2"),
            ("page", "1"),
            ("order", "oldest"),
            ("fields[]", "document_number"),
            ("conditions[publication_date][is]", PUBLICATION_DATE),
            ("conditions[agencies][]", AGENCY),
            ("conditions[type][]", "PRORULE"),
            ("conditions[sections][]", "environment"),
        ],
    ),
    request(
        "documents_presidential_projected",
        "/documents.json",
        query=[
            ("per_page", "2"),
            ("page", "1"),
            ("order", "executive_order_number"),
            ("conditions[publication_date][year]", "2025"),
            ("conditions[type][]", "PRESDOCU"),
            ("conditions[presidential_document_type][]", "executive_order"),
            ("conditions[president][]", "donald-trump"),
        ],
    ),
    request("document_detail", f"/documents/{DOCUMENT}.json"),
    request("document_off_chain_detail", f"/documents/{OFF_CHAIN_DOCUMENT}.json"),
    request("agencies_catalog", "/agencies.json"),
    request("agency_epa", f"/agencies/{AGENCY}.json"),
    request(
        "agency_suggestions_environment",
        "/agencies/suggestions.json",
        query=[("conditions[term]", "environment")],
    ),
    request(
        "public_inspection_issue",
        "/public-inspection-documents.json",
        query=[("conditions[available_on]", PUBLIC_INSPECTION_DATE)],
    ),
    request(
        "public_inspection_current_page",
        "/public-inspection-documents.json",
        query=[("per_page", "2"), ("page", "1"), ("order", "newest")],
    ),
    request(
        "public_inspection_filtered_search",
        "/public-inspection-documents.json",
        query=[
            ("per_page", "2"),
            ("page", "1"),
            ("order", "newest"),
            ("conditions[term]", "Medicaid"),
            ("conditions[agencies][]", "centers-for-medicare-medicaid-services"),
            ("conditions[type][]", "PRORULE"),
            ("conditions[special_filing]", "1"),
        ],
    ),
    request("public_inspection_detail", f"/public-inspection-documents/{DOCUMENT}.json"),
    request("issue_detail", f"/issues/{PUBLICATION_DATE}.json"),
    request("sections_catalog", "/sections.json"),
    request("topics_catalog", "/topics.json"),
    request("documents_type_facet", "/documents/facets/type.json", query=FACET_FILTERS),
    request("documents_topic_facet", "/documents/facets/topic.json", query=FACET_FILTERS),
    request(
        "documents_section_facet",
        "/documents/facets/section.json",
        query=FACET_FILTERS[:2],
    ),
    request(
        "suggested_searches_environment",
        "/suggested_searches.json",
        query=[("conditions[sections]", "environment")],
    ),
    request("suggested_search_detail", f"/suggested_searches/{SUGGESTED_SEARCH}.json"),
    request(
        "documents_empty_future",
        "/documents.json",
        query=[
            ("per_page", "2"),
            ("page", "1"),
            ("order", "oldest"),
            ("fields[]", "document_number"),
            ("conditions[publication_date][is]", "2099-01-01"),
        ],
    ),
    request(
        "public_inspection_empty_future",
        "/public-inspection-documents.json",
        query=[("conditions[available_on]", "2099-01-01")],
    ),
    request(
        "documents_invalid_date",
        "/documents.json",
        query=[("conditions[publication_date][is]", "not-a-date")],
        status=400,
    ),
    request("issue_invalid_date", "/issues/not-a-date.json", status=400),
    request(
        "public_inspection_invalid_date",
        "/public-inspection-documents.json",
        query=[("conditions[available_on]", "not-a-date")],
        status=500,
    ),
    request("document_missing", "/documents/9999-99999.json", status=404),
    request("agency_missing", "/agencies/not-a-real-agency.json", status=404),
    request(
        "public_inspection_missing",
        "/public-inspection-documents/9999-99999.json",
        status=404,
    ),
    request("issue_missing", "/issues/2099-01-01.json", status=404),
    request("documents_invalid_facet", "/documents/facets/president.json", status=404),
    request(
        "suggested_search_missing",
        "/suggested_searches/not-a-real-search.json",
        status=404,
    ),
)


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self._transport = httpx.HTTPTransport(retries=2)
        self.last_request: dict[str, Any] | None = None
        self.last_response: dict[str, Any] | None = None

    def handle_request(self, request_: httpx.Request) -> httpx.Response:
        if request_.method != "GET":
            raise ValueError("Federal Register evidence capture may issue only GET requests")
        parsed = urlparse(str(request_.url))
        if parsed.scheme != "https" or parsed.hostname != HOST:
            raise ValueError(
                f"Federal Register evidence request escaped the exact HTTPS host: {request_.url}"
            )
        self.last_request = {
            "method": request_.method,
            "url": str(request_.url),
            "accept": request_.headers.get("accept"),
            "authorization_present": "authorization" in request_.headers,
            "cookie_present": "cookie" in request_.headers,
        }
        response = self._transport.handle_request(request_)
        self.last_response = {
            "status": response.status_code,
            "headers": {
                name: response.headers[name]
                for name in ("content-type", "content-length", "date", "etag", "last-modified")
                if response.headers.get(name) is not None
            },
        }
        return response

    def close(self) -> None:
        self._transport.close()


def body_bytes(body: Any) -> bytes:
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def capture(spec: dict[str, Any]) -> dict[str, Any]:
    transport = RecordingTransport()
    live = LiveGateConfig(
        upstreams={
            "fr": LiveUpstream(
                base_url=BASE,
                static_headers={
                    "accept": spec["accept"],
                    "user-agent": "datalox-federal-register-public-evidence/1.0",
                },
            )
        }
    )
    client = LiveCaptureClient(live, timeout=120, transport=transport)
    try:
        response = client.fetch(CallRequest("GET", f"/fr{spec['path']}", query=list(spec["query"])))
    finally:
        client.close()
    if response.status_code != spec["expected_status"]:
        raise ValueError(
            f"unexpected status for {spec['id']}: {response.status_code}; "
            f"expected {spec['expected_status']}; body={str(response.body)[:500]}"
        )
    if transport.last_request is None or transport.last_response is None:
        raise ValueError(f"transport evidence missing for {spec['id']}")
    if transport.last_request["authorization_present"] or transport.last_request["cookie_present"]:
        raise ValueError(f"secret-bearing request header observed for {spec['id']}")
    serialized = body_bytes(response.body)
    query = urlencode(spec["query"])
    url = f"{BASE}{spec['path']}" + (f"?{query}" if query else "")
    return {
        "id": spec["id"],
        "method": "GET",
        "url": url,
        "path": spec["path"],
        "query": dict(spec["query"]),
        "request_headers": {"accept": spec["accept"]},
        "status": response.status_code,
        "response_headers": transport.last_response["headers"],
        "captured_at": datetime.now(UTC).isoformat(),
        "body_sha256": f"sha256:{hashlib.sha256(serialized).hexdigest()}",
        "body_bytes": len(serialized),
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
    parser.add_argument("--refresh-pinned", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.refresh_pinned == (args.out is not None):
        parser.error("choose exactly one of --refresh-pinned or an explicit --out path")
    output = OUTPUT if args.refresh_pinned else args.out
    assert output is not None
    requested_at = datetime.now(UTC).isoformat()
    records = [capture(dict(spec)) for spec in REQUESTS]
    payload = {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "federal_register",
        "implementation": "FederalRegister.gov API v1",
        "implementation_base_url": BASE,
        "selected_document_number": DOCUMENT,
        "selected_agency_slug": AGENCY,
        "selected_publication_date": PUBLICATION_DATE,
        "selected_public_inspection_date": PUBLIC_INSPECTION_DATE,
        "official_edition_note": "FederalRegister.gov XML/HTML is informational; linked govinfo PDF is the official legal edition.",
        "allowed_host": HOST,
        "allowed_method": "GET",
        "secret_headers_forwarded": False,
        "cookies_persisted": False,
        "requested_at": requested_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "capture_count": len(records),
        "captures": records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"path": str(output), "capture_count": len(records)}))


if __name__ == "__main__":
    main()
