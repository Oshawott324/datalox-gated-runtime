#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "envs/optimade_cod_public_v0/evidence/core_get_capture.json"
COD_BASE = "https://www.crystallography.net/cod/optimade"
STRUCTURE_FIELDS = quote("id,chemical_formula_reduced,elements,nsites", safe="")
REFERENCE_FIELDS = quote("id,title,doi,year", safe="")
FILE_FIELDS = quote("id,url,name,media_type", safe="")
REQUESTS = (
    ("info_unversioned", f"{COD_BASE}/info", 200),
    ("info_v1", f"{COD_BASE}/v1/info", 200),
    ("info_v1_1_0", f"{COD_BASE}/v1.1.0/info", 200),
    ("info_v1_2_0", f"{COD_BASE}/v1.2.0/info", 200),
    ("info_v1_3_0", f"{COD_BASE}/v1.3.0/info", 200),
    ("structures_info_v1_3_0", f"{COD_BASE}/v1.3.0/info/structures", 200),
    ("references_info_v1_3_0", f"{COD_BASE}/v1.3.0/info/references", 200),
    ("files_info_v1_3_0", f"{COD_BASE}/v1.3.0/info/files", 200),
    ("links_v1_3_0", f"{COD_BASE}/v1.3.0/links", 200),
    (
        "structures_list_v1_3_0",
        f"{COD_BASE}/v1.3.0/structures?response_fields={STRUCTURE_FIELDS}&page_limit=2",
        200,
    ),
    (
        "structure_detail_v1_3_0",
        f"{COD_BASE}/v1.3.0/structures/1000000?response_fields={STRUCTURE_FIELDS}",
        200,
    ),
    (
        "references_list_v1_3_0",
        f"{COD_BASE}/v1.3.0/references?response_fields={REFERENCE_FIELDS}&page_limit=2",
        200,
    ),
    (
        "reference_detail_v1_3_0",
        f"{COD_BASE}/v1.3.0/references/1000000?response_fields={REFERENCE_FIELDS}",
        200,
    ),
    (
        "files_list_v1_3_0",
        f"{COD_BASE}/v1.3.0/files?response_fields={FILE_FIELDS}&page_limit=2",
        200,
    ),
    (
        "file_detail_v1_3_0",
        f"{COD_BASE}/v1.3.0/files/1000000.cif?response_fields={FILE_FIELDS}",
        200,
    ),
    (
        "structures_page_number_v1",
        f"{COD_BASE}/v1/structures?response_fields=id&page_limit=1&page_number=2",
        200,
    ),
    (
        "structures_page_offset_v1",
        f"{COD_BASE}/v1/structures?response_fields=id&page_limit=1&page_offset=1",
        200,
    ),
    (
        "references_page_number_v1_3_0",
        f"{COD_BASE}/v1.3.0/references?response_fields=id&page_limit=1&page_number=2",
        200,
    ),
    (
        "files_page_number_v1_3_0",
        f"{COD_BASE}/v1.3.0/files?response_fields=id&page_limit=1&page_number=2",
        200,
    ),
    (
        "structures_filter_v1_3_0",
        f"{COD_BASE}/v1.3.0/structures?filter=id%3D%221000000%22&response_fields={STRUCTURE_FIELDS}&page_limit=1",
        200,
    ),
    (
        "structures_sort_ignored_v1",
        f"{COD_BASE}/v1/structures?response_fields=id&page_limit=1&sort=-id",
        200,
    ),
    (
        "structures_cursor_ignored_v1",
        f"{COD_BASE}/v1/structures?response_fields=id&page_limit=1&page_cursor=1000001",
        200,
    ),
    (
        "structures_above_ignored_v1",
        f"{COD_BASE}/v1/structures?response_fields=id&page_limit=1&page_above=1000000",
        200,
    ),
    (
        "structures_below_ignored_v1",
        f"{COD_BASE}/v1/structures?response_fields=id&page_limit=1&page_below=1000001",
        200,
    ),
    ("api_hint_v1_3_unversioned_error", f"{COD_BASE}/info?api_hint=v1.3", 553),
    ("unsupported_version", f"{COD_BASE}/v2/info", 553),
    ("page_limit_exceeded", f"{COD_BASE}/v1/structures?page_limit=101", 403),
    ("include_unsupported_v1_3_0", f"{COD_BASE}/v1.3.0/structures?include=references", 400),
    ("format_unsupported_v1_3_0", f"{COD_BASE}/v1.3.0/structures?response_format=xml", 400),
    ("unknown_endpoint_v1_3_0", f"{COD_BASE}/v1.3.0/not-an-endpoint", 404),
    (
        "unknown_filter_property_v1_3_0",
        f"{COD_BASE}/v1.3.0/structures?filter=not_a_field%3D%221%22&page_limit=1",
        400,
    ),
    ("structure_absent_v1_3_0", f"{COD_BASE}/v1.3.0/structures/9999999", 200),
    ("versioned_api_hint_url_wins", f"{COD_BASE}/v1.3.0/info?api_hint=v1.1", 200),
    (
        "email_address_accepted",
        f"{COD_BASE}/v1/structures?response_fields=id&page_limit=1&email_address=agent%40example.test",
        200,
    ),
)
SAFE_HEADERS = ("content-type", "content-length", "date", "etag", "last-modified")
ALLOWED_HOST = "www.crystallography.net"


def fetch(capture_id: str, url: str, expected_status: int) -> dict[str, object]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST:
        raise ValueError(f"capture URL is outside the declared exact host: {url}")
    request = Request(
        url,
        method="GET",
        headers={
            "Accept": "application/vnd.api+json",
            "User-Agent": "datalox-optimade-core-evidence/1.0",
        },
    )
    try:
        response = urlopen(request, timeout=180)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        final_url = response.geturl()
        final_parsed = urlparse(final_url)
        if final_parsed.scheme != "https" or final_parsed.hostname != ALLOWED_HOST:
            raise ValueError(f"capture redirected outside the declared exact host: {final_url}")
        if response.status != expected_status:
            raise ValueError(
                f"unexpected status for {capture_id}: {response.status}; expected {expected_status}"
            )
        content_type = response.headers.get("content-type", "")
        body: object = json.loads(raw) if "json" in content_type.lower() and raw else raw.decode()
        return {
            "id": capture_id,
            "method": "GET",
            "url": url,
            "final_url": final_url,
            "status": response.status,
            "response_headers": {
                name: response.headers[name]
                for name in SAFE_HEADERS
                if response.headers.get(name) is not None
            },
            "captured_at": datetime.now(UTC).isoformat(),
            "body_sha256": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "body_bytes": len(raw),
            "body_representation": "parsed_json" if isinstance(body, (dict, list)) else "utf8_text",
            "body": body,
            "redaction": {"agent_auth_cookie_or_secret_headers_forwarded": False},
            "provenance": {
                "authentication": "credential_free",
                "environment": "public_production_read",
                "grounding_level": "G3_PUBLIC_PRODUCTION",
                "sandbox": False,
                "tenant": "none_public_catalog",
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    requested_at = datetime.now(UTC).isoformat()
    records = [fetch(capture_id, url, status) for capture_id, url, status in REQUESTS]
    payload = {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "optimade_cod",
        "implementation": "Crystallography Open Database OPTIMADE v0.13.0",
        "implementation_base_url": COD_BASE,
        "implementation_api_versions": ["1.1.0", "1.2.0", "1.3.0"],
        "allowed_hosts": [ALLOWED_HOST],
        "allowed_method": "GET",
        "authentication": "credential_free",
        "tenant": "none_public_catalog",
        "secret_headers_forwarded": False,
        "requested_at": requested_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "capture_count": len(records),
        "captures": records,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"path": str(args.out), "capture_count": len(records)}))


if __name__ == "__main__":
    main()
