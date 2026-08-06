#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "envs/optimade_cod_public_v0/evidence/public_get_capture.json"
COD_BASE = "https://www.crystallography.net/cod/optimade"
PROVIDERS_BASE = "https://providers.optimade.org"
STRUCTURE_FIELDS = "chemical_formula_reduced%2Celements%2Cnsites"
REFERENCE_FIELDS = "title%2Cdoi%2Cyear"
REQUESTS = (
    ("official_provider_registry", f"{PROVIDERS_BASE}/v1/links", 200),
    ("official_cod_index", f"{PROVIDERS_BASE}/index-metadbs/cod/v1/links", 200),
    ("versions", f"{COD_BASE}/versions", 200),
    ("info", f"{COD_BASE}/v1/info", 200),
    ("structures_info", f"{COD_BASE}/v1/info/structures", 200),
    ("references_info", f"{COD_BASE}/v1/info/references", 200),
    ("links", f"{COD_BASE}/v1/links", 200),
    (
        "structures_page_1",
        f"{COD_BASE}/v1/structures?response_fields={STRUCTURE_FIELDS}&page_limit=1&page_offset=0",
        200,
    ),
    (
        "structures_page_2",
        f"{COD_BASE}/v1/structures?response_fields={STRUCTURE_FIELDS}&page_limit=1&page_offset=1",
        200,
    ),
    (
        "structure_linked_search",
        f"{COD_BASE}/v1/structures?filter=id%3D%221000000%22&response_fields={STRUCTURE_FIELDS}&sort=id&response_format=json&page_limit=1&page_offset=0",
        200,
    ),
    (
        "structure_detail",
        f"{COD_BASE}/v1/structures/1000000?response_fields={STRUCTURE_FIELDS}&response_format=json",
        200,
    ),
    (
        "reference_linked_search",
        f"{COD_BASE}/v1/references?filter=id%3D%221000000%22&response_fields={REFERENCE_FIELDS}&sort=id&response_format=json&page_limit=1&page_offset=0",
        200,
    ),
    (
        "reference_detail",
        f"{COD_BASE}/v1/references/1000000?response_fields={REFERENCE_FIELDS}&response_format=json",
        200,
    ),
    (
        "structure_off_chain_search",
        f"{COD_BASE}/v1/structures?filter=id%3D%221000001%22&response_fields={STRUCTURE_FIELDS}&sort=id&response_format=json&page_limit=1&page_offset=0",
        200,
    ),
    (
        "reference_off_chain_detail",
        f"{COD_BASE}/v1/references/1000001?response_fields={REFERENCE_FIELDS}&response_format=json",
        200,
    ),
    ("structure_absent", f"{COD_BASE}/v1/structures/9999999", 200),
    (
        "invalid_filter",
        f"{COD_BASE}/v1/structures?filter=not_a_field%3D%221%22&page_limit=1",
        400,
    ),
    (
        "invalid_format",
        f"{COD_BASE}/v1/structures?response_format=xml&page_limit=1",
        400,
    ),
    (
        "unsupported_include",
        f"{COD_BASE}/v1/structures?include=references&page_limit=1",
        400,
    ),
)
SAFE_HEADERS = (
    "content-type",
    "content-length",
    "date",
    "etag",
    "last-modified",
)
ALLOWED_HOSTS = {"www.crystallography.net", "providers.optimade.org"}


def fetch(capture_id: str, url: str, expected_status: int) -> dict[str, object]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"capture URL is outside the declared exact hosts: {url}")
    request = Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "datalox-optimade-evidence/1.0"},
    )
    try:
        response = urlopen(request, timeout=120)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        final_url = response.geturl()
        final_parsed = urlparse(final_url)
        if final_parsed.scheme != "https" or final_parsed.hostname not in ALLOWED_HOSTS:
            raise ValueError(f"capture redirected outside the declared exact hosts: {final_url}")
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
        "implementation": "Crystallography Open Database OPTIMADE",
        "implementation_base_url": COD_BASE,
        "implementation_api_version": "1.1.0",
        "discovery_source": f"{PROVIDERS_BASE}/v1/links",
        "allowed_hosts": sorted(ALLOWED_HOSTS),
        "allowed_method": "GET",
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
