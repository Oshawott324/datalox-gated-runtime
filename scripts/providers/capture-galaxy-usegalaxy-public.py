#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "envs/galaxy_usegalaxy_public_v0/evidence/public_get_capture.json"
BASE = "https://usegalaxy.org"
HOST = "usegalaxy.org"
TOOL_LINEAGE = "toolshed.g2.bx.psu.edu/repos/iuc/staramr/staramr_search"
TOOL = f"{TOOL_LINEAGE}/0.11.0+galaxy3"
WORKFLOW = "f8fab0cd6fc30d92"
HISTORY = "836d881feaa0bad1"
DATASET = "4690812943e4fee0"
WORKFLOW_QUERY = {
    "show_published": "true",
    "search": "user:iwc is:published",
    "limit": "1",
    "offset": "0",
    "sort_by": "name",
    "sort_desc": "false",
}
HISTORY_QUERY = {
    "q": "name",
    "qv": "ObtainingHighQualityReads",
    "limit": "2",
    "offset": "0",
    "order": "update_time-asc",
}
STATIC_REQUESTS = (
    ("version", f"{BASE}/api/version", 200),
    ("configuration", f"{BASE}/api/configuration", 200),
    ("openapi", f"{BASE}/openapi.json", 200),
    (
        "tool_search",
        f"{BASE}/api/tools?{urlencode({'q': 'staramr', 'in_panel': 'false'})}",
        200,
    ),
    (
        "tool_versions",
        f"{BASE}/api/tools?{urlencode({'tool_id': TOOL_LINEAGE, 'in_panel': 'false'})}",
        200,
    ),
    (
        "tool_detail",
        f"{BASE}/api/tools/{TOOL}?{urlencode({'io_details': 'false', 'link_details': 'true'})}",
        200,
    ),
    (
        "tool_schema",
        f"{BASE}/api/tools/{TOOL}?{urlencode({'io_details': 'true', 'link_details': 'true'})}",
        200,
    ),
    ("tool_citations", f"{BASE}/api/tools/{TOOL}/citations", 200),
    ("workflows_page_1", f"{BASE}/api/workflows?{urlencode(WORKFLOW_QUERY)}", 200),
    (
        "workflows_page_2",
        f"{BASE}/api/workflows?{urlencode({**WORKFLOW_QUERY, 'offset': '1'})}",
        200,
    ),
    ("workflow_detail", f"{BASE}/api/workflows/{WORKFLOW}", 200),
    ("workflow_versions", f"{BASE}/api/workflows/{WORKFLOW}/versions", 200),
    (
        "workflow_download",
        f"{BASE}/api/workflows/{WORKFLOW}/download?{urlencode({'style': 'ga'})}",
        200,
    ),
    ("history_search", f"{BASE}/api/histories/published?{urlencode(HISTORY_QUERY)}", 200),
    ("history_detail", f"{BASE}/api/histories/{HISTORY}", 200),
    ("history_contents", f"{BASE}/api/histories/{HISTORY}/contents", 200),
    ("dataset_detail", f"{BASE}/api/histories/{HISTORY}/contents/{DATASET}", 200),
    (
        "dataset_display",
        f"{BASE}/api/histories/{HISTORY}/contents/{DATASET}/display",
        200,
    ),
    (
        "datatypes",
        f"{BASE}/api/datatypes?{urlencode({'extension_only': 'true', 'upload_only': 'false'})}",
        200,
    ),
    (
        "tool_not_found",
        f"{BASE}/api/tools/toolshed.g2.bx.psu.edu/repos/iuc/not-a-tool/not-a-tool/0.0.0?{urlencode({'io_details': 'true', 'link_details': 'true'})}",
        404,
    ),
    ("workflow_not_found", f"{BASE}/api/workflows/0000000000000000", 400),
    ("history_not_found", f"{BASE}/api/histories/0000000000000000", 400),
    (
        "dataset_not_found",
        f"{BASE}/api/histories/{HISTORY}/contents/0000000000000000",
        400,
    ),
    (
        "workflow_invalid_limit",
        f"{BASE}/api/workflows?{urlencode({'show_published': 'true', 'limit': 'not-an-int'})}",
        400,
    ),
    (
        "history_invalid_limit",
        f"{BASE}/api/histories/published?{urlencode({'limit': 'not-an-int'})}",
        400,
    ),
    (
        "datatype_invalid_bool",
        f"{BASE}/api/datatypes?{urlencode({'extension_only': 'not-a-bool'})}",
        400,
    ),
    ("auth_datasets", f"{BASE}/api/datasets?limit=1", 403),
    ("session_jobs", f"{BASE}/api/jobs?limit=1", 400),
    (
        "auth_provenance",
        f"{BASE}/api/histories/{HISTORY}/contents/{DATASET}/provenance",
        403,
    ),
    (
        "auth_extended_metadata",
        f"{BASE}/api/histories/{HISTORY}/contents/{DATASET}/extended_metadata",
        403,
    ),
    ("anonymous_whoami", f"{BASE}/api/whoami", 200),
    ("anonymous_histories_empty", f"{BASE}/api/histories", 200),
)
SAFE_HEADERS = ("content-type", "content-length", "date", "etag", "last-modified")


def fetch(capture_id: str, url: str, expected_status: int) -> dict[str, object]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != HOST:
        raise ValueError(f"capture URL is outside the exact usegalaxy.org host: {url}")
    request = Request(
        url,
        method="GET",
        headers={
            "Accept": "text/plain,text/html"
            if capture_id == "dataset_display"
            else "application/json",
            "User-Agent": "datalox-galaxy-evidence/1.0",
        },
    )
    try:
        response = urlopen(request, timeout=120)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        final_url = response.geturl()
        final = urlparse(final_url)
        if final.scheme != "https" or final.hostname != HOST:
            raise ValueError(f"capture redirected outside the exact HTTPS host: {final_url}")
        if response.status != expected_status:
            raise ValueError(
                f"unexpected status for {capture_id}: {response.status}; expected {expected_status}; "
                f"body={raw[:500]!r}"
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
            "body_representation": "parsed_json"
            if isinstance(body, (dict, list)) or body is None
            else "utf8_text",
            "body": body,
            "redaction": {
                "agent_auth_cookie_or_secret_headers_forwarded": False,
                "cookies_persisted": False,
            },
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
    records = [fetch(capture_id, url, status) for capture_id, url, status in STATIC_REQUESTS]
    by_id = {str(item["id"]): item for item in records}
    workflow_page_2 = by_id["workflows_page_2"]["body"]
    if not isinstance(workflow_page_2, list) or len(workflow_page_2) != 1:
        raise ValueError("expected one real off-chain workflow on page two")
    off_chain_workflow = str(workflow_page_2[0]["id"])
    records.append(
        fetch(
            "workflow_off_chain_detail",
            f"{BASE}/api/workflows/{quote(off_chain_workflow, safe='')}",
            200,
        )
    )
    contents = by_id["history_contents"]["body"]
    if not isinstance(contents, list):
        raise ValueError("history contents must be a list")
    off_chain_matches = [
        item
        for item in contents
        if item.get("id") != DATASET and str(item.get("name", "")).endswith(".html")
    ]
    if len(off_chain_matches) != 1:
        raise ValueError("expected one real off-chain HTML history dataset")
    off_chain_dataset = str(off_chain_matches[0]["id"])
    records.append(
        fetch(
            "dataset_off_chain_detail",
            f"{BASE}/api/histories/{HISTORY}/contents/{quote(off_chain_dataset, safe='')}",
            200,
        )
    )
    payload = {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "galaxy_usegalaxy",
        "implementation": "Galaxy Main",
        "implementation_base_url": BASE,
        "galaxy_version": "26.1.rc1",
        "allowed_host": HOST,
        "allowed_method": "GET",
        "secret_headers_forwarded": False,
        "cookies_persisted": False,
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
