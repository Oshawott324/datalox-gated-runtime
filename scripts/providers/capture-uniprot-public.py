#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "envs/uniprot_public_v0/evidence/public_get_capture.json"
HOST = "rest.uniprot.org"
BASE = f"https://{HOST}"
REQUESTS = (
    (
        "uniprotkb_search",
        "/uniprotkb/search?query=accession%3AP05067&format=json&fields=accession%2Cid%2Cprotein_name%2Corganism_id%2Clength&size=1",
        200,
    ),
    (
        "uniprotkb_paged_search",
        "/uniprotkb/search?query=gene%3AAPP%20AND%20organism_id%3A9606&format=json&fields=accession%2Cid%2Cprotein_name%2Corganism_id%2Clength&size=1&sort=length%20asc",
        200,
    ),
    (
        "uniprotkb_stream",
        "/uniprotkb/stream?query=accession%3AP05067&format=json&fields=accession%2Cid%2Corganism_id%2Clength",
        200,
    ),
    ("uniprotkb_detail", "/uniprotkb/P05067?format=json", 200),
    ("uniprotkb_fasta", "/uniprotkb/P05067.fasta", 200),
    ("uniref_search", "/uniref/search?query=id%3AUniRef100_P05067&format=json&size=1", 200),
    (
        "uniref_off_chain_search",
        "/uniref/search?query=id%3AUniRef100_Q99999&format=json&size=1",
        200,
    ),
    ("uniref_stream", "/uniref/stream?query=id%3AUniRef100_P05067&format=json", 200),
    ("uniref_detail", "/uniref/UniRef100_P05067?format=json", 200),
    ("uniref_members", "/uniref/UniRef100_P05067/members?format=json&size=1", 200),
    (
        "uniparc_search",
        "/uniparc/search?query=upi%3AUPI000002DB1C&format=json&size=1&sort=length%20desc",
        200,
    ),
    ("uniparc_stream", "/uniparc/stream?query=upi%3AUPI000002DB1C&format=json", 200),
    ("uniparc_detail", "/uniparc/UPI000002DB1C?format=json", 200),
    ("uniparc_databases", "/uniparc/UPI000002DB1C/databases?format=json&size=1", 200),
    ("uniparc_databases_stream", "/uniparc/UPI000002DB1C/databases/stream?format=json", 200),
    (
        "proteomes_search",
        "/proteomes/search?query=upid%3AUP000005640&format=json&size=1&sort=protein_count%20desc",
        200,
    ),
    ("proteomes_stream", "/proteomes/stream?query=upid%3AUP000005640&format=json", 200),
    ("proteomes_detail", "/proteomes/UP000005640?format=json", 200),
    ("taxonomy_search", "/taxonomy/search?query=tax_id%3A9606&format=json&size=1", 200),
    ("taxonomy_stream", "/taxonomy/stream?query=tax_id%3A9606&format=json", 200),
    ("taxonomy_detail", "/taxonomy/9606?format=json", 200),
    ("genecentric_search", "/genecentric/search?query=accession%3AP05067&format=json&size=1", 200),
    ("genecentric_stream", "/genecentric/stream?query=accession%3AP05067&format=json", 200),
    (
        "keywords_search",
        "/keywords/search?query=id%3AKW-0002&format=json&size=1&sort=name%20asc",
        200,
    ),
    ("keywords_detail", "/keywords/KW-0002?format=json", 200),
    (
        "locations_search",
        "/locations/search?query=id%3ASL-0039&format=json&size=1&sort=name%20asc",
        200,
    ),
    ("locations_detail", "/locations/SL-0039?format=json", 200),
    ("diseases_search", "/diseases/search?query=id%3ADI-00085&format=json&size=1", 200),
    ("diseases_detail", "/diseases/DI-00085?format=json", 200),
    ("citations_search", "/citations/search?query=id%3A2881207&format=json&size=1", 200),
    ("citations_detail", "/citations/2881207?format=json", 200),
    ("database_search", "/database/search?query=ChEMBL&format=json&size=1", 200),
    ("database_detail", "/database/DB-0174?format=json", 200),
    ("uniprotkb_not_found", "/uniprotkb/P99997?format=json", 404),
    ("invalid_query_field", "/uniprotkb/search?query=not_a_field%3Avalue&format=json&size=1", 400),
    (
        "invalid_return_field",
        "/uniprotkb/search?query=accession%3AP05067&format=json&fields=not_a_field&size=1",
        400,
    ),
    (
        "invalid_cursor",
        "/uniprotkb/search?query=gene%3AAPP&format=json&size=1&cursor=not-a-cursor",
        500,
    ),
)
SAFE_HEADERS = (
    "content-type",
    "content-length",
    "date",
    "etag",
    "last-modified",
    "link",
    "x-total-results",
    "x-uniprot-release",
    "x-uniprot-release-date",
    "x-api-deployment-date",
)
PAGED_IDS = ("uniprotkb_paged_search", "uniref_members", "uniparc_databases")


def fetch(capture_id: str, url: str, expected_status: int) -> dict[str, object]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != HOST:
        raise ValueError(f"capture URL is outside the exact UniProt host: {url}")
    request = Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "datalox-uniprot-evidence/1.0"},
    )
    try:
        response = urlopen(request, timeout=120)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        final_url = response.geturl()
        if urlparse(final_url).hostname != HOST:
            raise ValueError(f"capture redirected outside the exact UniProt host: {final_url}")
        if response.status != expected_status:
            raise ValueError(
                f"unexpected UniProt status for {capture_id}: {response.status}; expected {expected_status}"
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
            "redaction": {
                "performed": False,
                "reason": "Credential-free public biological records; no agent headers were forwarded.",
                "agent_auth_cookie_or_secret_headers_forwarded": False,
            },
            "provenance": {
                "grounding_level": "G3_PUBLIC_PRODUCTION",
                "environment": "public_production_read",
                "authentication": "credential_free",
                "sandbox": False,
            },
        }


def capture() -> dict[str, object]:
    requested_at = datetime.now(UTC).isoformat()
    records = [fetch(identifier, BASE + path, status) for identifier, path, status in REQUESTS]
    for identifier in PAGED_IDS:
        first = next(item for item in records if item["id"] == identifier)
        link = str(first["response_headers"].get("link", ""))
        match = re.fullmatch(r'<(https://rest\.uniprot\.org/[^>]+)>; rel="next"', link)
        if match is None:
            raise ValueError(f"{identifier} did not expose the expected cursor Link header")
        records.append(fetch(f"{identifier}_cursor_page_2", match.group(1), 200))
    return {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "uniprot",
        "requested_at": requested_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "allowed_host": HOST,
        "allowed_method": "GET",
        "request_headers": {
            "Accept": "application/json",
            "User-Agent": "datalox-uniprot-evidence/1.0",
        },
        "secret_headers_forwarded": False,
        "capture_count": len(records),
        "captures": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    payload = capture()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"path": str(args.out), "capture_count": payload["capture_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
