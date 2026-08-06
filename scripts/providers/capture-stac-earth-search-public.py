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
OUTPUT = ROOT / "envs/stac_earth_search_public_v0/evidence/public_get_capture.json"
CORE_OUTPUT = ROOT / "envs/stac_earth_search_public_v0/evidence/core_get_capture.json"
ORIGINAL_CAPTURE_SHA256 = "e365c19bb5c53411ba1d6da040acf3e2b190036e1d1d3b1263a245964ac44f84"
BASE = "https://earth-search.aws.element84.com/v1"
HOST = "earth-search.aws.element84.com"
COLLECTION = "sentinel-2-pre-c1-l2a"
ITEM = "S2B_T21NYC_20221205T140704_L2A"
FIXTURE_ITEMS = (
    ITEM,
    "S2B_T21NZF_20221205T140704_L2A",
    "S2B_T21NZC_20221205T140704_L2A",
)
MATERIALIZED_AGGREGATIONS = ",".join(
    (
        "datetime_frequency",
        "cloud_cover_frequency",
        "sun_elevation_frequency",
        "sun_azimuth_frequency",
        "grid_code_frequency",
        "grid_geohex_frequency",
        "grid_geohash_frequency",
        "grid_geotile_frequency",
    )
)
BBOX = "-55.202493%2C1.71876%2C-54.214277%2C2.71282"
DATETIME = "2022-12-05T00%3A00%3A00Z%2F2022-12-06T00%3A00%3A00Z"
STATIC_REQUESTS = (
    ("landing", BASE, 200),
    ("service_description", f"{BASE}/api", 200),
    ("conformance", f"{BASE}/conformance", 200),
    ("collections", f"{BASE}/collections", 200),
    ("collection_detail", f"{BASE}/collections/{COLLECTION}", 200),
    ("collection_queryables", f"{BASE}/collections/{COLLECTION}/queryables", 200),
    ("global_queryables", f"{BASE}/queryables", 200),
    ("collection_items_page_1", f"{BASE}/collections/{COLLECTION}/items?limit=1", 200),
    ("item_detail", f"{BASE}/collections/{COLLECTION}/items/{ITEM}", 200),
    (
        "search_combo_page_1",
        f"{BASE}/search?collections={COLLECTION}&bbox={BBOX}&datetime={DATETIME}&limit=1",
        200,
    ),
    (
        "search_ids",
        f"{BASE}/search?collections={COLLECTION}&ids={ITEM}&bbox={BBOX}&datetime={DATETIME}&limit=1",
        200,
    ),
    (
        "search_query_extension",
        f"{BASE}/search?collections={COLLECTION}&query=%7B%22eo%3Acloud_cover%22%3A%7B%22lt%22%3A50%7D%7D&limit=1",
        200,
    ),
    (
        "search_sort_extension",
        f"{BASE}/search?collections={COLLECTION}&sortby=-properties.datetime&limit=1",
        200,
    ),
    (
        "search_fields_extension",
        f"{BASE}/search?collections={COLLECTION}&fields=id%2Ccollection%2Cproperties.datetime%2Cassets.thumbnail&limit=1",
        200,
    ),
    ("collection_not_found", f"{BASE}/collections/not-a-collection", 404),
    ("item_not_found", f"{BASE}/collections/{COLLECTION}/items/not-an-item", 404),
    ("invalid_bbox", f"{BASE}/search?bbox=1%2C2%2C3&limit=1", 400),
    ("invalid_datetime", f"{BASE}/search?datetime=not-a-date&limit=1", 400),
    (
        "invalid_query",
        f"{BASE}/search?collections={COLLECTION}&query=not-json&limit=1",
        500,
    ),
)
CORE_REQUESTS = (
    ("aggregations_catalog", f"{BASE}/aggregations", 200),
    ("aggregations_collection", f"{BASE}/collections/{COLLECTION}/aggregations", 200),
    (
        "aggregate_catalog_total_count",
        f"{BASE}/aggregate?collections={COLLECTION}&aggregations=total_count",
        200,
    ),
    (
        "aggregate_collection_total_count",
        f"{BASE}/collections/{COLLECTION}/aggregate?aggregations=total_count",
        200,
    ),
    *(
        (
            f"aggregate_item_materialization_{item_id}",
            f"{BASE}/collections/{COLLECTION}/aggregate?ids={item_id}&aggregations={MATERIALIZED_AGGREGATIONS}",
            200,
        )
        for item_id in FIXTURE_ITEMS
    ),
)
SAFE_HEADERS = ("content-type", "content-length", "date", "etag", "last-modified")


def fetch(capture_id: str, url: str, expected_status: int) -> dict[str, object]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != HOST:
        raise ValueError(f"capture URL is outside the exact Earth Search host: {url}")
    request = Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "datalox-stac-evidence/1.0"},
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


def next_href(record: dict[str, object]) -> str:
    body = record["body"]
    if not isinstance(body, dict):
        raise ValueError("paged response is not JSON")
    matches = [item["href"] for item in body["links"] if item.get("rel") == "next"]
    if len(matches) != 1:
        raise ValueError("expected one next link")
    return str(matches[0])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", choices=("canonical", "core"), default="canonical")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    requested_at = datetime.now(UTC).isoformat()
    if args.scope == "core":
        digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
        if digest != ORIGINAL_CAPTURE_SHA256:
            raise ValueError("canonical Earth Search capture changed before supplemental capture")
        records = [fetch(capture_id, url, status) for capture_id, url, status in CORE_REQUESTS]
        output = args.out or CORE_OUTPUT
        payload = {
            "schema_version": "datalox_public_get_capture_v1",
            "provider_id": "stac_earth_search",
            "implementation": "Element 84 Earth Search",
            "implementation_base_url": BASE,
            "stac_api_version": "1.0.0",
            "stac_object_version": "1.0.0",
            "allowed_host": HOST,
            "allowed_method": "GET",
            "secret_headers_forwarded": False,
            "requested_at": requested_at,
            "completed_at": datetime.now(UTC).isoformat(),
            "capture_count": len(records),
            "captures": records,
            "canonical_capture_sha256": f"sha256:{ORIGINAL_CAPTURE_SHA256}",
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"path": str(output), "capture_count": len(records)}))
        return
    output = args.out or OUTPUT
    records = [fetch(capture_id, url, status) for capture_id, url, status in STATIC_REQUESTS]
    by_id = {str(item["id"]): item for item in records}
    items_page_2 = fetch(
        "collection_items_page_2", next_href(by_id["collection_items_page_1"]), 200
    )
    records.append(items_page_2)
    off_chain_id = str(items_page_2["body"]["features"][0]["id"])
    records.append(
        fetch(
            "item_off_chain_detail",
            f"{BASE}/collections/{COLLECTION}/items/{quote(off_chain_id, safe='')}",
            200,
        )
    )
    records.append(fetch("search_combo_page_2", next_href(by_id["search_combo_page_1"]), 200))
    records.append(
        fetch(
            "search_off_chain_id",
            f"{BASE}/search?collections={COLLECTION}&ids={quote(off_chain_id, safe='')}&limit=1",
            200,
        )
    )
    payload = {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "stac_earth_search",
        "implementation": "Element 84 Earth Search",
        "implementation_base_url": BASE,
        "stac_api_version": "1.0.0",
        "stac_object_version": "1.0.0",
        "allowed_host": HOST,
        "allowed_method": "GET",
        "secret_headers_forwarded": False,
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
