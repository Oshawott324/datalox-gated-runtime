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
OUTPUT = ROOT / "envs/msc_geomet_public_v0/evidence/public_get_capture.json"
BASE = "https://api.weather.gc.ca"
HOST = "api.weather.gc.ca"
STATIONS = "hydrometric-stations"
DAILY = "hydrometric-daily-mean"
COVERAGE = "climate:cangrd:historical:annual:trend"
STATION = "02OA016"
DAILY_ITEM = "02OA016.2023-06-01"
OFFCHAIN_STATION = "02KF005"
OFFCHAIN_DAILY_ITEM = "02OA095.2023-06-01"
PROCESS = "raster-drill"
DAILY_QUERY = {
    "f": "json",
    "limit": "2",
    "offset": "0",
    "STATION_NUMBER": STATION,
    "datetime": "2023-06-01/2023-06-05",
}


def api(path: str, query: dict[str, str] | None = None) -> str:
    suffix = f"?{urlencode(query)}" if query else ""
    return f"{BASE}{path}{suffix}"


STATIC_REQUESTS = (
    ("landing", api("/", {"f": "json"}), 200),
    ("conformance", api("/conformance", {"f": "json"}), 200),
    ("openapi", api("/openapi", {"f": "json"}), 200),
    ("collections", api("/collections", {"f": "json"}), 200),
    ("station_collection", api(f"/collections/{STATIONS}", {"f": "json"}), 200),
    (
        "station_queryables",
        api(f"/collections/{STATIONS}/queryables", {"f": "json"}),
        200,
    ),
    ("station_schema", api(f"/collections/{STATIONS}/schema", {"f": "json"}), 200),
    (
        "station_search",
        api(
            f"/collections/{STATIONS}/items",
            {"f": "json", "limit": "1", "STATION_NUMBER": STATION},
        ),
        200,
    ),
    (
        "station_page",
        api(f"/collections/{STATIONS}/items", {"f": "json", "limit": "2", "offset": "0"}),
        200,
    ),
    (
        "station_detail",
        api(f"/collections/{STATIONS}/items/{quote(STATION, safe='')}", {"f": "json"}),
        200,
    ),
    (
        "station_off_chain_detail",
        api(
            f"/collections/{STATIONS}/items/{quote(OFFCHAIN_STATION, safe='')}",
            {"f": "json"},
        ),
        200,
    ),
    ("daily_collection", api(f"/collections/{DAILY}", {"f": "json"}), 200),
    (
        "daily_queryables",
        api(f"/collections/{DAILY}/queryables", {"f": "json"}),
        200,
    ),
    ("daily_schema", api(f"/collections/{DAILY}/schema", {"f": "json"}), 200),
    ("daily_page_1", api(f"/collections/{DAILY}/items", DAILY_QUERY), 200),
    (
        "daily_page_2",
        api(f"/collections/{DAILY}/items", {**DAILY_QUERY, "offset": "2"}),
        200,
    ),
    (
        "daily_page_3",
        api(f"/collections/{DAILY}/items", {**DAILY_QUERY, "offset": "4"}),
        200,
    ),
    (
        "daily_bbox_search",
        api(
            f"/collections/{DAILY}/items",
            {
                "f": "json",
                "limit": "2",
                "bbox": "-74,45,-73,46",
                "datetime": "2023-06-01/2023-06-05",
            },
        ),
        200,
    ),
    (
        "daily_properties_search",
        api(
            f"/collections/{DAILY}/items",
            {
                "f": "json",
                "limit": "2",
                "properties": "STATION_NUMBER,DISCHARGE,DATE",
                "STATION_NUMBER": STATION,
                "datetime": "2023-06-01/2023-06-05",
            },
        ),
        200,
    ),
    (
        "daily_detail",
        api(f"/collections/{DAILY}/items/{quote(DAILY_ITEM, safe='')}", {"f": "json"}),
        200,
    ),
    (
        "daily_off_chain_detail",
        api(
            f"/collections/{DAILY}/items/{quote(OFFCHAIN_DAILY_ITEM, safe='')}",
            {"f": "json"},
        ),
        200,
    ),
    ("coverage_collection", api(f"/collections/{COVERAGE}", {"f": "json"}), 200),
    ("coverage_schema", api(f"/collections/{COVERAGE}/schema", {"f": "json"}), 200),
    (
        "coverage_bbox",
        api(
            f"/collections/{COVERAGE}/coverage",
            {"f": "json", "bbox": "-74,45,-73,46"},
        ),
        200,
    ),
    ("processes", api("/processes", {"f": "json"}), 200),
    ("process_detail", api(f"/processes/{PROCESS}", {"f": "json"}), 200),
    ("jobs_empty", api("/jobs", {"f": "json"}), 200),
    ("stac_root", api("/stac", {"f": "json"}), 200),
    ("stac_child", api("/stac/msc-datamart", {"f": "json"}), 200),
    ("tile_matrix_sets", api("/TileMatrixSets", {"f": "json"}), 200),
    ("collection_not_found", api("/collections/not-real", {"f": "json"}), 404),
    (
        "item_not_found",
        api(f"/collections/{DAILY}/items/not-real", {"f": "json"}),
        404,
    ),
    ("process_not_found", api("/processes/not-real", {"f": "json"}), 404),
    (
        "invalid_limit",
        api(f"/collections/{DAILY}/items", {"f": "json", "limit": "not-an-int"}),
        400,
    ),
    (
        "invalid_bbox",
        api(f"/collections/{DAILY}/items", {"f": "json", "bbox": "bad"}),
        400,
    ),
    (
        "invalid_datetime",
        api(f"/collections/{DAILY}/items", {"f": "json", "datetime": "not-a-date"}),
        400,
    ),
    (
        "coverage_invalid_bbox",
        api(f"/collections/{COVERAGE}/coverage", {"f": "json", "bbox": "bad"}),
        500,
    ),
    (
        "station_datetime_unsupported",
        api(
            f"/collections/{STATIONS}/items",
            {"f": "json", "limit": "2", "datetime": "2024-01-01/2024-01-02"},
        ),
        500,
    ),
)
SAFE_HEADERS = (
    "content-type",
    "content-length",
    "date",
    "etag",
    "last-modified",
    "x-powered-by",
)


def fetch(capture_id: str, url: str, expected_status: int) -> dict[str, object]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != HOST:
        raise ValueError(f"capture URL is outside the exact MSC GeoMet host: {url}")
    request = Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "datalox-msc-geomet-evidence/1.0"},
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
        body = json.loads(raw)
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
            "body_representation": "parsed_json",
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
    payload = {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "msc_geomet",
        "implementation": "MSC GeoMet OGC API",
        "implementation_base_url": BASE,
        "pygeoapi_version": "0.20.0",
        "openapi_version": "3.0.2",
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
