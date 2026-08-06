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
OUTPUT = ROOT / "envs/ecb_data_portal_public_v0/evidence/public_get_capture.json"
BASE = "https://data-api.ecb.europa.eu/service"
HOST = "data-api.ecb.europa.eu"
SERIES = "D.USD.EUR.SP00.A"
BOUNDS = {"startPeriod": "2024-01-01", "endPeriod": "2024-01-10"}
STRUCTURE_XML = "application/vnd.sdmx.structure+xml;version=2.1"
JSON = "application/json"


def request(
    capture_id: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    accept: str = JSON,
    status: int = 200,
) -> dict[str, Any]:
    return {
        "id": capture_id,
        "path": path,
        "query": query or {},
        "accept": accept,
        "expected_status": status,
    }


REQUESTS = (
    request(
        "dataflow_catalog",
        "/dataflow/ECB/all/latest",
        query={"detail": "allstubs"},
        accept=STRUCTURE_XML,
    ),
    request("dataflow_exr", "/dataflow/ECB/EXR/1.0", accept=STRUCTURE_XML),
    request(
        "datastructure_exr",
        "/datastructure/ECB/ECB_EXR1/1.0",
        accept=STRUCTURE_XML,
    ),
    request("codelist_freq", "/codelist/ECB/CL_FREQ/1.0", accept=STRUCTURE_XML),
    request("codelist_currency", "/codelist/ECB/CL_CURRENCY/1.0", accept=STRUCTURE_XML),
    request("codelist_exr_type", "/codelist/ECB/CL_EXR_TYPE/1.0", accept=STRUCTURE_XML),
    request(
        "codelist_exr_suffix",
        "/codelist/ECB/CL_EXR_SUFFIX/1.0",
        accept=STRUCTURE_XML,
    ),
    request(
        "conceptscheme_ecb",
        "/conceptscheme/ECB/ECB_CONCEPTS/1.0",
        accept=STRUCTURE_XML,
    ),
    request("series_bounded_json", f"/data/EXR/{SERIES}", query=BOUNDS),
    request(
        "series_keys_only",
        f"/data/EXR/{SERIES}",
        query={**BOUNDS, "detail": "serieskeysonly"},
    ),
    request(
        "observations_data_only",
        f"/data/EXR/{SERIES}",
        query={**BOUNDS, "detail": "dataonly"},
    ),
    request(
        "observations_first_two",
        f"/data/EXR/{SERIES}",
        query={**BOUNDS, "firstNObservations": "2"},
    ),
    request(
        "observations_last_two",
        f"/data/EXR/{SERIES}",
        query={**BOUNDS, "lastNObservations": "2"},
    ),
    request(
        "observations_updated_after",
        f"/data/EXR/{SERIES}",
        query={**BOUNDS, "updatedAfter": "2024-01-01T00:00:00Z"},
    ),
    request(
        "observations_updated_after_future",
        f"/data/EXR/{SERIES}",
        query={**BOUNDS, "updatedAfter": "2099-01-01T00:00:00Z"},
        status=404,
    ),
    request(
        "multi_frequency_first_two",
        "/data/EXR/D+M.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-01",
            "endPeriod": "2024-03-31",
            "firstNObservations": "2",
        },
    ),
    request(
        "off_chain_jpy_series",
        "/data/EXR/D.JPY.EUR.SP00.A",
        query={"startPeriod": "2024-01-01", "endPeriod": "2024-01-03"},
    ),
    request(
        "format_csv_text",
        f"/data/EXR/{SERIES}",
        query={"startPeriod": "2024-01-01", "endPeriod": "2024-01-03"},
        accept="text/csv",
    ),
    request(
        "format_csv_ecb",
        f"/data/EXR/{SERIES}",
        query={"startPeriod": "2024-01-01", "endPeriod": "2024-01-03"},
        accept="application/vnd.ecb.data+csv;version=1.0.0",
    ),
    request(
        "format_generic_xml",
        f"/data/EXR/{SERIES}",
        query={"startPeriod": "2024-01-01", "endPeriod": "2024-01-03"},
        accept="application/vnd.sdmx.genericdata+xml;version=2.1",
    ),
    request(
        "format_structure_specific_xml",
        f"/data/EXR/{SERIES}",
        query={"startPeriod": "2024-01-01", "endPeriod": "2024-01-03"},
        accept="application/vnd.sdmx.structurespecificdata+xml;version=2.1",
    ),
    request(
        "format_json_wd",
        f"/data/EXR/{SERIES}",
        query={"startPeriod": "2024-01-01", "endPeriod": "2024-01-03"},
        accept="application/vnd.sdmx.data+json;version=1.0.0-wd",
    ),
    request(
        "empty_future_csv",
        f"/data/EXR/{SERIES}",
        query={"startPeriod": "2099-01-01", "endPeriod": "2099-01-02"},
        accept="text/csv",
    ),
    request(
        "invalid_start_period",
        f"/data/EXR/{SERIES}",
        query={"startPeriod": "bad"},
        status=400,
    ),
    request(
        "invalid_first_n",
        f"/data/EXR/{SERIES}",
        query={"firstNObservations": "no"},
        status=400,
    ),
    request(
        "missing_series_flow",
        f"/data/NOTREAL/{SERIES}",
        status=404,
    ),
    request(
        "missing_dataflow",
        "/dataflow/ECB/NOTREAL/latest",
        accept=STRUCTURE_XML,
        status=404,
    ),
    request(
        "missing_codelist",
        "/codelist/ECB/CL_NOTREAL/latest",
        accept=STRUCTURE_XML,
        status=404,
    ),
    request(
        "unacceptable_data_format",
        f"/data/EXR/{SERIES}",
        query={"startPeriod": "2024-01-01", "endPeriod": "2024-01-03"},
        accept="application/vnd.sdmx.data+csv;version=2.0.0",
        status=406,
    ),
    request(
        "unacceptable_structure_json",
        "/dataflow/ECB/EXR/1.0",
        accept=JSON,
        status=406,
    ),
)


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self._transport = httpx.HTTPTransport(retries=2)
        self.last_request: dict[str, Any] | None = None
        self.last_response: dict[str, Any] | None = None

    def handle_request(self, request_: httpx.Request) -> httpx.Response:
        if request_.method != "GET":
            raise ValueError("ECB evidence capture may issue only GET requests")
        parsed = urlparse(str(request_.url))
        if parsed.scheme != "https" or parsed.hostname != HOST:
            raise ValueError(f"ECB evidence request escaped the exact HTTPS host: {request_.url}")
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
            "ecb": LiveUpstream(
                base_url=BASE,
                static_headers={
                    "accept": spec["accept"],
                    "user-agent": "datalox-ecb-public-evidence/1.0",
                },
            )
        }
    )
    client = LiveCaptureClient(live, timeout=120, transport=transport)
    try:
        response = client.fetch(
            CallRequest("GET", f"/ecb{spec['path']}", query=dict(spec["query"]))
        )
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
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    requested_at = datetime.now(UTC).isoformat()
    records = [capture(dict(spec)) for spec in REQUESTS]
    payload = {
        "schema_version": "datalox_public_get_capture_v1",
        "provider_id": "ecb_data_portal",
        "implementation": "ECB Data Portal SDMX REST API",
        "implementation_base_url": BASE,
        "sdmx_rest_version": "2.1 resource syntax with provider-advertised representations",
        "selected_dataflow": "ECB/EXR/1.0",
        "selected_datastructure": "ECB/ECB_EXR1/1.0",
        "selected_series_key": SERIES,
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
