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
OUTPUT = ROOT / "envs/ecb_data_portal_public_v0/evidence/core_get_capture.json"
BASE = "https://data-api.ecb.europa.eu/service"
HOST = "data-api.ecb.europa.eu"
STRUCTURE_XML = "application/vnd.sdmx.structure+xml;version=2.1"
XML = "application/xml"


def request(
    capture_id: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    accept: str = STRUCTURE_XML,
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
        "structure_catalog_allstubs",
        "/structure/ECB/all/latest",
        query={"detail": "allstubs"},
    ),
    request(
        "dataflow_exr_reference_stubs",
        "/dataflow/ECB/EXR/1.0",
        query={"detail": "referencestubs", "references": "children"},
    ),
    request(
        "datastructure_exr_reference_stubs",
        "/datastructure/ECB/ECB_EXR1/1.0",
        query={"detail": "referencestubs", "references": "children"},
    ),
    request(
        "contentconstraint_exr",
        "/contentconstraint/ECB/EXR_CONSTRAINTS/1.0",
    ),
    request(
        "schema_dataflow_exr",
        "/schema/dataflow/ECB/EXR/1.0",
        accept=XML,
    ),
    request(
        "schema_datastructure_exr",
        "/schema/datastructure/ECB/ECB_EXR1/1.0",
        accept=XML,
    ),
    request(
        "data_include_history_false",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "includeHistory": "false",
        },
        accept="application/json",
    ),
    request(
        "data_include_history_true",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "includeHistory": "true",
        },
        accept="application/json",
    ),
    request(
        "data_detail_nodata",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "detail": "nodata",
        },
        accept="application/json",
    ),
    request(
        "data_dimension_time_period",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "dimensionAtObservation": "TIME_PERIOD",
        },
        accept="application/json",
    ),
    request(
        "data_dimension_all_dimensions",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "dimensionAtObservation": "AllDimensions",
        },
        accept="application/json",
    ),
    request(
        "data_dimension_unsupported",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "dimensionAtObservation": "CURRENCY",
        },
        accept="application/json",
        status=501,
    ),
    request(
        "data_flow_ref_agency_alias",
        "/data/ECB,EXR/D.USD.EUR.SP00.A",
        query={"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
        accept="application/json",
    ),
    request(
        "data_flow_ref_version_alias",
        "/data/ECB,EXR,1.0/D.USD.EUR.SP00.A",
        query={"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
        accept="application/json",
    ),
    request(
        "data_or_currency_first",
        "/data/EXR/D.USD+JPY.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
        },
        accept="application/json",
    ),
    request(
        "data_omitted_key_all",
        "/data/EXR",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
        },
        accept="application/json",
    ),
    request(
        "data_first_last_union",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-10",
            "firstNObservations": "1",
            "lastNObservations": "1",
        },
        accept="application/json",
    ),
    request(
        "data_format_csvdata",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "format": "csvdata",
        },
        accept="*/*",
    ),
    request(
        "data_format_jsondata",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "format": "jsondata",
        },
        accept="*/*",
    ),
    request(
        "data_format_structurespecificdata",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "format": "structurespecificdata",
        },
        accept="*/*",
    ),
    request(
        "data_format_genericdata",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "format": "genericdata",
        },
        accept="*/*",
    ),
    request(
        "formatted_csv_full_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "full",
        },
        accept="text/csv",
    ),
    request(
        "formatted_csv_dataonly_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "dataonly",
        },
        accept="text/csv",
    ),
    request(
        "formatted_csv_serieskeysonly_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "serieskeysonly",
        },
        accept="text/csv",
    ),
    request(
        "formatted_csv_nodata_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "nodata",
        },
        accept="text/csv",
    ),
    request(
        "formatted_csv_composable_controls",
        "/data/EXR/.USD+JPY.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "lastNObservations": "1",
            "updatedAfter": "2024-01-01T00:00:00Z",
            "detail": "dataonly",
            "includeHistory": "false",
            "dimensionAtObservation": "TIME_PERIOD",
        },
        accept="text/csv",
    ),
    request(
        "formatted_csv_omitted_key_first",
        "/data/EXR",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "serieskeysonly",
        },
        accept="text/csv",
    ),
    request(
        "formatted_csv_history_true",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "includeHistory": "true",
        },
        accept="text/csv",
    ),
    request(
        "formatted_csv_all_dimensions",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "dimensionAtObservation": "AllDimensions",
        },
        accept="text/csv",
    ),
    request(
        "formatted_ecb_csv_dataonly_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "dataonly",
        },
        accept="application/vnd.ecb.data+csv;version=1.0.0",
    ),
    request(
        "formatted_json_dataonly_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "dataonly",
        },
        accept="application/json",
    ),
    request(
        "formatted_json_wd_dataonly_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "dataonly",
        },
        accept="application/vnd.sdmx.data+json;version=1.0.0-wd",
    ),
    request(
        "formatted_generic_xml_dataonly_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "dataonly",
        },
        accept="application/vnd.sdmx.genericdata+xml;version=2.1",
    ),
    request(
        "formatted_structure_specific_xml_dataonly_first",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "firstNObservations": "1",
            "detail": "dataonly",
        },
        accept="application/vnd.sdmx.structurespecificdata+xml;version=2.1",
    ),
    request(
        "formatted_generic_xml_serieskeysonly",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "detail": "serieskeysonly",
        },
        accept="application/vnd.sdmx.genericdata+xml;version=2.1",
    ),
    request(
        "formatted_generic_xml_nodata",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={**{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"}, "detail": "nodata"},
        accept="application/vnd.sdmx.genericdata+xml;version=2.1",
    ),
    request(
        "formatted_structure_specific_xml_serieskeysonly",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "detail": "serieskeysonly",
        },
        accept="application/vnd.sdmx.structurespecificdata+xml;version=2.1",
    ),
    request(
        "formatted_structure_specific_xml_nodata",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={**{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"}, "detail": "nodata"},
        accept="application/vnd.sdmx.structurespecificdata+xml;version=2.1",
    ),
    request(
        "formatted_ecb_csv_history_true",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "includeHistory": "true",
        },
        accept="application/vnd.ecb.data+csv;version=1.0.0",
    ),
    request(
        "formatted_json_wd_history_true",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "includeHistory": "true",
        },
        accept="application/vnd.sdmx.data+json;version=1.0.0-wd",
    ),
    request(
        "formatted_generic_xml_history_true",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "includeHistory": "true",
        },
        accept="application/vnd.sdmx.genericdata+xml;version=2.1",
    ),
    request(
        "formatted_structure_specific_xml_history_true",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "includeHistory": "true",
        },
        accept="application/vnd.sdmx.structurespecificdata+xml;version=2.1",
    ),
    request(
        "formatted_ecb_csv_all_dimensions",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "dimensionAtObservation": "AllDimensions",
        },
        accept="application/vnd.ecb.data+csv;version=1.0.0",
    ),
    request(
        "formatted_json_wd_all_dimensions",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "dimensionAtObservation": "AllDimensions",
        },
        accept="application/vnd.sdmx.data+json;version=1.0.0-wd",
    ),
    request(
        "formatted_generic_xml_all_dimensions",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "dimensionAtObservation": "AllDimensions",
        },
        accept="application/vnd.sdmx.genericdata+xml;version=2.1",
    ),
    request(
        "formatted_structure_specific_xml_all_dimensions",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            **{"startPeriod": "2024-01-02", "endPeriod": "2024-01-03"},
            "dimensionAtObservation": "AllDimensions",
        },
        accept="application/vnd.sdmx.structurespecificdata+xml;version=2.1",
    ),
    request(
        "formatted_csv_dimension_unsupported",
        "/data/EXR/D.USD.EUR.SP00.A",
        query={
            "startPeriod": "2024-01-02",
            "endPeriod": "2024-01-03",
            "dimensionAtObservation": "CURRENCY",
        },
        accept="text/csv",
        status=501,
    ),
    request(
        "provisionagreement_catalog_missing",
        "/provisionagreement/ECB/all/latest",
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
            raise ValueError("ECB core evidence capture may issue only GET requests")
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
                    "user-agent": "datalox-ecb-public-core-evidence/1.0",
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
