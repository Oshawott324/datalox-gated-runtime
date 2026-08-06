#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

from datalox_gated_runtime.capture import LiveCaptureClient
from datalox_gated_runtime.models import CallRequest, LiveGateConfig, LiveUpstream


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/public_get_format_capture.json"
XML_SHAPE_OUTPUT = ROOT / "envs/ensembl_public_v0/evidence/public_get_xml_shape_capture.json"
VARIATION_DEFAULT_XML_OUTPUT = (
    ROOT / "envs/ensembl_public_v0/evidence/public_get_variation_default_xml_capture.json"
)
BASE = "https://rest.ensembl.org"
HOST = "rest.ensembl.org"


CASES = (
    ("lookup_braf_xml", "/lookup/id/ENSG00000157764", {}, "xml", "text/xml"),
    ("compara_methods_yaml", "/info/compara/methods", {}, "yaml", "text/x-yaml"),
    ("ping_jsonp", "/info/ping", {"callback": "cb"}, "jsonp", "text/javascript"),
    (
        "sequence_braf_fasta",
        "/sequence/id/ENSP00000493543",
        {"type": "protein"},
        "fasta",
        "text/x-fasta",
    ),
    (
        "sequence_braf_seqxml",
        "/sequence/id/ENSP00000493543",
        {"type": "protein"},
        "seqxml",
        "text/x-seqxml+xml",
    ),
    (
        "sequence_braf_text",
        "/sequence/id/ENSP00000493543",
        {"type": "protein"},
        "text",
        "text/plain",
    ),
    (
        "overlap_braf_gff3",
        "/overlap/id/ENSG00000157764",
        {"feature": "transcript"},
        "gff3",
        "text/x-gff3",
    ),
    (
        "overlap_braf_bed",
        "/overlap/region/homo_sapiens/7:140753336-140753436",
        {"feature": "variation"},
        "bed",
        "text/x-bed",
    ),
    ("cafe_official_nh", "/cafe/genetree/id/ENSGT00390000003602", {}, "nh", "text/x-nh"),
    (
        "genetree_braf_phyloxml",
        "/genetree/member/id/homo_sapiens/ENSG00000157764",
        {},
        "phyloxml",
        "text/x-phyloxml+xml",
    ),
    (
        "homology_braf_orthoxml",
        "/homology/id/homo_sapiens/ENSG00000157764",
        {"target_species": "mus_musculus", "type": "orthologues"},
        "orthoxml",
        "text/x-orthoxml+xml",
    ),
)
XML_SHAPE_CASES = (
    ("vep_braf_hgvs_xml", "/vep/homo_sapiens/hgvs/7:g.140753336A>T", {}, "xml", "text/xml"),
    ("vep_braf_id_xml", "/vep/homo_sapiens/id/rs113488022", {}, "xml", "text/xml"),
    (
        "vep_braf_region_xml",
        "/vep/homo_sapiens/region/7:140753336-140753336/T",
        {},
        "xml",
        "text/xml",
    ),
    (
        "variant_recoder_braf_xml",
        "/variant_recoder/homo_sapiens/rs113488022",
        {},
        "xml",
        "text/xml",
    ),
    (
        "variation_braf_xml",
        "/variation/homo_sapiens/rs113488022",
        {"phenotypes": "1"},
        "xml",
        "text/xml",
    ),
)
VARIATION_DEFAULT_XML_CASES = (
    ("variation_braf_default_xml", "/variation/homo_sapiens/rs113488022", {}, "xml", "text/xml"),
)


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self._transport = httpx.HTTPTransport(retries=2)
        self.request: dict[str, Any] | None = None
        self.response_headers: dict[str, str] | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        parsed = urlparse(str(request.url))
        if request.method != "GET" or parsed.scheme != "https" or parsed.hostname != HOST:
            raise ValueError(
                f"format evidence escaped the GET-only Ensembl boundary: {request.method} {request.url}"
            )
        self.request = {
            "method": request.method,
            "url": str(request.url),
            "accept": request.headers.get("accept"),
            "content_type": request.headers.get("content-type"),
            "authorization_present": "authorization" in request.headers,
            "cookie_present": "cookie" in request.headers,
        }
        response = self._transport.handle_request(request)
        self.response_headers = {
            name: response.headers[name]
            for name in (
                "content-type",
                "content-length",
                "date",
                "x-ratelimit-limit",
                "x-ratelimit-period",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
                "retry-after",
            )
            if response.headers.get(name) is not None
        }
        return response

    def close(self) -> None:
        self._transport.close()


def capture(case: tuple[str, str, dict[str, str], str, str]) -> dict[str, Any]:
    identifier, path, query, response_format, mime = case
    transport = RecordingTransport()
    live = LiveGateConfig(
        upstreams={
            "ensembl": LiveUpstream(
                base_url=BASE,
                static_headers={
                    "accept": mime,
                    "content-type": mime,
                    "user-agent": "datalox-ensembl-format-evidence/1.0",
                },
            )
        }
    )
    client = LiveCaptureClient(live, timeout=120, transport=transport)
    try:
        response = client.fetch(CallRequest("GET", f"/ensembl{path}", query=query))
    finally:
        client.close()
    if response.status_code != 200 or not isinstance(response.body, str):
        raise ValueError(
            f"unexpected format response for {identifier}: {response.status_code} {type(response.body).__name__}"
        )
    if transport.request is None or transport.response_headers is None:
        raise ValueError(f"missing transport evidence for {identifier}")
    if transport.request["authorization_present"] or transport.request["cookie_present"]:
        raise ValueError(f"secret-bearing request observed for {identifier}")
    body = response.body
    return {
        "id": identifier,
        "method": "GET",
        "path": path,
        "query": query,
        "url": BASE + path + (f"?{urlencode(query)}" if query else ""),
        "final_url": transport.request["url"],
        "status": response.status_code,
        "response_format": response_format,
        "request_headers": {"accept": mime, "content-type": mime},
        "response_headers": transport.response_headers,
        "body": body,
        "body_representation": "text",
        "body_bytes": len(body.encode()),
        "body_sha256": "sha256:" + hashlib.sha256(body.encode()).hexdigest(),
        "captured_at": datetime.now(UTC).isoformat(),
        "provenance": {
            "authentication": "credential_free",
            "environment": "public_production_read",
            "grounding_level": "G3_PUBLIC_PRODUCTION",
            "sandbox": False,
        },
        "redaction": {"agent_auth_cookie_or_secret_headers_forwarded": False},
    }


def write_exclusive(output: Path, value: dict[str, Any]) -> None:
    lock = output.with_suffix(output.suffix + ".lock")
    lock_descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(lock_descriptor)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent, prefix=f".{output.name}.", suffix=".tmp", text=True
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise RuntimeError(f"refusing to overwrite immutable evidence: {output}") from exc
    finally:
        temporary.unlink(missing_ok=True)
        lock.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture exact non-JSON Ensembl GET representations."
    )
    parser.add_argument(
        "--write", action="store_true", help="Write a new evidence file; never overwrites one."
    )
    parser.add_argument(
        "--xml-shapes",
        action="store_true",
        help="Capture nested XML shapes into a separate immutable asset.",
    )
    parser.add_argument(
        "--variation-default",
        action="store_true",
        help="Capture the default variation XML baseline separately.",
    )
    args = parser.parse_args()
    if not args.write:
        parser.error("capture is explicit: pass --write")
    if args.xml_shapes and args.variation_default:
        parser.error("choose only one capture mode")
    output = (
        VARIATION_DEFAULT_XML_OUTPUT
        if args.variation_default
        else XML_SHAPE_OUTPUT
        if args.xml_shapes
        else OUTPUT
    )
    cases = (
        VARIATION_DEFAULT_XML_CASES
        if args.variation_default
        else XML_SHAPE_CASES
        if args.xml_shapes
        else CASES
    )
    if output.exists():
        raise SystemExit(f"refusing to overwrite immutable evidence: {output}")
    records = [capture(case) for case in cases]
    write_exclusive(
        output,
        {
            "provider_id": "ensembl",
            "provider_base_url": BASE,
            "allowed_host": HOST,
            "allowed_method": "GET",
            "capture_count": len(records),
            "secret_headers_forwarded": False,
            "captures": records,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
