#!/usr/bin/env python3
"""Capture the separately reviewed PubChem PUG-View supplemental GET evidence.

This is an authoring utility, not a runtime live-write surface.  It has one
fixed HTTPS origin, one fixed GET-only case manifest, no redirect or retry
logic, and no credential input.  Network execution is explicit and requires
externally reviewed digests for this runner, the shared binary-response
implementation, and the official PubChem source pins.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Callable
from datetime import UTC, datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from types import ModuleType
from typing import Any, NamedTuple, Protocol
from urllib.parse import urlencode, urlparse

RUNNER_PATH = Path(__file__).resolve()
ROOT = RUNNER_PATH.parents[2]
OUTPUT_RELATIVE = Path(
    "envs/pubchem_public_v0/evidence/public_get_capture_pug_view_supplement_v1.json"
)
OUTPUT = ROOT / OUTPUT_RELATIVE
OFFICIAL_SOURCE_PINS = ROOT / "envs/pubchem_public_v0/evidence/official_source_pins.json"
BINARY_RESPONSE_HELPER = ROOT / "src/datalox_gated_runtime/binary_response.py"


def compile_binary_response_builder(
    source_bytes: bytes,
    *,
    source_path: Path,
) -> Callable[..., dict[str, Any]]:
    if not isinstance(source_bytes, bytes):
        raise TypeError("binary-response helper source must be frozen bytes")
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    module_name = f"_datalox_pubchem_capture_binary_response_{source_sha256}"
    module = ModuleType(module_name)
    module.__file__ = str(source_path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        code = compile(source_bytes, str(source_path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    builder = getattr(module, "make_binary_response_body", None)
    if not callable(builder):
        raise RuntimeError("shared binary-response helper lacks its canonical builder")
    return builder


LOADED_BINARY_HELPER_BYTES = BINARY_RESPONSE_HELPER.read_bytes()
make_binary_response_body = compile_binary_response_builder(
    LOADED_BINARY_HELPER_BYTES,
    source_path=BINARY_RESPONSE_HELPER,
)

BASE = "https://pubchem.ncbi.nlm.nih.gov"
HOST = "pubchem.ncbi.nlm.nih.gov"
METHOD = "GET"
USER_AGENT = "datalox-pubchem-pug-view-supplement/1.0"
MIN_INTERVAL_SECONDS = 0.5
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_HEADER_BYTES = 64_000
MAX_WIRE_RECV_BYTES = 64 * 1024
MAX_TOTAL_RESPONSE_BYTES = 48 * 1024 * 1024
MAX_JOURNAL_FILE_BYTES = 192 * 1024 * 1024

INDEX_OR_IMAGE_CAP = 1 * 1024 * 1024
DATA_OR_REPORT_CAP = 3 * 1024 * 1024
QR_CAP = 500 * 1024
ATTACHMENT_CAP = 5 * 1024 * 1024
NEGATIVE_CAP = 16 * 1024

JSON_TYPES = ("application/json", "application/json; charset=utf-8")
JSONP_TYPES = (
    "application/javascript",
    "application/javascript; charset=utf-8",
    "text/javascript",
)
XML_TYPES = (
    "application/xml",
    "application/xml; charset=utf-8",
    "text/xml",
    "text/xml; charset=utf-8",
)
ASNT_TYPES = (
    "text/plain",
    "text/plain; charset=utf-8",
    "application/asn.1",
)
ASNB_TYPES = (
    "application/octet-stream",
    "application/asn.1",
    "text/plain",
    "text/plain; charset=utf-8",
)
PNG_TYPES = ("image/png",)
SVG_TYPES = ("image/svg+xml", "image/svg+xml; charset=utf-8")
ATTACHMENT_TYPES = (
    "application/octet-stream",
    "application/pdf",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/svg+xml",
    "text/plain",
)

SAFE_RESPONSE_HEADERS = (
    "cache-control",
    "content-encoding",
    "content-length",
    "content-type",
    "date",
    "retry-after",
    "x-throttling-control",
)
TEXTUAL_FORMATS = frozenset({"json", "jsonp", "xml", "asnt", "negative_json"})
BINARY_FORMATS = frozenset({"png", "svg", "asnb", "attachment"})
CLASSIFICATIONS = frozenset({"core_operation_candidate", "provider_native_negative"})
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
HEADER_NAME_PATTERN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
STATUS_LINE_PATTERN = re.compile(rb"HTTP/1[.]1 ([0-9]{3})(?: (.*))?")
CONTENT_LENGTH_PATTERN = re.compile(r"0|[1-9][0-9]*", re.ASCII)
CONTENT_TYPE_PATTERN = re.compile(
    r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+/[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
    r"(?: *; *[!#$%&'*+\-.^_`|~0-9A-Za-z]+="
    r"(?:[!#$%&'*+\-.^_`|~0-9A-Za-z]+|\"(?:[ !#-\[\]-~]|\\[ -~])*\")"
    r")*",
    re.ASCII,
)
ORIGIN_PATH_PATTERN = re.compile(r"/rest/pug(?:_view)?/[A-Za-z0-9._~:/-]+", re.ASCII)
THROTTLE_PATTERN = re.compile(
    r"Request Count status: (?P<count>Green|Yellow|Red) \([0-9]+%\), "
    r"Request Time status: (?P<time>Green|Yellow|Red) \([0-9]+%\), "
    r"Service status: (?P<service>Green|Yellow|Red) \([0-9]+%\)"
)

REDACTION = {
    "agent_auth_cookie_or_secret_headers_forwarded": False,
    "environment_credentials_read_or_forwarded": False,
}


class CaptureHalt(RuntimeError):
    """The reviewed capture stopped and must not be retried automatically."""


class ResponseCaptureInterrupted(Exception):
    """A response could not be proven complete under the framing contract."""

    def __init__(
        self,
        code: str,
        detail: str,
        observation: dict[str, Any] | None,
        *,
        original: BaseException | None = None,
    ) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.observation = observation
        self.original = original


def case(
    identifier: str,
    path: str,
    *,
    response_format: str,
    accept: str,
    content_types: tuple[str, ...],
    maximum_body_bytes: int,
    classification: str = "core_operation_candidate",
    expected_statuses: tuple[int, ...] = (200,),
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "method": METHOD,
        "path": path,
        "query": dict(query or {}),
        "accept": accept,
        "response_format": response_format,
        "classification": classification,
        "expected_statuses": list(expected_statuses),
        "expected_content_types": list(content_types),
        "maximum_body_bytes": maximum_body_bytes,
    }


STRUCTURED_FORMATS = {
    "JSON": {
        "response_format": "json",
        "accept": "application/json",
        "content_types": JSON_TYPES,
    },
    "JSONP": {
        "response_format": "jsonp",
        "accept": "application/javascript",
        "content_types": JSONP_TYPES,
    },
    "XML": {
        "response_format": "xml",
        "accept": "application/xml",
        "content_types": XML_TYPES,
    },
    "ASNT": {
        "response_format": "asnt",
        "accept": "text/plain",
        "content_types": ASNT_TYPES,
    },
    "ASNB": {
        "response_format": "asnb",
        "accept": "application/octet-stream",
        "content_types": ASNB_TYPES,
    },
}
CANDIDATE_STATUSES = (200, 400, 404, 501)
DOCUMENTED_DATA_IDENTIFIERS = {
    "compound": "1234",
    "substance": "1",
    "assay": "1",
    "patent": "US-5837728-A",
    "gene": "1",
    "protein": "P00533",
    "pathway": "Reactome:R-HSA-70171",
    "taxonomy": "9606",
    "cell": "HeLa",
    "element": "17",
}
INDEX_IDENTIFIERS = {
    "compound": "1234",
    # These two controls are retained from the separately reviewed 18-case
    # supplement design; this new asset will make their evidence durable.
    "substance": "103164874",
    "element": "8",
}
INVALID_INDEX_IDENTIFIERS = {
    "assay": "92967",
    "patent": "US-5837728-A",
    "gene": "3690",
    "protein": "P05106",
    "pathway": "Reactome:R-HSA-109582",
    "taxonomy": "9606",
    "cell": "HeLa",
}
REPORT_EXAMPLES = {
    "annotations": "/rest/pug_view/annotations/heading/Viscosity",
    "categories": "/rest/pug_view/categories/compound/1234",
    "literature": "/rest/pug_view/literature/compound/1234",
    "structure": "/rest/pug_view/structure/compound/2244",
}
LINKOUT_IDENTIFIERS = {
    "compound": "1234",
    "substance": "1",
    "assay": "1",
}


def structured_case(
    identifier: str,
    base_path: str,
    format_name: str,
    *,
    maximum_body_bytes: int,
) -> dict[str, Any]:
    format_contract = STRUCTURED_FORMATS[format_name]
    content_types = tuple(format_contract["content_types"])
    if "application/json" not in content_types:
        # Unsupported candidate routes are expected to return PubChem's JSON
        # error representation; exact status, type, headers, and bytes remain
        # captured rather than being promoted by this runner.
        content_types = (*content_types, *JSON_TYPES)
    return case(
        identifier,
        f"{base_path}/{format_name}",
        query={"callback": "func"} if format_name == "JSONP" else None,
        response_format=str(format_contract["response_format"]),
        accept=str(format_contract["accept"]),
        content_types=content_types,
        maximum_body_bytes=maximum_body_bytes,
        classification="core_operation_candidate",
        expected_statuses=CANDIDATE_STATUSES,
    )


def build_cases() -> tuple[dict[str, Any], ...]:
    result: list[dict[str, Any]] = []
    for record_type, identifier in DOCUMENTED_DATA_IDENTIFIERS.items():
        base_path = f"/rest/pug_view/data/{record_type}/{identifier}"
        for format_name in STRUCTURED_FORMATS:
            result.append(
                structured_case(
                    f"pug_view_data_{record_type}_{format_name.lower()}",
                    base_path,
                    format_name,
                    maximum_body_bytes=DATA_OR_REPORT_CAP,
                )
            )
    for record_type, identifier in INDEX_IDENTIFIERS.items():
        base_path = f"/rest/pug_view/index/{record_type}/{identifier}"
        for format_name in STRUCTURED_FORMATS:
            result.append(
                structured_case(
                    f"pug_view_index_{record_type}_{format_name.lower()}",
                    base_path,
                    format_name,
                    maximum_body_bytes=INDEX_OR_IMAGE_CAP,
                )
            )
    for record_type, identifier in INVALID_INDEX_IDENTIFIERS.items():
        result.append(
            case(
                f"pug_view_invalid_index_{record_type}",
                f"/rest/pug_view/index/{record_type}/{identifier}/JSON",
                response_format="negative_json",
                accept="application/json",
                content_types=JSON_TYPES,
                maximum_body_bytes=NEGATIVE_CAP,
                classification="provider_native_negative",
                expected_statuses=(400,),
            )
        )
    for report_name, base_path in REPORT_EXAMPLES.items():
        for format_name in STRUCTURED_FORMATS:
            result.append(
                structured_case(
                    f"pug_view_{report_name}_{format_name.lower()}",
                    base_path,
                    format_name,
                    maximum_body_bytes=DATA_OR_REPORT_CAP,
                )
            )
    for record_type, identifier in LINKOUT_IDENTIFIERS.items():
        base_path = f"/rest/pug_view/linkout/{record_type}/{identifier}"
        for format_name in STRUCTURED_FORMATS:
            result.append(
                structured_case(
                    f"pug_view_linkout_{record_type}_{format_name.lower()}",
                    base_path,
                    format_name,
                    maximum_body_bytes=DATA_OR_REPORT_CAP,
                )
            )
    result.extend(
        (
            case(
                "pug_compound_record_png",
                "/rest/pug/compound/cid/2244/record/PNG",
                query={"record_type": "2d"},
                response_format="png",
                accept="image/png",
                content_types=(*PNG_TYPES, *JSON_TYPES),
                maximum_body_bytes=INDEX_OR_IMAGE_CAP,
                classification="core_operation_candidate",
                expected_statuses=CANDIDATE_STATUSES,
            ),
            case(
                "pug_view_biologic_image_svg",
                "/rest/pug_view/image/biologic/243577/SVG",
                response_format="svg",
                accept="image/svg+xml",
                content_types=(*SVG_TYPES, *JSON_TYPES),
                maximum_body_bytes=INDEX_OR_IMAGE_CAP,
                classification="core_operation_candidate",
                expected_statuses=CANDIDATE_STATUSES,
            ),
            case(
                "pug_view_qr_short_compound_svg",
                "/rest/pug_view/qr/short/compound/1234/SVG",
                response_format="svg",
                accept="image/svg+xml",
                content_types=(*SVG_TYPES, *JSON_TYPES),
                maximum_body_bytes=QR_CAP,
                classification="core_operation_candidate",
                expected_statuses=CANDIDATE_STATUSES,
            ),
            case(
                "pug_view_qr_long_compound_svg",
                "/rest/pug_view/qr/long/compound/1234/SVG",
                response_format="svg",
                accept="image/svg+xml",
                content_types=(*SVG_TYPES, *JSON_TYPES),
                maximum_body_bytes=QR_CAP,
                classification="core_operation_candidate",
                expected_statuses=CANDIDATE_STATUSES,
            ),
            case(
                "pug_view_native_attachment",
                "/rest/pug_view/data/key/236678_1",
                response_format="attachment",
                accept="*/*",
                content_types=(*ATTACHMENT_TYPES, *JSON_TYPES),
                maximum_body_bytes=ATTACHMENT_CAP,
                classification="core_operation_candidate",
                expected_statuses=CANDIDATE_STATUSES,
            ),
        )
    )
    return tuple(result)


CASES = build_cases()


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


LOADED_RUNNER_SHA256 = digest(RUNNER_PATH.read_bytes())
LOADED_BINARY_HELPER_SHA256 = digest(LOADED_BINARY_HELPER_BYTES)


class CaptureIdentity(NamedTuple):
    runner_sha256: str
    binary_helper_sha256: str
    source_pins_sha256: str


def validate_expected_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase sha256:<64 hex> digest")
    return value


def file_digest(path: Path) -> str:
    return digest(path.read_bytes())


def verify_capture_identity(identity: CaptureIdentity) -> None:
    if LOADED_RUNNER_SHA256 != identity.runner_sha256:
        raise ValueError("loaded runner does not match the externally reviewed SHA-256")
    if file_digest(RUNNER_PATH) != identity.runner_sha256:
        raise ValueError("runner file drifted from the loaded reviewed source")
    if LOADED_BINARY_HELPER_SHA256 != identity.binary_helper_sha256:
        raise ValueError(
            "loaded binary-response helper does not match the externally reviewed SHA-256"
        )
    if file_digest(BINARY_RESPONSE_HELPER) != identity.binary_helper_sha256:
        raise ValueError("binary-response helper drifted from the loaded reviewed source")
    if file_digest(OFFICIAL_SOURCE_PINS) != identity.source_pins_sha256:
        raise ValueError("official source pins drifted from the externally reviewed SHA-256")


def freeze_capture_identity(
    *,
    expected_runner_sha256: str,
    expected_binary_helper_sha256: str,
    expected_source_pins_sha256: str,
) -> CaptureIdentity:
    identity = CaptureIdentity(
        runner_sha256=validate_expected_sha256(
            expected_runner_sha256,
            label="expected runner SHA-256",
        ),
        binary_helper_sha256=validate_expected_sha256(
            expected_binary_helper_sha256,
            label="expected binary-helper SHA-256",
        ),
        source_pins_sha256=validate_expected_sha256(
            expected_source_pins_sha256,
            label="expected source-pins SHA-256",
        ),
    )
    verify_capture_identity(identity)
    return identity


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def validate_origin_path(path: Any, *, case_id: str) -> str:
    segments = path.split("/") if isinstance(path, str) else []
    if (
        not isinstance(path, str)
        or not path.isascii()
        or ORIGIN_PATH_PATTERN.fullmatch(path) is None
        or "" in segments[1:]
        or any(segment in {".", ".."} for segment in segments)
        or any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in path
        )
    ):
        raise ValueError(f"{case_id} has a non-canonical origin-form path")
    return path


def validate_cases() -> None:
    expected_case_count = (
        len(DOCUMENTED_DATA_IDENTIFIERS) * len(STRUCTURED_FORMATS)
        + len(INDEX_IDENTIFIERS) * len(STRUCTURED_FORMATS)
        + len(INVALID_INDEX_IDENTIFIERS)
        + len(REPORT_EXAMPLES) * len(STRUCTURED_FORMATS)
        + len(LINKOUT_IDENTIFIERS) * len(STRUCTURED_FORMATS)
        + 5
    )
    if len(CASES) != expected_case_count:
        raise ValueError(
            f"derived supplement must contain {expected_case_count} cases, got {len(CASES)}"
        )
    ids = [item["id"] for item in CASES]
    if len(ids) != len(set(ids)):
        raise ValueError("supplement case IDs must be unique")
    expected_keys = {
        "id",
        "method",
        "path",
        "query",
        "accept",
        "response_format",
        "classification",
        "expected_statuses",
        "expected_content_types",
        "maximum_body_bytes",
    }
    for item in CASES:
        if set(item) != expected_keys:
            raise ValueError(f"{item.get('id', '<missing>')} case fields drifted")
        if item["method"] != METHOD:
            raise ValueError(f"{item['id']} is not GET")
        validate_origin_path(item["path"], case_id=item["id"])
        if not isinstance(item["query"], dict) or not all(
            isinstance(key, str)
            and key.isascii()
            and isinstance(value, str)
            and value.isascii()
            and "\r" not in key
            and "\n" not in key
            and "\r" not in value
            and "\n" not in value
            for key, value in item["query"].items()
        ):
            raise ValueError(f"{item['id']} has an invalid query")
        if (
            not isinstance(item["accept"], str)
            or not item["accept"].isascii()
            or "\r" in item["accept"]
            or "\n" in item["accept"]
        ):
            raise ValueError(f"{item['id']} has an invalid Accept value")
        response_format = item["response_format"]
        if response_format not in TEXTUAL_FORMATS | BINARY_FORMATS:
            raise ValueError(f"{item['id']} has an invalid response format")
        if item["classification"] not in CLASSIFICATIONS:
            raise ValueError(f"{item['id']} has an invalid classification")
        if (
            not isinstance(item["expected_statuses"], list)
            or not item["expected_statuses"]
            or not all(
                isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599
                for status in item["expected_statuses"]
            )
        ):
            raise ValueError(f"{item['id']} has invalid expected statuses")
        content_types = item["expected_content_types"]
        if (
            not isinstance(content_types, list)
            or not content_types
            or not all(
                isinstance(content_type, str)
                and CONTENT_TYPE_PATTERN.fullmatch(content_type) is not None
                for content_type in content_types
            )
        ):
            raise ValueError(f"{item['id']} has invalid expected content types")
        maximum = item["maximum_body_bytes"]
        if (
            not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not 0 < maximum <= ATTACHMENT_CAP
        ):
            raise ValueError(f"{item['id']} has an invalid body cap")
        if item["classification"] == "provider_native_negative":
            if item["expected_statuses"] != [400] or response_format != "negative_json":
                raise ValueError(f"{item['id']} negative contract drifted")
            if maximum != NEGATIVE_CAP:
                raise ValueError(f"{item['id']} negative body cap drifted")
        elif item["expected_statuses"] != list(CANDIDATE_STATUSES):
            raise ValueError(f"{item['id']} candidate status contract drifted")
    if sum(item["classification"] == "core_operation_candidate" for item in CASES) != len(
        CASES
    ) - len(INVALID_INDEX_IDENTIFIERS):
        raise ValueError("supplement core-candidate classification drifted")
    if sum(item["classification"] == "provider_native_negative" for item in CASES) != len(
        INVALID_INDEX_IDENTIFIERS
    ):
        raise ValueError("supplement provider-native negative classification drifted")


def request_url(spec: dict[str, Any]) -> str:
    path = validate_origin_path(spec.get("path"), case_id=str(spec.get("id", "<missing>")))
    query = urlencode(sorted(spec["query"].items()))
    return BASE + path + (f"?{query}" if query else "")


def request_headers(spec: dict[str, Any]) -> dict[str, str]:
    return {
        "accept": spec["accept"],
        "accept-encoding": "identity",
        "connection": "close",
        "host": HOST,
        "user-agent": USER_AGENT,
    }


def canonical_request(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": METHOD,
        "url": request_url(spec),
        "path": spec["path"],
        "query": sorted((str(key), str(value)) for key, value in spec["query"].items()),
        "headers": request_headers(spec),
        "body_bytes": 0,
    }


def request_fingerprint(spec: dict[str, Any]) -> str:
    return digest(
        json.dumps(
            canonical_request(spec),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def request_record_fields(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": spec["id"],
        "method": METHOD,
        "path": spec["path"],
        "query": dict(spec["query"]),
        "request_headers": request_headers(spec),
        "request_body_bytes": 0,
        "request_fingerprint_sha256": request_fingerprint(spec),
        "classification": spec["classification"],
        "response_format": spec["response_format"],
        "expected_statuses": list(spec["expected_statuses"]),
        "expected_content_types": list(spec["expected_content_types"]),
        "maximum_body_bytes": spec["maximum_body_bytes"],
    }


def case_manifest() -> list[dict[str, Any]]:
    validate_cases()
    return [
        {
            **item,
            "request_fingerprint_sha256": request_fingerprint(item),
        }
        for item in CASES
    ]


def manifest_digest() -> str:
    return digest(
        json.dumps(
            case_manifest(),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def capture_provenance(identity: CaptureIdentity) -> dict[str, Any]:
    verify_capture_identity(identity)
    return {
        "authentication": "credential_free",
        "environment": "public_production",
        "grounding_level": "G3_PUBLIC_PRODUCTION_GET_CAPTURE",
        "capture_lane": "controlled_authoring_get_capture",
        "runtime_live_method_eligible": True,
        "sandbox": False,
        "capture_runner_sha256": identity.runner_sha256,
        "binary_response_helper_sha256": identity.binary_helper_sha256,
        "official_source_pins_sha256": identity.source_pins_sha256,
    }


def spec_payload() -> dict[str, Any]:
    validate_cases()
    return {
        "schema_version": "datalox_pubchem_pug_view_get_supplement_spec_v1",
        "provider_id": "pubchem",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": METHOD,
        "output": str(OUTPUT_RELATIVE),
        "wire_transport": "direct_verified_tls_http_1_1_connection_close",
        "credential_mode": "none",
        "redirect_count": 0,
        "retry_count": 0,
        "minimum_interval_seconds_after_completion": MIN_INTERVAL_SECONDS,
        "maximum_response_header_bytes": MAX_RESPONSE_HEADER_BYTES,
        "maximum_total_response_bytes": MAX_TOTAL_RESPONSE_BYTES,
        "case_count": len(CASES),
        "core_operation_candidate_case_count": len(CASES) - len(INVALID_INDEX_IDENTIFIERS),
        "provider_native_negative_case_count": len(INVALID_INDEX_IDENTIFIERS),
        "case_manifest_sha256": manifest_digest(),
        "capture_runner_sha256": file_digest(RUNNER_PATH),
        "binary_response_helper_sha256": file_digest(BINARY_RESPONSE_HELPER),
        "official_source_pins_sha256": file_digest(OFFICIAL_SOURCE_PINS),
        "cases": case_manifest(),
    }


def request_bytes(spec: dict[str, Any]) -> bytes:
    parsed = urlparse(request_url(spec))
    if (
        parsed.scheme != "https"
        or parsed.hostname != HOST
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{spec['id']} escaped the exact PubChem HTTPS origin")
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    headers = request_headers(spec)
    if set(headers) != {
        "accept",
        "accept-encoding",
        "connection",
        "host",
        "user-agent",
    }:
        raise ValueError(f"request headers drifted for {spec['id']}")
    if any(name in headers for name in ("authorization", "cookie", "proxy-authorization")):
        raise ValueError(f"secret-bearing request observed for {spec['id']}")
    lines = [
        f"{METHOD} {target} HTTP/1.1",
        f"Host: {headers['host']}",
        f"Accept: {headers['accept']}",
        f"Accept-Encoding: {headers['accept-encoding']}",
        f"Connection: {headers['connection']}",
        f"User-Agent: {headers['user-agent']}",
    ]
    if any("\r" in line or "\n" in line for line in lines):
        raise ValueError(f"request header injection rejected for {spec['id']}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


class WireConnection(Protocol):
    def settimeout(self, value: float) -> None: ...

    def sendall(self, value: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


class AbsoluteDeadlineExceeded(TimeoutError):
    """The single request's monotonic wall-clock deadline expired."""


class AbsoluteDeadline:
    def __init__(
        self,
        timeout_seconds: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0 < timeout_seconds <= DEFAULT_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout must be greater than zero and at most {DEFAULT_TIMEOUT_SECONDS}"
            )
        self._monotonic = monotonic
        self._expires_at = monotonic() + timeout_seconds

    def remaining(self) -> float:
        remaining = self._expires_at - self._monotonic()
        if remaining <= 0:
            raise AbsoluteDeadlineExceeded("absolute capture deadline expired")
        return remaining

    def checkpoint(self) -> None:
        self.remaining()


DNS_RESOLVER_CHILD = r"""
import json
import socket
import sys

addresses = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), type=socket.SOCK_STREAM)
if not addresses:
    raise OSError("DNS returned no addresses")
family, socket_type, protocol, canonical_name, address = addresses[0]
sys.stdout.write(json.dumps({
    "family": family,
    "socket_type": socket_type,
    "protocol": protocol,
    "canonical_name": canonical_name,
    "address": list(address),
}, separators=(",", ":"), sort_keys=True))
"""


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_resolver_result(value: Any) -> tuple[Any, ...]:
    if not isinstance(value, dict) or set(value) != {
        "family",
        "socket_type",
        "protocol",
        "canonical_name",
        "address",
    }:
        raise OSError("DNS resolver child returned an invalid result schema")
    family = value["family"]
    socket_type = value["socket_type"]
    protocol = value["protocol"]
    canonical_name = value["canonical_name"]
    address = value["address"]
    if (
        not isinstance(family, int)
        or isinstance(family, bool)
        or family not in {socket.AF_INET, socket.AF_INET6}
        or socket_type != socket.SOCK_STREAM
        or isinstance(socket_type, bool)
        or protocol not in {0, socket.IPPROTO_TCP}
        or isinstance(protocol, bool)
        or not isinstance(canonical_name, str)
    ):
        raise OSError("DNS resolver child returned invalid socket parameters")
    expected_items = 2 if family == socket.AF_INET else 4
    if not isinstance(address, list) or len(address) != expected_items:
        raise OSError("DNS resolver child returned an invalid address")
    host, port, *scope = address
    if not isinstance(host, str) or port != 443 or isinstance(port, bool):
        raise OSError("DNS resolver child returned an invalid host or port")
    try:
        parsed_host = ipaddress.ip_address(host)
    except ValueError as error:
        raise OSError("DNS resolver child returned a non-IP address") from error
    if (family == socket.AF_INET) != (parsed_host.version == 4):
        raise OSError("DNS resolver child returned an address-family mismatch")
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in scope):
        raise OSError("DNS resolver child returned invalid IPv6 flow/scope fields")
    return family, socket_type, protocol, canonical_name, tuple(address)


def resolve_in_subprocess(
    deadline: AbsoluteDeadline,
    *,
    identity: CaptureIdentity,
) -> tuple[Any, ...]:
    verify_capture_identity(identity)
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", DNS_RESOLVER_CHILD, HOST, "443"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=deadline.remaining())
    except subprocess.TimeoutExpired as error:
        process.kill()
        try:
            process.communicate(timeout=1.0)
        except subprocess.TimeoutExpired as cleanup_error:
            raise RuntimeError(
                "DNS resolver child could not be reaped after kill"
            ) from cleanup_error
        if process.poll() is None:
            raise RuntimeError("DNS resolver child remained alive after kill")
        raise AbsoluteDeadlineExceeded("DNS resolution exceeded absolute deadline") from error
    deadline.checkpoint()
    if process.returncode != 0:
        detail = stderr[-1024:].decode("utf-8", errors="replace").strip()
        raise OSError(f"DNS resolution failed in child process: {detail or process.returncode}")
    if len(stdout) > 4096:
        raise OSError("DNS resolver child output exceeded its fixed cap")
    try:
        result = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise OSError("DNS resolver child returned invalid JSON") from error
    return validate_resolver_result(result)


def resolve_once(
    deadline: AbsoluteDeadline,
    *,
    identity: CaptureIdentity,
    resolver: Callable[..., list[tuple[Any, ...]]] | None = None,
) -> tuple[Any, ...]:
    verify_capture_identity(identity)
    if resolver is None:
        return resolve_in_subprocess(deadline, identity=identity)
    addresses = resolver(HOST, 443, type=socket.SOCK_STREAM)
    deadline.checkpoint()
    if not isinstance(addresses, list) or not addresses:
        raise OSError("DNS returned no addresses for the fixed PubChem host")
    selected = addresses[0]
    if not isinstance(selected, tuple) or len(selected) != 5:
        raise OSError("DNS returned a malformed address tuple")
    return selected


def open_verified_tls_connection(
    deadline: AbsoluteDeadline,
    *,
    identity: CaptureIdentity,
    resolver: Callable[..., list[tuple[Any, ...]]] | None = None,
    socket_factory: Callable[..., WireConnection] = socket.socket,
    ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
) -> WireConnection:
    verify_capture_identity(identity)
    family, socket_type, protocol, _, address = resolve_once(
        deadline,
        identity=identity,
        resolver=resolver,
    )
    raw_socket = socket_factory(family, socket_type, protocol)
    try:
        raw_socket.settimeout(deadline.remaining())
        raw_socket.connect(address)  # type: ignore[attr-defined]
        deadline.checkpoint()
        context = ssl_context_factory()
        if context.check_hostname is not True or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("TLS context must require certificate and hostname verification")
        context.set_alpn_protocols(["http/1.1"])
        raw_socket.settimeout(deadline.remaining())
        connection = context.wrap_socket(
            raw_socket,
            server_hostname=HOST,
            suppress_ragged_eofs=False,
        )
        deadline.checkpoint()
        selected_alpn = getattr(connection, "selected_alpn_protocol", lambda: None)()
        if selected_alpn != "http/1.1":
            raise ValueError(f"TLS negotiated an unsupported protocol: {selected_alpn}")
        connection.settimeout(deadline.remaining())
        return connection
    except BaseException:
        raw_socket.close()
        raise


def send_with_deadline(
    connection: WireConnection,
    value: bytes,
    deadline: AbsoluteDeadline,
) -> None:
    connection.settimeout(deadline.remaining())
    connection.sendall(value)
    deadline.checkpoint()


def recv_with_deadline(
    connection: WireConnection,
    size: int,
    deadline: AbsoluteDeadline,
) -> bytes:
    if not 0 < size <= MAX_WIRE_RECV_BYTES:
        raise ValueError("wire receive size escaped its bound")
    connection.settimeout(deadline.remaining())
    value = connection.recv(size)
    deadline.checkpoint()
    if not isinstance(value, bytes):
        raise TypeError("wire transport returned a non-byte response")
    if len(value) > size:
        raise ValueError("wire transport returned more bytes than requested")
    return value


def read_wire_header(connection: WireConnection, deadline: AbsoluteDeadline) -> bytes:
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        if len(header) >= MAX_RESPONSE_HEADER_BYTES:
            raise ResponseCaptureInterrupted(
                "response_header_limit_exceeded",
                f"maximum={MAX_RESPONSE_HEADER_BYTES}",
                None,
            )
        chunk = recv_with_deadline(connection, 1, deadline)
        if chunk == b"":
            raise ResponseCaptureInterrupted(
                "response_header_incomplete",
                f"captured={len(header)}",
                None,
            )
        header.extend(chunk)
    return bytes(header)


def semantic_headers(fields: list[tuple[str, bytes]]) -> dict[str, str]:
    grouped: dict[str, list[str]] = {}
    for name, raw_value in fields:
        value = raw_value[1:] if raw_value.startswith(b" ") else raw_value
        grouped.setdefault(name.lower(), []).append(value.decode("latin-1"))
    return {name: ", ".join(grouped[name]) for name in SAFE_RESPONSE_HEADERS if name in grouped}


def parse_wire_header(
    raw_header: bytes,
) -> tuple[bytes, int, list[tuple[str, bytes]], dict[str, str]]:
    if len(raw_header) > MAX_RESPONSE_HEADER_BYTES or not raw_header.endswith(b"\r\n\r\n"):
        raise ValueError("response header escaped its exact framing bound")
    lines = raw_header[:-4].split(b"\r\n")
    if not lines:
        raise ValueError("response status line is missing")
    status_match = STATUS_LINE_PATTERN.fullmatch(lines[0])
    if status_match is None:
        raise ValueError("response status line is not HTTP/1.1")
    status = int(status_match.group(1))
    if not 100 <= status <= 599:
        raise ValueError("response status code is outside the HTTP range")
    fields: list[tuple[str, bytes]] = []
    for line in lines[1:]:
        if not line or line.startswith((b" ", b"\t")):
            raise ValueError("empty or obs-fold response header rejected")
        if b":" not in line:
            raise ValueError("response header lacks a colon")
        raw_name, raw_value = line.split(b":", 1)
        if HEADER_NAME_PATTERN.fullmatch(raw_name) is None:
            raise ValueError("response header name is invalid")
        if any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in raw_value):
            raise ValueError("response header value contains a forbidden control byte")
        fields.append((raw_name.decode("ascii"), raw_value))
    return lines[0], status, fields, semantic_headers(fields)


def serialized_header_fields(fields: list[tuple[str, bytes]]) -> list[dict[str, str]]:
    return [
        {"name": name, "value_base64": base64.b64encode(value).decode("ascii")}
        for name, value in fields
    ]


def decode_base64_bounded(value: Any, *, maximum_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or not value.isascii():
        raise ValueError(f"{label} is not an ASCII base64 string")
    if len(value) > ((maximum_bytes + 2) // 3) * 4:
        raise ValueError(f"{label} exceeds its encoded-size cap")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError(f"{label} is not valid base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{label} is not canonical RFC 4648 base64")
    if len(decoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds its decoded-size cap")
    return decoded


def deserialize_header_fields(value: Any) -> list[tuple[str, bytes]]:
    if not isinstance(value, list):
        raise ValueError("response header fields are not a list")
    fields: list[tuple[str, bytes]] = []
    total = 0
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "value_base64"}:
            raise ValueError("response header field schema drifted")
        name = item["name"]
        if (
            not isinstance(name, str)
            or not name.isascii()
            or HEADER_NAME_PATTERN.fullmatch(name.encode("ascii")) is None
        ):
            raise ValueError("response header name is invalid")
        raw_value = decode_base64_bounded(
            item["value_base64"],
            maximum_bytes=MAX_RESPONSE_HEADER_BYTES,
            label="response header value",
        )
        if any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in raw_value):
            raise ValueError("response header value contains a forbidden control byte")
        total += len(name.encode("ascii")) + len(raw_value) + 3
        if total > MAX_RESPONSE_HEADER_BYTES:
            raise ValueError("serialized response headers exceed their aggregate cap")
        fields.append((name, raw_value))
    return fields


def exact_single_header_value(
    fields: list[tuple[str, bytes]],
    *,
    name: str,
) -> tuple[str | None, str]:
    values = [value for field_name, value in fields if field_name.lower() == name]
    if len(values) != 1:
        return None, f"field_count={len(values)}"
    raw = values[0]
    if not raw.startswith(b" ") or raw.startswith(b"  ") or raw.endswith((b" ", b"\t")):
        return None, "noncanonical_ows"
    try:
        return raw[1:].decode("ascii"), "ok"
    except UnicodeDecodeError:
        return None, "not_ascii"


def exact_content_length(fields: list[tuple[str, bytes]]) -> tuple[int | None, str]:
    value, detail = exact_single_header_value(fields, name="content-length")
    if value is None:
        return None, detail
    if CONTENT_LENGTH_PATTERN.fullmatch(value) is None:
        return None, "noncanonical_decimal"
    parsed = int(value)
    if parsed > MAX_TOTAL_RESPONSE_BYTES:
        return MAX_TOTAL_RESPONSE_BYTES + 1, "exceeds_batch_cap"
    return parsed, f"value={value}"


def exact_content_type(fields: list[tuple[str, bytes]]) -> tuple[str | None, str]:
    value, detail = exact_single_header_value(fields, name="content-type")
    if value is None:
        return None, detail
    if CONTENT_TYPE_PATTERN.fullmatch(value) is None:
        return None, "invalid_media_type"
    return value, "ok"


def response_body_value(
    spec: dict[str, Any],
    raw: bytes,
    *,
    content_type: str,
) -> tuple[Any, str]:
    if spec["response_format"] in BINARY_FORMATS:
        return (
            make_binary_response_body(raw, content_type=content_type),
            "datalox_binary_response_v1",
        )
    try:
        return raw.decode("utf-8"), "utf8_text_with_exact_raw_base64"
    except UnicodeDecodeError as error:
        raise ResponseCaptureInterrupted(
            "response_text_encoding_invalid",
            "UnicodeDecodeError",
            None,
            original=error,
        ) from error


def response_observation(
    *,
    spec: dict[str, Any],
    url: str,
    status: int,
    response_headers: dict[str, str],
    header_fields: list[tuple[str, bytes]],
    status_line: bytes,
    content_type: str | None,
    raw: bytes,
    complete: bool,
) -> dict[str, Any]:
    if complete and content_type is not None:
        body, representation = response_body_value(spec, raw, content_type=content_type)
    else:
        body = None
        representation = "partial_raw_base64"
    return {
        "url": url,
        "final_url": url,
        "status": status,
        "response_headers": response_headers,
        "response_header_fields": serialized_header_fields(header_fields),
        "response_status_line_base64": base64.b64encode(status_line).decode("ascii"),
        "content_type": content_type,
        "body": body,
        "body_representation": representation,
        "body_base64": base64.b64encode(raw).decode("ascii"),
        "body_bytes": len(raw),
        "body_sha256": digest(raw),
        "body_transfer": "raw_wire_bytes",
        "body_complete": complete,
        "captured_at": utc_now(),
    }


def terminal_response_reason(
    spec: dict[str, Any],
    *,
    status: int,
    headers: dict[str, str],
    content_type: str,
) -> str | None:
    if status not in spec["expected_statuses"]:
        return f"unexpected_status_{status}"
    if "retry-after" in headers:
        return "provider_retry_after"
    content_encoding = headers.get("content-encoding")
    if content_encoding is not None and content_encoding.lower() != "identity":
        return "unexpected_content_encoding"
    throttle = headers.get("x-throttling-control")
    if throttle is None:
        return "missing_throttling_control"
    match = THROTTLE_PATTERN.fullmatch(throttle)
    if match is None:
        return "unparseable_throttling_control"
    for dimension in ("count", "time", "service"):
        state = match[dimension]
        if state != "Green":
            return f"{dimension}_{state.lower()}"
    if content_type.lower() not in {
        expected.lower() for expected in spec["expected_content_types"]
    }:
        return "unexpected_content_type"
    return None


def capture(
    spec: dict[str, Any],
    *,
    timeout_seconds: float,
    remaining_total_bytes: int,
    identity: CaptureIdentity | None = None,
    connection_factory: Callable[[AbsoluteDeadline], WireConnection] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Any], str | None]:
    if identity is None:
        raise ValueError("externally reviewed identity is required before any capture transport")
    verify_capture_identity(identity)
    url = request_url(spec)
    if spec not in CASES:
        raise ValueError("capture case is not from the frozen manifest")
    if (
        not isinstance(remaining_total_bytes, int)
        or isinstance(remaining_total_bytes, bool)
        or not 0 < remaining_total_bytes <= MAX_TOTAL_RESPONSE_BYTES
    ):
        raise ValueError("remaining total response budget must be positive and bounded")
    response_limit = min(spec["maximum_body_bytes"], remaining_total_bytes)
    deadline = AbsoluteDeadline(timeout_seconds, monotonic=monotonic)
    connection = (
        open_verified_tls_connection(deadline, identity=identity)
        if connection_factory is None
        else connection_factory(deadline)
    )
    pending: BaseException | None = None
    result: tuple[dict[str, Any], str | None] | None = None
    try:
        verify_capture_identity(identity)
        send_with_deadline(connection, request_bytes(spec), deadline)
        raw_header = read_wire_header(connection, deadline)
        try:
            status_line, status, header_fields, response_headers = parse_wire_header(raw_header)
        except ValueError as error:
            raise ResponseCaptureInterrupted(
                "response_header_invalid",
                type(error).__name__,
                None,
                original=error,
            ) from error
        observation_args = {
            "spec": spec,
            "url": url,
            "status": status,
            "response_headers": response_headers,
            "header_fields": header_fields,
            "status_line": status_line,
        }
        transfer_encodings = [
            value for name, value in header_fields if name.lower() == "transfer-encoding"
        ]
        if transfer_encodings:
            observation = response_observation(
                **observation_args,
                content_type=None,
                raw=b"",
                complete=False,
            )
            raise ResponseCaptureInterrupted(
                "response_transfer_encoding_forbidden",
                f"field_count={len(transfer_encodings)}",
                observation,
            )
        declared_length, length_detail = exact_content_length(header_fields)
        if declared_length is None:
            observation = response_observation(
                **observation_args,
                content_type=None,
                raw=b"",
                complete=False,
            )
            raise ResponseCaptureInterrupted(
                "response_length_missing_or_invalid_before_body",
                length_detail,
                observation,
            )
        content_type, content_type_detail = exact_content_type(header_fields)
        if content_type is None:
            observation = response_observation(
                **observation_args,
                content_type=None,
                raw=b"",
                complete=False,
            )
            raise ResponseCaptureInterrupted(
                "response_content_type_missing_or_invalid_before_body",
                content_type_detail,
                observation,
            )
        if declared_length > response_limit:
            observation = response_observation(
                **observation_args,
                content_type=content_type,
                raw=b"",
                complete=False,
            )
            raise ResponseCaptureInterrupted(
                "response_budget_exceeded_before_body",
                f"declared={declared_length}, available={response_limit}",
                observation,
            )
        raw_buffer = bytearray()
        try:
            while len(raw_buffer) < declared_length:
                read_size = min(
                    MAX_WIRE_RECV_BYTES,
                    declared_length - len(raw_buffer),
                    response_limit - len(raw_buffer),
                )
                chunk = recv_with_deadline(connection, read_size, deadline)
                if chunk == b"":
                    raise EOFError("response body ended before Content-Length")
                raw_buffer.extend(chunk)
            trailing = recv_with_deadline(connection, 1, deadline)
            if trailing != b"":
                observation = response_observation(
                    **observation_args,
                    content_type=content_type,
                    raw=bytes(raw_buffer),
                    complete=False,
                )
                raise ResponseCaptureInterrupted(
                    "response_exceeds_declared_length",
                    f"declared={declared_length}, rejected_trailing_bytes_at_least=1",
                    observation,
                )
        except ResponseCaptureInterrupted:
            raise
        except BaseException as error:
            observation = response_observation(
                **observation_args,
                content_type=content_type,
                raw=bytes(raw_buffer),
                complete=False,
            )
            code = (
                "response_eof_unproven"
                if len(raw_buffer) == declared_length
                else "response_stream_interrupted"
            )
            raise ResponseCaptureInterrupted(
                code,
                type(error).__name__,
                observation,
                original=error,
            ) from error
        try:
            observation = response_observation(
                **observation_args,
                content_type=content_type,
                raw=bytes(raw_buffer),
                complete=True,
            )
        except ResponseCaptureInterrupted as error:
            if error.observation is None:
                error.observation = response_observation(
                    **observation_args,
                    content_type=content_type,
                    raw=bytes(raw_buffer),
                    complete=False,
                )
            raise
        record = {
            **request_record_fields(spec),
            **observation,
            "provenance": capture_provenance(identity),
            "redaction": dict(REDACTION),
        }
        result = (
            record,
            terminal_response_reason(
                spec,
                status=status,
                headers=response_headers,
                content_type=content_type,
            ),
        )
    except BaseException as error:
        pending = error
    try:
        connection.close()
    except BaseException as close_error:
        pending_is_interrupt = isinstance(pending, (KeyboardInterrupt, SystemExit)) or (
            isinstance(pending, ResponseCaptureInterrupted)
            and isinstance(pending.original, (KeyboardInterrupt, SystemExit))
        )
        if pending_is_interrupt:
            raise pending
        if pending is None and result is not None:
            record = result[0]
            observation = {key: record[key] for key in RESPONSE_OBSERVATION_KEYS}
            raise ResponseCaptureInterrupted(
                "response_finalization_interrupted",
                type(close_error).__name__,
                observation,
                original=close_error,
            ) from close_error
        if isinstance(close_error, (KeyboardInterrupt, SystemExit)):
            raise close_error
    if pending is not None:
        raise pending
    if result is None:
        raise RuntimeError("wire capture ended without a result")
    verify_capture_identity(identity)
    return result


REQUEST_RECORD_KEYS = {
    "id",
    "method",
    "path",
    "query",
    "request_headers",
    "request_body_bytes",
    "request_fingerprint_sha256",
    "classification",
    "response_format",
    "expected_statuses",
    "expected_content_types",
    "maximum_body_bytes",
}
RESPONSE_OBSERVATION_KEYS = {
    "url",
    "final_url",
    "status",
    "response_headers",
    "response_header_fields",
    "response_status_line_base64",
    "content_type",
    "body",
    "body_representation",
    "body_base64",
    "body_bytes",
    "body_sha256",
    "body_transfer",
    "body_complete",
    "captured_at",
}


def capture_payload(
    records: list[dict[str, Any]],
    *,
    in_flight: dict[str, Any] | None = None,
    halt: dict[str, str] | None = None,
    identity: CaptureIdentity | None = None,
) -> dict[str, Any]:
    if identity is None:
        raise ValueError("externally reviewed identity is required for capture payloads")
    partial_bytes = 0
    if in_flight is not None and in_flight["response_observation"] is not None:
        partial_bytes = in_flight["response_observation"]["body_bytes"]
    total = sum(record["body_bytes"] for record in records) + partial_bytes
    if total > MAX_TOTAL_RESPONSE_BYTES:
        raise ValueError("capture payload exceeds the batch response cap")
    return {
        "schema_version": "datalox_pubchem_pug_view_get_supplement_capture_v1",
        "provider_id": "pubchem",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": METHOD,
        "output": str(OUTPUT_RELATIVE),
        "wire_transport": "direct_verified_tls_http_1_1_connection_close",
        "case_manifest_sha256": manifest_digest(),
        "capture_runner_sha256": identity.runner_sha256,
        "binary_response_helper_sha256": identity.binary_helper_sha256,
        "official_source_pins_sha256": identity.source_pins_sha256,
        "capture_count": len(records),
        "expected_capture_count": len(CASES),
        "core_operation_candidate_capture_count": sum(
            record["classification"] == "core_operation_candidate" for record in records
        ),
        "provider_native_negative_capture_count": sum(
            record["classification"] == "provider_native_negative" for record in records
        ),
        "complete": len(records) == len(CASES) and in_flight is None and halt is None,
        "minimum_interval_seconds_after_completion": MIN_INTERVAL_SECONDS,
        "maximum_response_header_bytes": MAX_RESPONSE_HEADER_BYTES,
        "maximum_total_response_bytes": MAX_TOTAL_RESPONSE_BYTES,
        "total_response_bytes": total,
        "redirect_count": 0,
        "retry_count": 0,
        "secret_headers_forwarded": False,
        "in_flight": in_flight,
        "halt": halt,
        "captures": records,
    }


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_fsynced(path: Path, value: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    encoder = json.JSONEncoder(
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    written = 0
    try:
        with os.fdopen(descriptor, "wb") as handle:
            for text_chunk in encoder.iterencode(value):
                encoded_chunk = text_chunk.encode("utf-8")
                if written + len(encoded_chunk) + 1 > MAX_JOURNAL_FILE_BYTES:
                    raise ValueError("serialized capture payload exceeds the file-size cap")
                handle.write(encoded_chunk)
                written += len(encoded_chunk)
            if written + 1 > MAX_JOURNAL_FILE_BYTES:
                raise ValueError("serialized capture payload exceeds the file-size cap")
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if os.path.exists(path):
            os.unlink(path)
        raise


def atomic_replace_payload(
    path: Path,
    value: dict[str, Any],
    *,
    precommit_check: Callable[[], None] | None = None,
) -> None:
    descriptor, name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary = Path(name)
    try:
        write_fsynced(temporary, value)
        if precommit_check is not None:
            precommit_check()
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()
            fsync_directory(path.parent)


def publish_exclusive(
    path: Path,
    value: dict[str, Any],
    *,
    precommit_check: Callable[[], None] | None = None,
) -> None:
    descriptor, name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary = Path(name)
    try:
        write_fsynced(temporary, value)
        if precommit_check is not None:
            precommit_check()
        os.link(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()
            fsync_directory(path.parent)


def load_json_strict(path: Path) -> dict[str, Any]:
    if stat.S_ISLNK(path.lstat().st_mode):
        raise ValueError("capture journal must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError("capture journal must be a regular file")
        if initial.st_size > MAX_JOURNAL_FILE_BYTES:
            raise ValueError("capture journal exceeds the file-size cap")
        chunks: list[bytes] = []
        retained = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_JOURNAL_FILE_BYTES + 1 - retained),
            )
            if not chunk:
                break
            chunks.append(chunk)
            retained += len(chunk)
            if retained > MAX_JOURNAL_FILE_BYTES:
                raise ValueError("capture journal exceeds the bounded read cap")
        final = os.fstat(descriptor)
        if (
            retained != initial.st_size
            or final.st_dev != initial.st_dev
            or final.st_ino != initial.st_ino
            or final.st_size != initial.st_size
            or final.st_mtime_ns != initial.st_mtime_ns
        ):
            raise ValueError("capture journal changed during bounded ingestion")
    finally:
        os.close(descriptor)
    try:
        encoded = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("capture journal is not valid UTF-8") from error
    result = json.loads(encoded, object_pairs_hook=reject_duplicate_json_keys)
    if not isinstance(result, dict):
        raise ValueError("capture journal root must be an object")
    return result


def validate_timestamp(value: Any) -> None:
    if not isinstance(value, str):
        raise ValueError("capture timestamp is not a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("capture timestamp is invalid") from error
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("capture timestamp is not UTC")


def validate_response_observation(
    observation: Any,
    *,
    spec: dict[str, Any],
    complete: bool,
) -> None:
    if not isinstance(observation, dict) or set(observation) != RESPONSE_OBSERVATION_KEYS:
        raise ValueError(f"response observation fields drifted for {spec['id']}")
    if observation["url"] != request_url(spec) or observation["final_url"] != request_url(spec):
        raise ValueError(f"response URL drifted for {spec['id']}")
    status = observation["status"]
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise ValueError(f"response status is invalid for {spec['id']}")
    fields = deserialize_header_fields(observation["response_header_fields"])
    if observation["response_headers"] != semantic_headers(fields):
        raise ValueError(f"semantic response headers drifted for {spec['id']}")
    status_line = decode_base64_bounded(
        observation["response_status_line_base64"],
        maximum_bytes=MAX_RESPONSE_HEADER_BYTES,
        label="response status line",
    )
    match = STATUS_LINE_PATTERN.fullmatch(status_line)
    if match is None or int(match.group(1)) != status:
        raise ValueError(f"response status line drifted for {spec['id']}")
    raw = decode_base64_bounded(
        observation["body_base64"],
        maximum_bytes=spec["maximum_body_bytes"],
        label=f"response body for {spec['id']}",
    )
    if observation["body_bytes"] != len(raw) or observation["body_sha256"] != digest(raw):
        raise ValueError(f"response body fingerprint drifted for {spec['id']}")
    if observation["body_transfer"] != "raw_wire_bytes":
        raise ValueError(f"response body transfer marker drifted for {spec['id']}")
    if observation["body_complete"] is not complete:
        raise ValueError(f"response completeness drifted for {spec['id']}")
    validate_timestamp(observation["captured_at"])
    content_type, _ = exact_content_type(fields)
    if observation["content_type"] != content_type:
        raise ValueError(f"response content type drifted for {spec['id']}")
    if complete:
        if content_type is None:
            raise ValueError(f"complete response lacks content type for {spec['id']}")
        expected_body, representation = response_body_value(
            spec,
            raw,
            content_type=content_type,
        )
        if (
            observation["body"] != expected_body
            or observation["body_representation"] != representation
        ):
            raise ValueError(f"response representation drifted for {spec['id']}")
    elif observation["body"] is not None or observation["body_representation"] != (
        "partial_raw_base64"
    ):
        raise ValueError(f"partial response representation drifted for {spec['id']}")


def validate_completed_record(
    record: Any,
    *,
    spec: dict[str, Any],
    identity: CaptureIdentity,
) -> str | None:
    expected_keys = (
        REQUEST_RECORD_KEYS
        | RESPONSE_OBSERVATION_KEYS
        | {
            "provenance",
            "redaction",
        }
    )
    if not isinstance(record, dict) or set(record) != expected_keys:
        raise ValueError(f"capture record fields drifted for {spec['id']}")
    if {key: record[key] for key in REQUEST_RECORD_KEYS} != request_record_fields(spec):
        raise ValueError(f"capture request fields drifted for {spec['id']}")
    observation = {key: record[key] for key in RESPONSE_OBSERVATION_KEYS}
    validate_response_observation(observation, spec=spec, complete=True)
    if record["provenance"] != capture_provenance(identity):
        raise ValueError(f"capture provenance drifted for {spec['id']}")
    if record["redaction"] != REDACTION:
        raise ValueError(f"capture redaction marker drifted for {spec['id']}")
    return terminal_response_reason(
        spec,
        status=record["status"],
        headers=record["response_headers"],
        content_type=record["content_type"],
    )


def in_flight_record(
    spec: dict[str, Any],
    *,
    prepared_at: str,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "state": "completion_unknown_do_not_retry",
        "prepared_at": prepared_at,
        "request": request_record_fields(spec),
        "url": request_url(spec),
        "response_observation": response,
    }


def validate_in_flight(value: Any, *, spec: dict[str, Any]) -> None:
    if not isinstance(value, dict) or set(value) != {
        "state",
        "prepared_at",
        "request",
        "url",
        "response_observation",
    }:
        raise ValueError("in-flight record fields drifted")
    if value["state"] != "completion_unknown_do_not_retry":
        raise ValueError("in-flight state drifted")
    validate_timestamp(value["prepared_at"])
    if value["request"] != request_record_fields(spec) or value["url"] != request_url(spec):
        raise ValueError("in-flight request drifted")
    observation = value["response_observation"]
    if observation is not None:
        if not isinstance(observation, dict) or not isinstance(
            observation.get("body_complete"), bool
        ):
            raise ValueError("in-flight response completeness is invalid")
        validate_response_observation(
            observation,
            spec=spec,
            complete=observation["body_complete"],
        )


def validate_halt(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"case_id", "code", "detail"}
        or not all(isinstance(item, str) and item for item in value.values())
    ):
        raise ValueError("capture halt envelope is invalid")
    return value


def validate_saved_envelope(
    saved: Any,
    *,
    identity: CaptureIdentity,
) -> list[dict[str, Any]]:
    verify_capture_identity(identity)
    if not isinstance(saved, dict):
        raise ValueError("capture journal root is not an object")
    expected_keys = set(capture_payload([], identity=identity))
    if set(saved) != expected_keys:
        raise ValueError("capture journal fields drifted")
    records = saved["captures"]
    if not isinstance(records, list) or len(records) > len(CASES):
        raise ValueError("capture journal records are invalid")
    terminal_reasons: list[str | None] = []
    for index, record in enumerate(records):
        terminal_reasons.append(
            validate_completed_record(
                record,
                spec=CASES[index],
                identity=identity,
            )
        )
    terminal_indexes = [
        index for index, reason in enumerate(terminal_reasons) if reason is not None
    ]
    if terminal_indexes and terminal_indexes != [len(records) - 1]:
        raise ValueError("capture continued after a terminal provider response")
    halt = validate_halt(saved["halt"])
    in_flight = saved["in_flight"]
    next_spec = CASES[len(records)] if len(records) < len(CASES) else None
    if in_flight is not None:
        if next_spec is None:
            raise ValueError("complete sequence cannot retain an in-flight request")
        validate_in_flight(in_flight, spec=next_spec)
        if terminal_indexes:
            raise ValueError("in-flight request followed a terminal provider response")
        if halt is not None and halt["case_id"] != next_spec["id"]:
            raise ValueError("in-flight halt case drifted")
        observation = in_flight["response_observation"]
        if halt is None:
            if observation is not None:
                raise ValueError("predispatch journal cannot contain a response")
        else:
            without_response = {
                "post_dispatch_exception_unknown_completion",
                "process_interrupted_unknown_completion",
                "request_error_unknown_completion",
                "response_header_incomplete",
                "response_header_invalid",
                "response_header_limit_exceeded",
            }
            with_incomplete_response = {
                "response_budget_exceeded_before_body",
                "response_content_type_missing_or_invalid_before_body",
                "response_eof_unproven",
                "response_exceeds_declared_length",
                "response_length_missing_or_invalid_before_body",
                "response_stream_interrupted",
                "response_text_encoding_invalid",
                "response_transfer_encoding_forbidden",
            }
            with_complete_response = {"response_finalization_interrupted"}
            if observation is None and halt["code"] not in without_response:
                raise ValueError("in-flight halt does not match an absent response")
            if observation is not None:
                if observation["body_complete"] is False:
                    if halt["code"] not in with_incomplete_response:
                        raise ValueError("in-flight halt does not match an incomplete response")
                elif halt["code"] not in with_complete_response:
                    raise ValueError("in-flight halt does not match a complete response")
    expected_terminal_halt = None
    if terminal_indexes:
        index = terminal_indexes[0]
        expected_terminal_halt = {
            "case_id": CASES[index]["id"],
            "code": "provider_terminal_signal",
            "detail": str(terminal_reasons[index]),
        }
    if in_flight is None and halt != expected_terminal_halt:
        if not (
            halt is not None
            and halt["code"] == "batch_response_budget_exhausted_before_dispatch"
            and next_spec is not None
            and halt["case_id"] == next_spec["id"]
        ):
            raise ValueError("capture journal terminal halt drifted")
    expected = capture_payload(
        records,
        in_flight=in_flight,
        halt=halt,
        identity=identity,
    )
    if saved != expected:
        raise ValueError("capture journal derived fields drifted")
    return records


def exception_halt(
    spec: dict[str, Any],
    error: BaseException,
) -> tuple[dict[str, str], dict[str, Any] | None, BaseException | None]:
    if isinstance(error, ResponseCaptureInterrupted):
        return (
            {"case_id": spec["id"], "code": error.code, "detail": error.detail},
            error.observation,
            error.original,
        )
    if isinstance(error, (OSError, TimeoutError, ssl.SSLError)):
        code = "request_error_unknown_completion"
    elif isinstance(error, (KeyboardInterrupt, SystemExit)):
        code = "process_interrupted_unknown_completion"
    else:
        code = "post_dispatch_exception_unknown_completion"
    return (
        {"case_id": spec["id"], "code": code, "detail": type(error).__name__},
        None,
        error,
    )


CaptureFunction = Callable[..., tuple[dict[str, Any], str | None]]


def run_capture(
    *,
    timeout_seconds: float,
    resume: bool,
    capture_function: CaptureFunction = capture,
    expected_runner_sha256: str | None = None,
    expected_binary_helper_sha256: str | None = None,
    expected_source_pins_sha256: str | None = None,
) -> None:
    if (
        expected_runner_sha256 is None
        or expected_binary_helper_sha256 is None
        or expected_source_pins_sha256 is None
    ):
        raise ValueError("all three externally reviewed SHA-256 identities are required")
    identity = freeze_capture_identity(
        expected_runner_sha256=expected_runner_sha256,
        expected_binary_helper_sha256=expected_binary_helper_sha256,
        expected_source_pins_sha256=expected_source_pins_sha256,
    )
    validate_cases()
    if not 0 < timeout_seconds <= DEFAULT_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be greater than zero and at most {DEFAULT_TIMEOUT_SECONDS}")

    def bound_payload(
        records: list[dict[str, Any]],
        *,
        in_flight: dict[str, Any] | None = None,
        halt: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        verify_capture_identity(identity)
        return capture_payload(
            records,
            in_flight=in_flight,
            halt=halt,
            identity=identity,
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    lock = OUTPUT.with_suffix(OUTPUT.suffix + ".lock")
    partial = OUTPUT.with_suffix(OUTPUT.suffix + ".partial")
    lock_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    lock_flags |= getattr(os, "O_NOFOLLOW", 0)
    lock_descriptor = os.open(lock, lock_flags, 0o600)
    os.close(lock_descriptor)
    fsync_directory(OUTPUT.parent)
    try:
        partial_present = os.path.lexists(partial)
        output_present = os.path.lexists(OUTPUT)
        if resume and not partial_present:
            raise FileNotFoundError("refusing resume without a partial capture journal")
        if output_present or (partial_present and not resume):
            raise FileExistsError(f"refusing overwrite or unrequested resume: {OUTPUT}")
        if partial_present:
            saved = load_json_strict(partial)
            records = validate_saved_envelope(saved, identity=identity)
            if saved["in_flight"] is not None:
                raise CaptureHalt(
                    "partial capture has unresolved in-flight state; it cannot be resumed"
                )
            if saved["halt"] is not None:
                raise CaptureHalt(
                    "partial capture records a terminal halt; manual review is required"
                )
        else:
            records = []

        for spec in CASES[len(records) :]:
            if records:
                time.sleep(MIN_INTERVAL_SECONDS)
            consumed = sum(record["body_bytes"] for record in records)
            remaining = MAX_TOTAL_RESPONSE_BYTES - consumed
            if remaining <= 0:
                halt = {
                    "case_id": spec["id"],
                    "code": "batch_response_budget_exhausted_before_dispatch",
                    "detail": str(consumed),
                }
                atomic_replace_payload(
                    partial,
                    bound_payload(records, halt=halt),
                    precommit_check=lambda: verify_capture_identity(identity),
                )
                raise CaptureHalt("total response budget exhausted before dispatch")
            prepared_at = utc_now()
            atomic_replace_payload(
                partial,
                bound_payload(
                    records,
                    in_flight=in_flight_record(spec, prepared_at=prepared_at),
                ),
                precommit_check=lambda: verify_capture_identity(identity),
            )
            print(f"capturing {spec['id']}", flush=True)
            try:
                record, halt_reason = capture_function(
                    spec,
                    timeout_seconds=timeout_seconds,
                    remaining_total_bytes=remaining,
                    identity=identity,
                )
                verify_capture_identity(identity)
                actual_halt = validate_completed_record(
                    record,
                    spec=spec,
                    identity=identity,
                )
                if actual_halt != halt_reason:
                    raise ValueError("capture function terminal classification drifted")
                next_records = [*records, record]
                halt = (
                    {
                        "case_id": spec["id"],
                        "code": "provider_terminal_signal",
                        "detail": halt_reason,
                    }
                    if halt_reason is not None
                    else None
                )
                atomic_replace_payload(
                    partial,
                    bound_payload(next_records, halt=halt),
                    precommit_check=lambda: verify_capture_identity(identity),
                )
            except BaseException as error:
                halt, observation, original = exception_halt(spec, error)
                if observation is not None:
                    try:
                        if not isinstance(observation.get("body_complete"), bool):
                            raise ValueError("response completeness is invalid")
                        validate_response_observation(
                            observation,
                            spec=spec,
                            complete=observation["body_complete"],
                        )
                    except (KeyError, TypeError, ValueError):
                        halt = {
                            "case_id": spec["id"],
                            "code": "post_dispatch_exception_unknown_completion",
                            "detail": "invalid_response_observation_rejected",
                        }
                        observation = None
                        original = error
                try:
                    atomic_replace_payload(
                        partial,
                        bound_payload(
                            records,
                            in_flight=in_flight_record(
                                spec,
                                prepared_at=prepared_at,
                                response=observation,
                            ),
                            halt=halt,
                        ),
                        precommit_check=lambda: verify_capture_identity(identity),
                    )
                except BaseException:
                    if isinstance(original, (KeyboardInterrupt, SystemExit)):
                        raise original
                    raise
                if isinstance(original, (KeyboardInterrupt, SystemExit)):
                    raise original
                raise CaptureHalt(
                    f"terminal unknown completion for {spec['id']}; no retry is permitted"
                ) from error
            records = next_records
            if halt is not None:
                raise CaptureHalt(f"terminal provider signal after {spec['id']}: {halt_reason}")

        final_payload = bound_payload(records)
        publish_exclusive(
            OUTPUT,
            final_payload,
            precommit_check=lambda: verify_capture_identity(identity),
        )
        partial.unlink()
        fsync_directory(OUTPUT.parent)
    finally:
        if lock.exists():
            lock.unlink()
            fsync_directory(OUTPUT.parent)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Print or execute the reviewed credential-free PubChem PUG-View "
            "supplemental GET capture."
        )
    )
    parser.add_argument("--print-spec", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--expected-runner-sha256")
    parser.add_argument("--expected-binary-helper-sha256")
    parser.add_argument("--expected-source-pins-sha256")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args()
    if args.print_spec:
        print(json.dumps(spec_payload(), indent=2, sort_keys=True))
        return 0
    if not args.write:
        parser.error("capture is explicit: pass --write or inspect --print-spec")
    expected = (
        args.expected_runner_sha256,
        args.expected_binary_helper_sha256,
        args.expected_source_pins_sha256,
    )
    if any(item is None for item in expected):
        parser.error(
            "--write requires externally reviewed runner, binary-helper, "
            "and source-pins SHA-256 values"
        )
    run_capture(
        timeout_seconds=args.timeout,
        resume=args.resume,
        expected_runner_sha256=args.expected_runner_sha256,
        expected_binary_helper_sha256=args.expected_binary_helper_sha256,
        expected_source_pins_sha256=args.expected_source_pins_sha256,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
