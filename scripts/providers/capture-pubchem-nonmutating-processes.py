#!/usr/bin/env python3
"""Authoring-only PubChem POST eligibility probe.

This script is deliberately outside the runtime live lane. It may be run only
after human review, and every request is a credential-free, non-mutating
retrieval or process request to the single allowlisted PubChem host.

The partial journal is intentionally conservative: immediately before every
POST it durably records an ``in_flight`` request. Any unresolved in-flight
request is terminal and can never be resumed, because its provider completion
state is unknown.
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
from typing import Any, NamedTuple, Protocol
from urllib.parse import urlencode, urlparse


RUNNER_PATH = Path(__file__).resolve()
ROOT = RUNNER_PATH.parents[2]
OUTPUT = ROOT / "envs/pubchem_public_v0/evidence/public_nonmutating_process_capture.json"
OFFICIAL_SOURCE_PINS = ROOT / "envs/pubchem_public_v0/evidence/official_source_pins.json"
BASE = "https://pubchem.ncbi.nlm.nih.gov"
HOST = "pubchem.ncbi.nlm.nih.gov"
METHOD = "POST"
MIN_INTERVAL_SECONDS = 0.5
MAX_REQUEST_BODY_BYTES = 64_000
MAX_RESPONSE_BODY_BYTES = 5_000_000
MAX_TOTAL_RESPONSE_BYTES = 50_000_000
MAX_RESPONSE_HEADER_BYTES = 64_000
MAX_WIRE_RECV_BYTES = 64 * 1024
REVIEWED_CASE_COUNT = 42
DEFAULT_TIMEOUT_SECONDS = 30.0
OFFICIAL_STATUSES = {200, 202, 400, 404, 405, 500, 501, 503, 504}
SAFE_RESPONSE_HEADERS = (
    "content-type",
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "date",
    "cache-control",
    "x-throttling-control",
    "retry-after",
)
ELIGIBILITY_VALUES = {"explicit", "generic_many_not_all"}
PUG_REST_SPECIFICATION = "pug-rest.md"
PUG_REST_TUTORIAL = "pug-rest-tutorial.md"
USER_AGENT = "datalox-pubchem-authoring-post-evidence/4.0"
THROTTLE_PATTERN = re.compile(
    r"Request Count status: (?P<count>Green|Yellow|Red|Black) \(\d+%\), "
    r"Request Time status: (?P<time>Green|Yellow|Red|Black) \(\d+%\), "
    r"Service status: (?P<service>Green|Yellow|Red|Black) \(\d+%\)"
)
CONTENT_LENGTH_PATTERN = re.compile(r"[0-9]+", re.ASCII)
HEADER_NAME_PATTERN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
STATUS_LINE_PATTERN = re.compile(rb"HTTP/1[.]1 ([0-9]{3})(?: (.*))?")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
ORIGIN_PATH_PATTERN = re.compile(r"/rest/pug/[A-Za-z0-9._~/-]+", re.ASCII)
HALT_KEYS = {"case_id", "code", "detail"}
REQUEST_RECORD_KEYS = {
    "id",
    "method",
    "path",
    "query",
    "request_headers",
    "request_body_base64",
    "request_body_bytes",
    "request_body_sha256",
    "request_fingerprint_sha256",
    "eligibility",
}
RESPONSE_OBSERVATION_KEYS = {
    "url",
    "final_url",
    "status",
    "response_headers",
    "response_header_fields",
    "response_status_line_base64",
    "body_base64",
    "body_bytes",
    "body_sha256",
    "body_transfer",
    "body_complete",
    "captured_at",
}
REDACTION = {"agent_auth_cookie_or_secret_headers_forwarded": False}


def base64_encoded_ceiling(raw_bytes: int) -> int:
    return 4 * ((raw_bytes + 2) // 3)


# The journal can contain all reviewed request bodies, the full 50 MB aggregate
# response budget, response headers and status lines for each case plus one
# in-flight observation, and a bounded allowance for JSON/envelope metadata.
MAX_JOURNAL_ENVELOPE_OVERHEAD_BYTES = 10_000_000
MAX_JOURNAL_FILE_BYTES = (
    base64_encoded_ceiling(MAX_TOTAL_RESPONSE_BYTES)
    + REVIEWED_CASE_COUNT * base64_encoded_ceiling(MAX_REQUEST_BODY_BYTES)
    + 2 * (REVIEWED_CASE_COUNT + 1) * base64_encoded_ceiling(MAX_RESPONSE_HEADER_BYTES)
    + MAX_JOURNAL_ENVELOPE_OVERHEAD_BYTES
)


class CaptureHalt(RuntimeError):
    """A terminal authoring-probe condition that must not be retried."""


class ResponseCaptureInterrupted(Exception):
    """A response began, but its complete raw body could not be captured."""

    def __init__(
        self,
        code: str,
        detail: str,
        observation: dict[str, Any] | None,
        *,
        original: BaseException | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.observation = observation
        self.original = original


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def source(
    *,
    eligibility: str,
    post_document: str,
    post_section: str,
    operation_section: str,
    note: str,
) -> dict[str, str]:
    if eligibility not in ELIGIBILITY_VALUES:
        raise ValueError(f"invalid official eligibility: {eligibility}")
    return {
        "official_eligibility": eligibility,
        "source_document": post_document,
        "source_section": post_section,
        "source_quote_category": eligibility,
        "operation_source_document": PUG_REST_SPECIFICATION,
        "operation_source_section": operation_section,
        "source_note": note,
    }


def generic_post_source(operation_section: str) -> dict[str, str]:
    return source(
        eligibility="generic_many_not_all",
        post_document=PUG_REST_TUTORIAL,
        post_section="How To Use HTTP POST",
        operation_section=operation_section,
        note=(
            "The tutorial says many, but not necessarily all, PUG REST input types "
            "accept POST. A success proves only this exact deployed request."
        ),
    )


def explicit_source(
    post_section: str,
    *,
    operation_section: str | None = None,
    document: str = PUG_REST_SPECIFICATION,
    note: str,
) -> dict[str, str]:
    return source(
        eligibility="explicit",
        post_document=document,
        post_section=post_section,
        operation_section=operation_section or post_section,
        note=note,
    )


def form_case(
    identifier: str,
    path: str,
    body: dict[str, str],
    *,
    eligibility: dict[str, str],
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    encoded = urlencode(body).encode("ascii")
    return {
        "id": identifier,
        "method": METHOD,
        "path": path,
        "query": query or {},
        "content_type": "application/x-www-form-urlencoded",
        "body_base64": base64.b64encode(encoded).decode("ascii"),
        "eligibility": eligibility,
    }


def multipart_case(
    identifier: str,
    path: str,
    field: str,
    value: str,
    *,
    eligibility: dict[str, str],
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    boundary = "DataloxPubChemBoundary"
    normalized_value = value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    encoded = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"\r\n'
        "Content-Type: text/plain\r\n"
        "\r\n"
        f"{normalized_value}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    return {
        "id": identifier,
        "method": METHOD,
        "path": path,
        "query": query or {},
        "content_type": f"multipart/form-data; boundary={boundary}",
        "body_base64": base64.b64encode(encoded).decode("ascii"),
        "eligibility": eligibility,
    }


OPERATION_SECTIONS = {
    "compound": {
        "record": "Full-record Retrieval",
        "property": "Compound Property Tables",
        "synonyms": "Synonyms",
        "description": "Description",
        "sids": "SIDS / CIDS / AIDS",
        "cids": "SIDS / CIDS / AIDS",
        "aids": "SIDS / CIDS / AIDS",
        "assaysummary": "Assay Summary",
        "classification": "Classification",
        "dates": "Dates",
        "xrefs": "XRefs",
        "conformers": "Conformers",
        "identifiers": "Identifiers",
    },
    "substance": {
        "record": "Full-record Retrieval",
        "synonyms": "Synonyms",
        "description": "Description",
        "sids": "SIDS / CIDS / AIDS",
        "cids": "SIDS / CIDS / AIDS",
        "aids": "SIDS / CIDS / AIDS",
        "assaysummary": "Assay Summary",
        "classification": "Classification",
        "dates": "Dates",
        "xrefs": "XRefs",
    },
    "assay": {
        "record": "Full-record Retrieval",
        "concise": "Full-record Retrieval",
        "aids": "SIDS / CIDS / AIDS",
        "sids": "SIDS / CIDS / AIDS",
        "cids": "SIDS / CIDS / AIDS",
        "description": "Assay Description",
        "targets": "Assay Targets",
        "summary": "Assay Summary",
        "classification": "Classification",
        "dates": "Dates",
    },
}
EXPLICIT_PROPERTY_POST = explicit_source(
    "Request (POST) Body",
    operation_section="Compound Property Tables",
    note="The specification gives the CID property POST path and form body.",
)
EXPLICIT_DOSE_RESPONSE_POST = explicit_source(
    "Assay Dose-Response",
    note="The specification gives the AID plus SID POST path and form body.",
)
EXPLICIT_INCHI_POST = explicit_source(
    "How To Use HTTP POST",
    document=PUG_REST_TUTORIAL,
    operation_section="The URL Path",
    note="The tutorial gives this exact InChI-to-CID POST request.",
)
EXPLICIT_SUBSTRUCTURE_POST = explicit_source(
    "Substructure / Superstructure",
    note="The specification gives an InChI POST example for substructure search.",
)
EXPLICIT_SUPERSTRUCTURE_POST = explicit_source(
    "Substructure / Superstructure",
    note=(
        "The specification permits InChI by POST for superstructure search; "
        "this case proves only the exact deployed request."
    ),
)
EXPLICIT_SIMILARITY_2D_POST = explicit_source(
    "Similarity",
    note=(
        "The specification permits InChI by POST for 2D similarity search; "
        "this case proves only the exact deployed request."
    ),
)
EXPLICIT_IDENTITY_POST = explicit_source(
    "Identity",
    note=(
        "The specification permits InChI by POST for identity search; "
        "this case proves only the exact deployed request."
    ),
)
STANDARDIZE_POST_CANDIDATE = generic_post_source("Standardize")
EXPLICIT_LISTKEY_POST = explicit_source(
    "Storing Lists on the Server",
    document=PUG_REST_TUTORIAL,
    operation_section="SIDS / CIDS / AIDS",
    note=(
        "The tutorial explicitly says identifiers in an HTTP POST body can "
        "create a ListKey. This case proves only the exact compound/CID/JSON "
        "request and does not generalize POST eligibility."
    ),
)
FAST_QUERY = {"MaxRecords": "1", "MaxSeconds": "5"}
ASPIRIN_INCHI = "InChI=1S/C9H8O4/c1-6(10)13-8-5-3-2-4-7(8)9(11)12/h2-5H,1H3,(H,11,12)"
METHANE_SDF = (
    "methane\n"
    "  Datalox PubChem authoring probe\n"
    "\n"
    "  1  0  0  0  0  0  0  0  0  0999 V2000\n"
    "    0.0000    0.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  0\n"
    "M  END\n"
    "$$$$"
)

COMPOUND_OPERATIONS = {
    "record": "JSON",
    "property": "property/MolecularFormula/JSON",
    "synonyms": "synonyms/JSON",
    "description": "description/JSON",
    "sids": "sids/JSON",
    "cids": "cids/JSON",
    "aids": "aids/JSON",
    "assaysummary": "assaysummary/JSON",
    "classification": "classification/JSON",
    "dates": "dates/JSON",
    "xrefs": "xrefs/RegistryID/JSON",
    "conformers": "conformers/JSON",
    "identifiers": "identifiers/JSON",
}
SUBSTANCE_OPERATIONS = {
    "record": "JSON",
    "synonyms": "synonyms/JSON",
    "description": "description/JSON",
    "sids": "sids/JSON",
    "cids": "cids/JSON",
    "aids": "aids/JSON",
    "assaysummary": "assaysummary/JSON",
    "classification": "classification/JSON",
    "dates": "dates/JSON",
    "xrefs": "xrefs/RegistryID/JSON",
}
ASSAY_OPERATIONS = {
    "record": "JSON",
    "concise": "concise/JSON",
    "aids": "aids/JSON",
    "sids": "sids/JSON",
    "cids": "cids/JSON",
    "description": "description/JSON",
    "targets": "targets/GeneID/JSON",
    "summary": "summary/JSON",
    "classification": "classification/JSON",
    "dates": "dates/JSON",
}


def direct_cases(
    domain: str,
    namespace: str,
    value: str,
    operations: dict[str, str],
) -> tuple[dict[str, Any], ...]:
    return tuple(
        form_case(
            f"{domain}_{operation}_post",
            f"/rest/pug/{domain}/{namespace}/{suffix}",
            {namespace: value},
            eligibility=(
                EXPLICIT_PROPERTY_POST
                if domain == "compound" and operation == "property"
                else generic_post_source(OPERATION_SECTIONS[domain][operation])
            ),
        )
        for operation, suffix in operations.items()
    )


CASES = (
    *direct_cases("compound", "cid", "2244", COMPOUND_OPERATIONS),
    *direct_cases("substance", "sid", "103164874", SUBSTANCE_OPERATIONS),
    *direct_cases("assay", "aid", "92967", ASSAY_OPERATIONS),
    form_case(
        "assay_doseresponse_post",
        "/rest/pug/assay/aid/doseresponse/JSON",
        {"aid": "504526", "sid": "104169547"},
        eligibility=EXPLICIT_DOSE_RESPONSE_POST,
    ),
    form_case(
        "compound_structure_query_post",
        "/rest/pug/compound/inchi/cids/JSON",
        {"inchi": "InChI=1S/C3H8/c1-3-2/h3H2,1-2H3"},
        eligibility=EXPLICIT_INCHI_POST,
    ),
    form_case(
        "fastsubstructure_post",
        "/rest/pug/compound/fastsubstructure/inchi/cids/JSON",
        {"inchi": ASPIRIN_INCHI},
        query=FAST_QUERY,
        eligibility=EXPLICIT_SUBSTRUCTURE_POST,
    ),
    form_case(
        "fastsuperstructure_post",
        "/rest/pug/compound/fastsuperstructure/inchi/cids/JSON",
        {"inchi": ASPIRIN_INCHI},
        query=FAST_QUERY,
        eligibility=EXPLICIT_SUPERSTRUCTURE_POST,
    ),
    form_case(
        "fastsimilarity_2d_post",
        "/rest/pug/compound/fastsimilarity_2d/inchi/cids/JSON",
        {"inchi": ASPIRIN_INCHI},
        query={**FAST_QUERY, "Threshold": "99"},
        eligibility=EXPLICIT_SIMILARITY_2D_POST,
    ),
    form_case(
        "fastidentity_post",
        "/rest/pug/compound/fastidentity/inchi/cids/JSON",
        {"inchi": ASPIRIN_INCHI},
        query={**FAST_QUERY, "identity_type": "same_connectivity"},
        eligibility=EXPLICIT_IDENTITY_POST,
    ),
    form_case(
        "standardize_inchi_post",
        "/rest/pug/standardize/inchi/JSON",
        {"inchi": "InChI=1S/C3H8/c1-3-2/h3H2,1-2H3"},
        query={"include_components": "false"},
        eligibility=STANDARDIZE_POST_CANDIDATE,
    ),
    form_case(
        "listkey_compound_cids_json_post",
        "/rest/pug/compound/cid/cids/JSON",
        {"cid": "2244,3672"},
        query={"list_return": "listkey"},
        eligibility=EXPLICIT_LISTKEY_POST,
    ),
    multipart_case(
        "standardize_sdf_multipart_post",
        "/rest/pug/standardize/sdf/JSON",
        "sdf",
        METHANE_SDF,
        query={"include_components": "false"},
        eligibility=STANDARDIZE_POST_CANDIDATE,
    ),
)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


LOADED_RUNNER_SHA256 = digest(RUNNER_PATH.read_bytes())


def official_source_pins_digest() -> str:
    return digest(OFFICIAL_SOURCE_PINS.read_bytes())


def capture_runner_digest() -> str:
    return digest(RUNNER_PATH.read_bytes())


class CaptureIdentity(NamedTuple):
    runner_sha256: str
    source_pins_sha256: str


def validate_expected_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase sha256:<64 hex> digest")
    return value


def verify_capture_identity(identity: CaptureIdentity) -> None:
    if LOADED_RUNNER_SHA256 != identity.runner_sha256:
        raise ValueError("loaded capture runner does not match the externally reviewed SHA-256")
    if capture_runner_digest() != identity.runner_sha256:
        raise ValueError("capture runner file drifted from the loaded reviewed source")
    if official_source_pins_digest() != identity.source_pins_sha256:
        raise ValueError("official source pins drifted from the externally reviewed SHA-256")


def freeze_capture_identity(
    *,
    expected_runner_sha256: str | None = None,
    expected_source_pins_sha256: str | None = None,
) -> CaptureIdentity:
    if (expected_runner_sha256 is None) != (expected_source_pins_sha256 is None):
        raise ValueError("both reviewed SHA-256 identities must be supplied together")
    runner_sha256 = validate_expected_sha256(
        LOADED_RUNNER_SHA256 if expected_runner_sha256 is None else expected_runner_sha256,
        label="expected runner SHA-256",
    )
    source_pins_sha256 = validate_expected_sha256(
        (
            official_source_pins_digest()
            if expected_source_pins_sha256 is None
            else expected_source_pins_sha256
        ),
        label="expected source-pins SHA-256",
    )
    identity = CaptureIdentity(
        runner_sha256=runner_sha256,
        source_pins_sha256=source_pins_sha256,
    )
    verify_capture_identity(identity)
    return identity


def capture_provenance(identity: CaptureIdentity | None = None) -> dict[str, Any]:
    if identity is None:
        identity = freeze_capture_identity()
    return {
        "authentication": "credential_free",
        "environment": "public_production_nonmutating_process",
        "grounding_level": "G3_AUTHORING_PUBLIC_PRODUCTION_POST_CAPTURE",
        "capture_lane": "authoring_only",
        "runtime_live_execution_eligible": False,
        "sandbox": False,
        "official_source_pins_sha256": identity.source_pins_sha256,
        "capture_runner_sha256": identity.runner_sha256,
    }


def decode_base64_bounded(value: Any, *, maximum_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or not value.isascii():
        raise ValueError(f"{label} is not an ASCII base64 string")
    if len(value) > base64_encoded_ceiling(maximum_bytes):
        raise ValueError(f"{label} exceeds its encoded-size cap")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError(f"{label} is not canonical base64") from error
    if len(decoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds its decoded-size cap")
    return decoded


def body_bytes(spec: dict[str, Any]) -> bytes:
    return decode_base64_bounded(
        spec["body_base64"],
        maximum_bytes=MAX_REQUEST_BODY_BYTES,
        label=f"request body for {spec.get('id', '<missing>')}",
    )


def validate_original_path(path: Any, *, case_id: str) -> str:
    path_segments = path.split("/") if isinstance(path, str) else []
    if (
        not isinstance(path, str)
        or not path.isascii()
        or ORIGIN_PATH_PATTERN.fullmatch(path) is None
        or "" in path_segments[1:]
        or any(segment in {".", ".."} for segment in path_segments)
        or any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in path
        )
    ):
        raise ValueError(f"{case_id} has a non-canonical origin-form path")
    return path


def request_headers(spec: dict[str, Any]) -> dict[str, str]:
    return {
        "accept": "application/json",
        "accept-encoding": "identity",
        "connection": "close",
        "content-length": str(len(body_bytes(spec))),
        "content-type": spec["content_type"],
        "host": HOST,
        "user-agent": USER_AGENT,
    }


def request_url(spec: dict[str, Any]) -> str:
    path = validate_original_path(spec.get("path"), case_id=str(spec.get("id", "<missing>")))
    query = urlencode(sorted(spec["query"].items()))
    return BASE + path + (f"?{query}" if query else "")


def canonical_request(spec: dict[str, Any]) -> dict[str, Any]:
    body = body_bytes(spec)
    return {
        "method": spec["method"],
        "url": request_url(spec),
        "path": spec["path"],
        "query": sorted((str(key), str(value)) for key, value in spec["query"].items()),
        "headers": request_headers(spec),
        "body_bytes": len(body),
        "body_sha256": digest(body),
    }


def request_fingerprint(spec: dict[str, Any]) -> str:
    encoded = json.dumps(
        canonical_request(spec),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return digest(encoded)


def enriched_case(spec: dict[str, Any]) -> dict[str, Any]:
    body = body_bytes(spec)
    return {
        **spec,
        "request_body_bytes": len(body),
        "request_body_sha256": digest(body),
        "request_fingerprint_sha256": request_fingerprint(spec),
    }


def validate_cases() -> None:
    ids = [spec["id"] for spec in CASES]
    if len(ids) != len(set(ids)):
        raise ValueError("PubChem POST probe case IDs must be unique")
    if len(CASES) != REVIEWED_CASE_COUNT:
        raise ValueError(
            f"reviewed PubChem POST probe must contain {REVIEWED_CASE_COUNT} cases, "
            f"got {len(CASES)}"
        )
    expected_case_keys = {
        "id",
        "method",
        "path",
        "query",
        "content_type",
        "body_base64",
        "eligibility",
    }
    expected_eligibility_keys = {
        "official_eligibility",
        "source_document",
        "source_section",
        "source_quote_category",
        "operation_source_document",
        "operation_source_section",
        "source_note",
    }
    for spec in CASES:
        if set(spec) != expected_case_keys:
            raise ValueError(f"{spec.get('id', '<missing>')} case fields drifted")
        if spec["method"] != METHOD:
            raise ValueError(f"{spec['id']} is not POST")
        validate_original_path(spec["path"], case_id=spec["id"])
        if not isinstance(spec["query"], dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in spec["query"].items()
        ):
            raise ValueError(f"{spec['id']} has an invalid query")
        if len(body_bytes(spec)) > MAX_REQUEST_BODY_BYTES:
            raise ValueError(f"{spec['id']} request body exceeds the reviewed cap")
        eligibility = spec["eligibility"]
        if not isinstance(eligibility, dict) or set(eligibility) != expected_eligibility_keys:
            raise ValueError(f"{spec['id']} eligibility provenance fields drifted")
        if eligibility["official_eligibility"] not in ELIGIBILITY_VALUES:
            raise ValueError(f"{spec['id']} has invalid official eligibility")
        if eligibility["official_eligibility"] != eligibility["source_quote_category"]:
            raise ValueError(f"{spec['id']} eligibility provenance diverged")
        if eligibility["source_document"] not in {
            PUG_REST_SPECIFICATION,
            PUG_REST_TUTORIAL,
        }:
            raise ValueError(f"{spec['id']} has an unpinned POST source")
        if eligibility["operation_source_document"] != PUG_REST_SPECIFICATION:
            raise ValueError(f"{spec['id']} has an unpinned operation source")
        if not eligibility["source_section"] or not eligibility["operation_source_section"]:
            raise ValueError(f"{spec['id']} has an empty official source anchor")
        if spec["id"].startswith("fast"):
            if spec["query"].get("MaxRecords") != "1":
                raise ValueError(f"{spec['id']} is missing MaxRecords=1")
            if spec["query"].get("MaxSeconds") != "5":
                raise ValueError(f"{spec['id']} is missing MaxSeconds=5")
    multipart = next(spec for spec in CASES if spec["id"] == "standardize_sdf_multipart_post")
    multipart_body = body_bytes(multipart)
    if b"\n" in multipart_body.replace(b"\r\n", b""):
        raise ValueError("multipart body contains a non-CRLF line ending")
    if b"V2000\r\n" not in multipart_body or b"M  END\r\n$$$$\r\n" not in multipart_body:
        raise ValueError("multipart SDF fixture is not the reviewed V2000 record")


def case_manifest() -> list[dict[str, Any]]:
    validate_cases()
    return [enriched_case(spec) for spec in CASES]


def manifest_digest() -> str:
    value = json.dumps(
        case_manifest(),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return digest(value)


def spec_payload() -> dict[str, Any]:
    cases = case_manifest()
    return {
        "schema_version": "datalox_pubchem_nonmutating_process_probe_spec_v4",
        "provider_id": "pubchem",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": METHOD,
        "execution_lane": "authoring_only_not_runtime_live",
        "wire_transport": "direct_verified_tls_http_1_1_connection_close",
        "response_format_evidence_scope": (
            "A JSON success proves only JSON eligibility for the exact request; "
            "it does not prove any other format."
        ),
        "minimum_interval_seconds_after_completion": MIN_INTERVAL_SECONDS,
        "maximum_request_body_bytes": MAX_REQUEST_BODY_BYTES,
        "maximum_response_header_bytes": MAX_RESPONSE_HEADER_BYTES,
        "maximum_response_body_bytes": MAX_RESPONSE_BODY_BYTES,
        "maximum_total_response_bytes": MAX_TOTAL_RESPONSE_BYTES,
        "official_source_pins_sha256": official_source_pins_digest(),
        "capture_runner_sha256": capture_runner_digest(),
        "retry_count": 0,
        "case_count": len(cases),
        "case_manifest_sha256": manifest_digest(),
        "scope_reconciliation": {
            "earlier_proposed_post_operation_count": 46,
            "excluded_deprecated_async_aliases": 5,
            "standardize_operation_branch_cases_added": 1,
            "listkey_post_creator_case_added": 1,
            "excluded_ungrounded_bounded_3d_similarity_case": 1,
            "reviewed_case_count": len(cases),
            "equation": (
                "46 - 5 deprecated aliases + 1 extra standardize branch "
                "+ 1 exact ListKey POST creator "
                "- 1 unbounded 3D similarity candidate = 42"
            ),
        },
        "cases": cases,
    }


def request_record_fields(spec: dict[str, Any]) -> dict[str, Any]:
    body = body_bytes(spec)
    return {
        "id": spec["id"],
        "method": METHOD,
        "path": spec["path"],
        "query": dict(spec["query"]),
        "request_headers": request_headers(spec),
        "request_body_base64": spec["body_base64"],
        "request_body_bytes": len(body),
        "request_body_sha256": digest(body),
        "request_fingerprint_sha256": request_fingerprint(spec),
        "eligibility": dict(spec["eligibility"]),
    }


def terminal_response_reason(status: int, headers: dict[str, str]) -> str | None:
    if status == 202:
        return "provider_async_accepted_unknown_completion"
    if status in {500, 503, 504}:
        return f"provider_status_{status}"
    if status not in OFFICIAL_STATUSES:
        return f"unexpected_status_{status}"
    if "retry-after" in headers:
        return "provider_retry_after"
    content_encoding = headers.get("content-encoding")
    if content_encoding is not None and content_encoding.strip().lower() != "identity":
        return "unexpected_content_encoding"
    value = headers.get("x-throttling-control")
    if value is None:
        return "missing_throttling_control"
    match = THROTTLE_PATTERN.fullmatch(value)
    if match is None:
        return "unparseable_throttling_control"
    if match["count"] != "Green":
        return f"request_count_{match['count'].lower()}"
    if match["time"] != "Green":
        return f"request_time_{match['time'].lower()}"
    if match["service"] != "Green":
        return f"service_{match['service'].lower()}"
    return None


def canonical_content_length(value: str | None) -> int | None:
    if value is None or CONTENT_LENGTH_PATTERN.fullmatch(value) is None:
        return None
    significant = value.lstrip("0") or "0"
    maximum = str(MAX_TOTAL_RESPONSE_BYTES)
    if len(significant) > len(maximum):
        return MAX_TOTAL_RESPONSE_BYTES + 1
    return int(significant)


class WireConnection(Protocol):
    def settimeout(self, value: float) -> None: ...

    def sendall(self, value: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


class AbsoluteDeadlineExceeded(TimeoutError):
    """The single capture deadline expired."""


class AbsoluteDeadline:
    def __init__(
        self,
        timeout_seconds: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
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
    expected_address_items = 2 if family == socket.AF_INET else 4
    if not isinstance(address, list) or len(address) != expected_address_items:
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


def resolve_in_subprocess(deadline: AbsoluteDeadline) -> tuple[Any, ...]:
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
        value = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise OSError("DNS resolver child returned invalid JSON") from error
    return validate_resolver_result(value)


def resolve_once(
    deadline: AbsoluteDeadline,
    *,
    resolver: Callable[..., list[tuple[Any, ...]]] | None = None,
) -> tuple[Any, ...]:
    if resolver is None:
        return resolve_in_subprocess(deadline)
    addresses = resolver(HOST, 443, type=socket.SOCK_STREAM)
    deadline.checkpoint()
    if not isinstance(addresses, list) or not addresses:
        raise OSError("DNS returned no addresses for the fixed PubChem host")
    return addresses[0]


def open_verified_tls_connection(
    deadline: AbsoluteDeadline,
    *,
    resolver: Callable[..., list[tuple[Any, ...]]] | None = None,
    socket_factory: Callable[..., WireConnection] = socket.socket,
    ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
) -> WireConnection:
    family, socket_type, protocol, _, address = resolve_once(
        deadline,
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
        if selected_alpn not in {None, "http/1.1"}:
            raise ValueError(f"TLS negotiated an unsupported protocol: {selected_alpn}")
        connection.settimeout(deadline.remaining())
        return connection
    except BaseException:
        raw_socket.close()
        raise


def set_deadline_timeout(
    connection: WireConnection,
    deadline: AbsoluteDeadline,
) -> None:
    connection.settimeout(deadline.remaining())


def send_with_deadline(
    connection: WireConnection,
    value: bytes,
    deadline: AbsoluteDeadline,
) -> None:
    set_deadline_timeout(connection, deadline)
    connection.sendall(value)
    deadline.checkpoint()


def recv_with_deadline(
    connection: WireConnection,
    size: int,
    deadline: AbsoluteDeadline,
) -> bytes:
    if not 0 < size <= MAX_WIRE_RECV_BYTES:
        raise ValueError("wire receive size escaped its bound")
    set_deadline_timeout(connection, deadline)
    value = connection.recv(size)
    deadline.checkpoint()
    if not isinstance(value, bytes):
        raise TypeError("wire transport returned a non-byte response")
    if len(value) > size:
        raise ValueError("wire transport returned more bytes than requested")
    return value


def request_bytes(spec: dict[str, Any]) -> bytes:
    parsed = urlparse(request_url(spec))
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    headers = request_headers(spec)
    if set(headers) != {
        "accept",
        "accept-encoding",
        "connection",
        "content-length",
        "content-type",
        "host",
        "user-agent",
    }:
        raise ValueError(f"request headers drifted for {spec['id']}")
    if "authorization" in headers or "cookie" in headers:
        raise ValueError(f"secret-bearing request observed for {spec['id']}")
    lines = [
        f"{METHOD} {target} HTTP/1.1",
        f"Host: {headers['host']}",
        f"Accept: {headers['accept']}",
        f"Accept-Encoding: {headers['accept-encoding']}",
        f"Connection: {headers['connection']}",
        f"Content-Length: {headers['content-length']}",
        f"Content-Type: {headers['content-type']}",
        f"User-Agent: {headers['user-agent']}",
    ]
    if any("\r" in line or "\n" in line for line in lines):
        raise ValueError(f"request header injection rejected for {spec['id']}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body_bytes(spec)


def read_wire_header(
    connection: WireConnection,
    deadline: AbsoluteDeadline,
) -> bytes:
    header = bytearray()
    terminator = b"\r\n\r\n"
    while not header.endswith(terminator):
        if len(header) >= MAX_RESPONSE_HEADER_BYTES:
            raise ResponseCaptureInterrupted(
                "response_header_limit_exceeded",
                f"maximum={MAX_RESPONSE_HEADER_BYTES}",
                None,
            )
        value = recv_with_deadline(connection, 1, deadline)
        if value == b"":
            raise ResponseCaptureInterrupted(
                "response_header_incomplete",
                f"captured={len(header)}",
                None,
            )
        header.extend(value)
    return bytes(header)


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
        name = raw_name.decode("ascii")
        fields.append((name, raw_value))
    return lines[0], status, fields, semantic_headers(fields)


def semantic_headers(fields: list[tuple[str, bytes]]) -> dict[str, str]:
    semantic: dict[str, list[str]] = {}
    for name, raw_value in fields:
        normalized = raw_value[1:] if raw_value.startswith(b" ") else raw_value
        try:
            text = normalized.decode("latin-1")
        except UnicodeDecodeError as error:
            raise ValueError("response header value cannot be preserved") from error
        semantic.setdefault(name.lower(), []).append(text)
    selected = {
        name: ", ".join(semantic[name]) for name in SAFE_RESPONSE_HEADERS if name in semantic
    }
    return selected


def serialized_header_fields(fields: list[tuple[str, bytes]]) -> list[dict[str, str]]:
    return [
        {
            "name": name,
            "value_base64": base64.b64encode(value).decode("ascii"),
        }
        for name, value in fields
    ]


def deserialize_header_fields(value: Any) -> list[tuple[str, bytes]]:
    if not isinstance(value, list):
        raise ValueError("response header fields are not a list")
    fields: list[tuple[str, bytes]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "value_base64"}:
            raise ValueError("response header field schema drifted")
        name = item["name"]
        if (
            not isinstance(name, str)
            or not name.isascii()
            or HEADER_NAME_PATTERN.fullmatch(name.encode("ascii")) is None
        ):
            raise ValueError("response header field name is invalid")
        encoded_value = item["value_base64"]
        raw_value = decode_base64_bounded(
            encoded_value,
            maximum_bytes=MAX_RESPONSE_HEADER_BYTES,
            label="response header field value",
        )
        if b"\r" in raw_value or b"\n" in raw_value:
            raise ValueError("response header field contains a line break")
        fields.append((name, raw_value))
    return fields


def exact_content_length(
    fields: list[tuple[str, bytes]],
) -> tuple[int | None, str]:
    raw_values = [value for name, value in fields if name.lower() == "content-length"]
    if len(raw_values) != 1:
        return None, f"field_count={len(raw_values)}"
    raw_value = raw_values[0]
    value = raw_value[1:] if raw_value.startswith(b" ") else raw_value
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError:
        return None, "value_is_not_ascii"
    parsed = canonical_content_length(decoded)
    if parsed is None:
        return None, f"value_sha256={digest(value)}, value_bytes={len(value)}"
    return parsed, f"value={decoded}"


def response_observation(
    *,
    url: str,
    final_url: str,
    status: int,
    headers: dict[str, str],
    header_fields: list[tuple[str, bytes]],
    status_line: bytes,
    raw: bytes,
    complete: bool,
) -> dict[str, Any]:
    return {
        "url": url,
        "final_url": final_url,
        "status": status,
        "response_headers": headers,
        "response_header_fields": serialized_header_fields(header_fields),
        "response_status_line_base64": base64.b64encode(status_line).decode("ascii"),
        "body_base64": base64.b64encode(raw).decode("ascii"),
        "body_bytes": len(raw),
        "body_sha256": digest(raw),
        "body_transfer": "raw_wire_bytes",
        "body_complete": complete,
        "captured_at": utc_now(),
    }


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
        identity = freeze_capture_identity()
    url = request_url(spec)
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != HOST
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"PubChem process probe escaped the allowlisted host: {url}")
    request_body = body_bytes(spec)
    if len(request_body) > MAX_REQUEST_BODY_BYTES:
        raise ValueError(f"request body exceeded cap for {spec['id']}")
    if not 0 < remaining_total_bytes <= MAX_TOTAL_RESPONSE_BYTES:
        raise ValueError("remaining total response budget must be positive and bounded")
    response_limit = min(MAX_RESPONSE_BODY_BYTES, remaining_total_bytes)
    deadline = AbsoluteDeadline(timeout_seconds, monotonic=monotonic)
    factory = connection_factory or open_verified_tls_connection
    connection = factory(deadline)
    pending: BaseException | None = None
    result: tuple[dict[str, Any], str | None] | None = None
    try:
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
        observation_fields = {
            "url": url,
            "final_url": url,
            "status": status,
            "headers": response_headers,
            "header_fields": header_fields,
            "status_line": status_line,
        }
        transfer_encodings = [
            value for name, value in header_fields if name.lower() == "transfer-encoding"
        ]
        if transfer_encodings:
            observation = response_observation(
                **observation_fields,
                raw=b"",
                complete=False,
            )
            raise ResponseCaptureInterrupted(
                "response_transfer_encoding_forbidden",
                f"field_count={len(transfer_encodings)}",
                observation,
            )
        declared_length, content_length_detail = exact_content_length(header_fields)
        if declared_length is None:
            observation = response_observation(
                **observation_fields,
                raw=b"",
                complete=False,
            )
            raise ResponseCaptureInterrupted(
                "response_length_missing_or_invalid_before_body",
                content_length_detail,
                observation,
            )
        if declared_length > response_limit:
            observation = response_observation(
                **observation_fields,
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
                remaining_declared = declared_length - len(raw_buffer)
                remaining_response = response_limit - len(raw_buffer)
                read_size = min(
                    MAX_WIRE_RECV_BYTES,
                    remaining_declared,
                    remaining_response,
                )
                chunk = recv_with_deadline(connection, read_size, deadline)
                if chunk == b"":
                    raise EOFError("response body ended before Content-Length")
                if len(chunk) > remaining_declared or len(chunk) > remaining_response:
                    raise ValueError("response chunk escaped declared or budget bound")
                raw_buffer.extend(chunk)
            trailing = recv_with_deadline(connection, 1, deadline)
            if trailing != b"":
                observation = response_observation(
                    **observation_fields,
                    raw=bytes(raw_buffer),
                    complete=False,
                )
                raise ResponseCaptureInterrupted(
                    "response_exceeds_declared_length",
                    (
                        f"declared={declared_length}, captured={len(raw_buffer)}, "
                        "rejected_trailing_bytes_at_least=1"
                    ),
                    observation,
                )
        except ResponseCaptureInterrupted:
            raise
        except BaseException as error:
            observation = response_observation(
                **observation_fields,
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
        raw = bytes(raw_buffer)
        observation = response_observation(
            **observation_fields,
            raw=raw,
            complete=True,
        )
        record = {
            **request_record_fields(spec),
            **observation,
            "provenance": capture_provenance(identity),
            "redaction": dict(REDACTION),
        }
        result = record, terminal_response_reason(status, response_headers)
    except BaseException as error:
        pending = error
    try:
        connection.close()
    except BaseException as close_error:
        pending_process_interrupt = isinstance(
            pending,
            (KeyboardInterrupt, SystemExit),
        ) or (
            isinstance(pending, ResponseCaptureInterrupted)
            and isinstance(pending.original, (KeyboardInterrupt, SystemExit))
        )
        if pending_process_interrupt:
            raise pending
        if pending is None and result is not None:
            complete_record = result[0]
            complete_observation = {key: complete_record[key] for key in RESPONSE_OBSERVATION_KEYS}
            raise ResponseCaptureInterrupted(
                "response_finalization_interrupted",
                type(close_error).__name__,
                complete_observation,
                original=close_error,
            ) from close_error
        if isinstance(close_error, (KeyboardInterrupt, SystemExit)):
            raise close_error
    if pending is not None:
        raise pending
    if result is None:
        raise RuntimeError("wire capture ended without a result")
    return result


def capture_payload(
    records: list[dict[str, Any]],
    *,
    in_flight: dict[str, Any] | None = None,
    halt: dict[str, str] | None = None,
    identity: CaptureIdentity | None = None,
) -> dict[str, Any]:
    if identity is None:
        identity = freeze_capture_identity()
    record_sizes = [record["body_bytes"] for record in records]
    partial_response_bytes = 0
    if in_flight is not None and in_flight["response_observation"] is not None:
        partial_response_bytes = in_flight["response_observation"]["body_bytes"]
    all_sizes = [*record_sizes, partial_response_bytes]
    if any(
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or size > MAX_RESPONSE_BODY_BYTES
        for size in all_sizes
    ):
        raise ValueError("capture payload contains an invalid response body size")
    total_response_bytes = sum(all_sizes)
    if total_response_bytes > MAX_TOTAL_RESPONSE_BYTES:
        raise ValueError("capture payload exceeds the total response budget")
    return {
        "schema_version": "datalox_pubchem_nonmutating_process_capture_v4",
        "provider_id": "pubchem",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "allowed_method": METHOD,
        "execution_lane": "authoring_only_not_runtime_live",
        "wire_transport": "direct_verified_tls_http_1_1_connection_close",
        "case_manifest_sha256": manifest_digest(),
        "official_source_pins_sha256": identity.source_pins_sha256,
        "capture_runner_sha256": identity.runner_sha256,
        "capture_count": len(records),
        "expected_capture_count": len(CASES),
        "complete": (len(records) == len(CASES) and in_flight is None and halt is None),
        "minimum_interval_seconds_after_completion": MIN_INTERVAL_SECONDS,
        "maximum_request_body_bytes": MAX_REQUEST_BODY_BYTES,
        "maximum_response_header_bytes": MAX_RESPONSE_HEADER_BYTES,
        "maximum_response_body_bytes": MAX_RESPONSE_BODY_BYTES,
        "maximum_total_response_bytes": MAX_TOTAL_RESPONSE_BYTES,
        "total_response_bytes": total_response_bytes,
        "retry_count": 0,
        "secret_headers_forwarded": False,
        "in_flight": in_flight,
        "halt": halt,
        "captures": records,
    }


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_fsynced(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key in capture journal: {key}")
        value[key] = item
    return value


def load_json_strict(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError("capture journal must be a regular file")
        if initial.st_size > MAX_JOURNAL_FILE_BYTES:
            raise ValueError("capture journal exceeds the bounded file-size cap")
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
    value = json.loads(encoded, object_pairs_hook=reject_duplicate_json_keys)
    if not isinstance(value, dict):
        raise ValueError("capture journal root must be an object")
    return value


def atomic_replace_payload(path: Path, value: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        write_fsynced(temporary, value)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()
            fsync_directory(path.parent)


def publish_exclusive(path: Path, value: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        write_fsynced(temporary, value)
        os.link(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()
            fsync_directory(path.parent)


def validate_timestamp(value: Any, *, label: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{label} timestamp is not a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} timestamp is invalid") from error
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{label} timestamp is not UTC")


def validate_halt(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != HALT_KEYS
        or not all(isinstance(item, str) and item for item in value.values())
    ):
        raise ValueError("partial capture halt envelope is invalid")
    return value


def precheck_encoded_field(value: Any, *, maximum_bytes: int, label: str) -> None:
    if not isinstance(value, str) or not value.isascii():
        raise ValueError(f"{label} is not an ASCII base64 string")
    if len(value) > base64_encoded_ceiling(maximum_bytes):
        raise ValueError(f"{label} exceeds its encoded-size cap")


def precheck_observation_encoded_fields(value: Any, *, label: str) -> None:
    if not isinstance(value, dict):
        return
    if "response_status_line_base64" in value:
        precheck_encoded_field(
            value["response_status_line_base64"],
            maximum_bytes=MAX_RESPONSE_HEADER_BYTES,
            label=f"{label} status line",
        )
    if "body_base64" in value:
        precheck_encoded_field(
            value["body_base64"],
            maximum_bytes=MAX_RESPONSE_BODY_BYTES,
            label=f"{label} body",
        )
    fields = value.get("response_header_fields")
    if isinstance(fields, list):
        for index, item in enumerate(fields):
            if isinstance(item, dict) and "value_base64" in item:
                precheck_encoded_field(
                    item["value_base64"],
                    maximum_bytes=MAX_RESPONSE_HEADER_BYTES,
                    label=f"{label} header field {index}",
                )


def precheck_saved_envelope_encoded_fields(saved: dict[str, Any]) -> None:
    captures = saved.get("captures")
    if isinstance(captures, list):
        for index, record in enumerate(captures):
            if not isinstance(record, dict):
                continue
            if "request_body_base64" in record:
                precheck_encoded_field(
                    record["request_body_base64"],
                    maximum_bytes=MAX_REQUEST_BODY_BYTES,
                    label=f"capture {index} request body",
                )
            precheck_observation_encoded_fields(record, label=f"capture {index} response")
    in_flight = saved.get("in_flight")
    if isinstance(in_flight, dict):
        request = in_flight.get("request")
        if isinstance(request, dict) and "request_body_base64" in request:
            precheck_encoded_field(
                request["request_body_base64"],
                maximum_bytes=MAX_REQUEST_BODY_BYTES,
                label="in-flight request body",
            )
        precheck_observation_encoded_fields(
            in_flight.get("response_observation"),
            label="in-flight response",
        )


def validate_response_observation(
    observation: Any,
    *,
    spec: dict[str, Any],
    complete: bool,
) -> None:
    if not isinstance(observation, dict) or set(observation) != RESPONSE_OBSERVATION_KEYS:
        raise ValueError(f"response observation fields drifted for {spec['id']}")
    expected_url = request_url(spec)
    if observation["url"] != expected_url or observation["final_url"] != expected_url:
        raise ValueError(f"response URL drifted for {spec['id']}")
    status = observation["status"]
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise ValueError(f"response status invalid for {spec['id']}")
    headers = observation["response_headers"]
    if (
        not isinstance(headers, dict)
        or not set(headers).issubset(SAFE_RESPONSE_HEADERS)
        or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in headers.items()
        )
    ):
        raise ValueError(f"response headers invalid for {spec['id']}")
    header_fields = deserialize_header_fields(observation["response_header_fields"])
    if headers != semantic_headers(header_fields):
        raise ValueError(f"response semantic headers drifted for {spec['id']}")
    status_line = decode_base64_bounded(
        observation["response_status_line_base64"],
        maximum_bytes=MAX_RESPONSE_HEADER_BYTES,
        label=f"response status line for {spec['id']}",
    )
    status_match = STATUS_LINE_PATTERN.fullmatch(status_line)
    if status_match is None or int(status_match.group(1)) != status:
        raise ValueError(f"response status line drifted for {spec['id']}")
    reconstructed_header_bytes = (
        len(status_line)
        + 2
        + sum(len(name.encode("ascii")) + 1 + len(value) + 2 for name, value in header_fields)
        + 2
    )
    if reconstructed_header_bytes > MAX_RESPONSE_HEADER_BYTES:
        raise ValueError(f"response header cap invalid for {spec['id']}")
    raw = decode_base64_bounded(
        observation["body_base64"],
        maximum_bytes=MAX_RESPONSE_BODY_BYTES,
        label=f"response body for {spec['id']}",
    )
    body_size = observation["body_bytes"]
    if (
        not isinstance(body_size, int)
        or isinstance(body_size, bool)
        or body_size < 0
        or body_size > MAX_RESPONSE_BODY_BYTES
        or len(raw) != body_size
        or digest(raw) != observation["body_sha256"]
    ):
        raise ValueError(f"response body digest or cap invalid for {spec['id']}")
    if observation["body_transfer"] != "raw_wire_bytes":
        raise ValueError(f"response transfer contract invalid for {spec['id']}")
    if observation["body_complete"] is not complete:
        raise ValueError(f"response completeness marker invalid for {spec['id']}")
    validate_timestamp(observation["captured_at"], label=f"response {spec['id']}")
    if complete:
        if any(name.lower() == "transfer-encoding" for name, _ in header_fields):
            raise ValueError(f"completed response retained Transfer-Encoding for {spec['id']}")
        declared, _ = exact_content_length(header_fields)
        if declared is None:
            raise ValueError(f"response content-length invalid for {spec['id']}")
        if declared != body_size:
            raise ValueError(f"response content-length mismatch for {spec['id']}")


def validate_saved_records(
    records: list[dict[str, Any]],
    *,
    identity: CaptureIdentity,
) -> list[str | None]:
    if len(records) > len(CASES):
        raise ValueError("partial capture has too many records")
    terminal_reasons: list[str | None] = []
    for record, spec in zip(records, CASES[: len(records)], strict=True):
        validate_completed_record(record, spec=spec, identity=identity)
        terminal_reasons.append(
            terminal_response_reason(record["status"], record["response_headers"])
        )
    if sum(record["body_bytes"] for record in records) > MAX_TOTAL_RESPONSE_BYTES:
        raise ValueError("partial capture exceeds total response budget")
    return terminal_reasons


def validate_completed_record(
    record: Any,
    *,
    spec: dict[str, Any],
    identity: CaptureIdentity | None = None,
) -> None:
    if identity is None:
        identity = freeze_capture_identity()
    if not isinstance(record, dict):
        raise ValueError(f"partial capture record is invalid for {spec['id']}")
    expected_keys = REQUEST_RECORD_KEYS | RESPONSE_OBSERVATION_KEYS | {"provenance", "redaction"}
    if set(record) != expected_keys:
        raise ValueError(f"partial capture record fields drifted for {spec['id']}")
    expected_request = request_record_fields(spec)
    actual_request = {key: record[key] for key in REQUEST_RECORD_KEYS}
    if actual_request != expected_request:
        raise ValueError(f"partial capture request fields drifted for {spec['id']}")
    observation = {key: record[key] for key in RESPONSE_OBSERVATION_KEYS}
    validate_response_observation(observation, spec=spec, complete=True)
    if record["provenance"] != capture_provenance(identity):
        raise ValueError(f"partial provenance invalid for {spec['id']}")
    if record["redaction"] != REDACTION:
        raise ValueError(f"partial redaction marker invalid for {spec['id']}")


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


def validate_in_flight(
    value: Any,
    *,
    next_spec: dict[str, Any],
) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "state",
        "prepared_at",
        "request",
        "url",
        "response_observation",
    }:
        raise ValueError("partial in-flight fields drifted")
    if value["state"] != "completion_unknown_do_not_retry":
        raise ValueError("partial in-flight state is invalid")
    validate_timestamp(value["prepared_at"], label="in-flight")
    if value["request"] != request_record_fields(next_spec):
        raise ValueError("partial in-flight request drifted")
    if value["url"] != request_url(next_spec):
        raise ValueError("partial in-flight URL drifted")
    observation = value["response_observation"]
    if observation is not None:
        if not isinstance(observation, dict) or not isinstance(
            observation.get("body_complete"), bool
        ):
            raise ValueError("partial in-flight response completeness is invalid")
        validate_response_observation(
            observation,
            spec=next_spec,
            complete=observation["body_complete"],
        )
    return value


def expected_completed_halt(
    records: list[dict[str, Any]],
    terminal_reasons: list[str | None],
) -> dict[str, str] | None:
    terminal_indexes = [
        index for index, reason in enumerate(terminal_reasons) if reason is not None
    ]
    if not terminal_indexes:
        return None
    if terminal_indexes != [len(records) - 1]:
        raise ValueError("capture continued after a terminal provider response")
    index = terminal_indexes[0]
    return {
        "case_id": records[index]["id"],
        "code": "provider_terminal_signal",
        "detail": str(terminal_reasons[index]),
    }


def validate_saved_envelope(
    saved: dict[str, Any],
    *,
    identity: CaptureIdentity | None = None,
) -> list[dict[str, Any]]:
    if identity is None:
        identity = freeze_capture_identity()
    else:
        verify_capture_identity(identity)
    if not isinstance(saved, dict):
        raise ValueError("partial capture envelope is not an object")
    precheck_saved_envelope_encoded_fields(saved)
    expected_envelope_keys = set(capture_payload([], identity=identity))
    if set(saved) != expected_envelope_keys:
        raise ValueError("partial capture envelope keys drifted")
    if not isinstance(saved["captures"], list):
        raise ValueError("partial capture records are missing")
    records: list[dict[str, Any]] = saved["captures"]
    terminal_reasons = validate_saved_records(records, identity=identity)
    if len(records) >= len(CASES):
        next_spec = None
        if saved["in_flight"] is not None:
            raise ValueError("complete case sequence cannot have an in-flight request")
    else:
        next_spec = CASES[len(records)]
    in_flight = (
        validate_in_flight(saved["in_flight"], next_spec=next_spec)
        if next_spec is not None
        else None
    )
    halt = validate_halt(saved["halt"])
    completed_halt = expected_completed_halt(records, terminal_reasons)
    if in_flight is None:
        if halt != completed_halt:
            if not (
                halt is not None
                and halt["code"] == "batch_response_budget_exhausted_before_dispatch"
                and next_spec is not None
                and halt["case_id"] == next_spec["id"]
                and sum(record["body_bytes"] for record in records) == MAX_TOTAL_RESPONSE_BYTES
            ):
                raise ValueError("partial terminal halt does not match provider response")
    else:
        if halt is not None and halt["case_id"] != next_spec["id"]:
            raise ValueError("in-flight halt case does not match request")
        if completed_halt is not None:
            raise ValueError("an in-flight request followed a terminal response")
        allowed_without_response = {
            "request_error_unknown_completion",
            "process_interrupted_unknown_completion",
            "post_dispatch_exception_unknown_completion",
            "response_header_incomplete",
            "response_header_invalid",
            "response_header_limit_exceeded",
        }
        allowed_with_response = {
            "completion_journal_failure_unknown_completion",
            "response_budget_exceeded_before_body",
            "response_eof_unproven",
            "response_exceeds_declared_length",
            "response_finalization_interrupted",
            "response_length_missing_or_invalid_before_body",
            "response_stream_interrupted",
            "response_transfer_encoding_forbidden",
        }
        observation = in_flight["response_observation"]
        if halt is None:
            if observation is not None:
                raise ValueError("unclassified in-flight response observation")
        elif observation is None:
            if halt["code"] not in allowed_without_response:
                raise ValueError("in-flight halt code does not match absent response")
        elif halt["code"] not in allowed_with_response:
            raise ValueError("in-flight halt code does not match response observation")
        observation_fields = (
            deserialize_header_fields(observation["response_header_fields"])
            if observation is not None
            else []
        )
        if halt is not None and halt["code"] == "response_budget_exceeded_before_body":
            declared_length, _ = exact_content_length(observation_fields)
            if declared_length is None:
                raise ValueError("response-budget halt lacks a valid content-length")
            remaining = MAX_TOTAL_RESPONSE_BYTES - sum(record["body_bytes"] for record in records)
            if observation["body_bytes"] != 0 or declared_length <= min(
                MAX_RESPONSE_BODY_BYTES, remaining
            ):
                raise ValueError("response-budget halt is not reproducible")
        if halt is not None and halt["code"] == "response_length_missing_or_invalid_before_body":
            valid_length, _ = exact_content_length(observation_fields)
            if observation["body_bytes"] != 0 or valid_length is not None:
                raise ValueError("response-length halt is not reproducible")
        if halt is not None and halt["code"] == "response_exceeds_declared_length":
            declared_length, _ = exact_content_length(observation_fields)
            if (
                declared_length is None
                or observation["body_bytes"] > declared_length
                or observation["body_bytes"] > MAX_RESPONSE_BODY_BYTES
            ):
                raise ValueError("response-overrun halt is not bounded by its declaration")
        if halt is not None and halt["code"] == "response_stream_interrupted":
            declared_length, _ = exact_content_length(observation_fields)
            if declared_length is None or observation["body_bytes"] >= declared_length:
                raise ValueError("response-stream halt is not reproducible")
        if halt is not None and halt["code"] == "response_eof_unproven":
            declared_length, _ = exact_content_length(observation_fields)
            if declared_length is None or observation["body_bytes"] != declared_length:
                raise ValueError("response-EOF halt is not reproducible")
        if halt is not None and halt["code"] == "response_transfer_encoding_forbidden":
            if not any(name.lower() == "transfer-encoding" for name, _ in observation_fields):
                raise ValueError("transfer-encoding halt lacks the original field")
        if halt is not None and halt["code"] == "completion_journal_failure_unknown_completion":
            if observation["body_complete"] is not True:
                raise ValueError("completion-journal halt lacks a complete response")
        elif halt is not None and halt["code"] == "response_finalization_interrupted":
            if observation["body_complete"] is not True:
                raise ValueError("response-finalization halt lacks a complete response")
        elif (
            halt is not None
            and observation is not None
            and observation["body_complete"] is not False
        ):
            raise ValueError("interrupted response was incorrectly marked complete")
    expected = capture_payload(
        records,
        in_flight=in_flight,
        halt=halt,
        identity=identity,
    )
    for key, expected_value in expected.items():
        if saved[key] != expected_value:
            raise ValueError(f"partial capture envelope field drifted: {key}")
    if saved["total_response_bytes"] > MAX_TOTAL_RESPONSE_BYTES:
        raise ValueError("partial capture exceeds total response budget")
    return records


def exception_halt(
    spec: dict[str, Any],
    error: BaseException,
    *,
    complete_observation: dict[str, Any] | None = None,
) -> tuple[dict[str, str], dict[str, Any] | None, BaseException | None]:
    if isinstance(error, ResponseCaptureInterrupted):
        original = error.original
        return (
            {
                "case_id": spec["id"],
                "code": error.code,
                "detail": error.detail,
            },
            error.observation,
            original,
        )
    if complete_observation is not None:
        return (
            {
                "case_id": spec["id"],
                "code": "completion_journal_failure_unknown_completion",
                "detail": type(error).__name__,
            },
            complete_observation,
            error,
        )
    if isinstance(error, (OSError, TimeoutError, ssl.SSLError)):
        code = "request_error_unknown_completion"
    elif isinstance(error, (KeyboardInterrupt, SystemExit)):
        code = "process_interrupted_unknown_completion"
    else:
        code = "post_dispatch_exception_unknown_completion"
    return (
        {
            "case_id": spec["id"],
            "code": code,
            "detail": type(error).__name__,
        },
        None,
        error,
    )


CaptureFunction = Callable[
    ...,
    tuple[dict[str, Any], str | None],
]


def run_capture(
    *,
    timeout_seconds: float,
    resume: bool,
    capture_function: CaptureFunction = capture,
    expected_runner_sha256: str | None = None,
    expected_source_pins_sha256: str | None = None,
) -> None:
    identity = freeze_capture_identity(
        expected_runner_sha256=expected_runner_sha256,
        expected_source_pins_sha256=expected_source_pins_sha256,
    )
    validate_cases()
    if not 0 < timeout_seconds <= DEFAULT_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be greater than zero and at most {DEFAULT_TIMEOUT_SECONDS}")

    def bound_payload(
        payload_records: list[dict[str, Any]],
        *,
        in_flight: dict[str, Any] | None = None,
        halt: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        verify_capture_identity(identity)
        value = capture_payload(
            payload_records,
            in_flight=in_flight,
            halt=halt,
            identity=identity,
        )
        if (
            value["official_source_pins_sha256"] != identity.source_pins_sha256
            or value["capture_runner_sha256"] != identity.runner_sha256
        ):
            raise ValueError("capture provenance bindings drifted")
        return value

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    lock = OUTPUT.with_suffix(OUTPUT.suffix + ".lock")
    partial = OUTPUT.with_suffix(OUTPUT.suffix + ".partial")
    lock_descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(lock_descriptor)
    fsync_directory(OUTPUT.parent)
    try:
        if resume and not partial.exists():
            raise FileNotFoundError("refusing resume without a partial capture journal")
        if OUTPUT.exists() or (partial.exists() and not resume):
            raise FileExistsError(f"refusing overwrite or unrequested resume: {OUTPUT}")
        if partial.exists():
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
            consumed = sum(item["body_bytes"] for item in records)
            remaining_total_bytes = MAX_TOTAL_RESPONSE_BYTES - consumed
            if remaining_total_bytes <= 0:
                halt = {
                    "case_id": spec["id"],
                    "code": "batch_response_budget_exhausted_before_dispatch",
                    "detail": str(consumed),
                }
                atomic_replace_payload(partial, bound_payload(records, halt=halt))
                raise CaptureHalt("total response budget exhausted before dispatch")
            prepared_at = utc_now()
            in_flight = in_flight_record(spec, prepared_at=prepared_at)
            atomic_replace_payload(
                partial,
                bound_payload(records, in_flight=in_flight),
            )
            print(f"capturing {spec['id']}", flush=True)
            durable_completion = False
            complete_observation: dict[str, Any] | None = None
            try:
                record, halt_reason = capture_function(
                    spec,
                    timeout_seconds=timeout_seconds,
                    remaining_total_bytes=remaining_total_bytes,
                    identity=identity,
                )
                verify_capture_identity(identity)
                validate_completed_record(record, spec=spec, identity=identity)
                complete_observation = {key: record[key] for key in RESPONSE_OBSERVATION_KEYS}
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
                )
                durable_completion = True
            except BaseException as error:
                if durable_completion:
                    raise
                halt, observation, original = exception_halt(
                    spec,
                    error,
                    complete_observation=complete_observation,
                )
                if observation is not None:
                    try:
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
                        if not isinstance(original, (KeyboardInterrupt, SystemExit)):
                            original = error
                terminal_in_flight = in_flight_record(
                    spec,
                    prepared_at=prepared_at,
                    response=observation,
                )
                try:
                    atomic_replace_payload(
                        partial,
                        bound_payload(
                            records,
                            in_flight=terminal_in_flight,
                            halt=halt,
                        ),
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
        publish_exclusive(OUTPUT, final_payload)
        partial.unlink()
        fsync_directory(OUTPUT.parent)
    finally:
        if lock.exists():
            lock.unlink()
            fsync_directory(OUTPUT.parent)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Print or execute the reviewed authoring-only, credential-free "
            "PubChem non-mutating POST eligibility probe."
        )
    )
    parser.add_argument("--print-spec", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--expected-runner-sha256")
    parser.add_argument("--expected-source-pins-sha256")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    args = parser.parse_args()
    if args.print_spec:
        print(json.dumps(spec_payload(), indent=2, sort_keys=True))
        return 0
    if not args.write:
        parser.error("capture is explicit: pass --write or inspect --print-spec")
    if args.expected_runner_sha256 is None or args.expected_source_pins_sha256 is None:
        parser.error(
            "--write requires --expected-runner-sha256 and "
            "--expected-source-pins-sha256 from external review"
        )
    run_capture(
        timeout_seconds=args.timeout,
        resume=args.resume,
        expected_runner_sha256=args.expected_runner_sha256,
        expected_source_pins_sha256=args.expected_source_pins_sha256,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
