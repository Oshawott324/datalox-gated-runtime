#!/usr/bin/env python3
"""Check the local UniProt async lifecycle against retained sanitized facts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from copy import deepcopy
from datetime import UTC
from email.parser import BytesParser
from email.policy import default
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import ProviderRuntime

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENV = ROOT / "envs" / "uniprot_idmapping_v0"
AUTHORITY = "rest.uniprot.org"

_RESTRICTED_CAPTURE_DATE = "2026-09-02"
_RESTRICTED_RECEIPT_DIRS = {
    "async-live",
    "invalid-duplicate-live",
    "preterminal",
    "status-404",
    "uniref-result-404",
}
_LEGACY_RECEIPT_FILES: dict[str, dict[str, tuple[int, str]]] = {
    "async-live": {
        "details.body": (
            3636,
            "sha256:db6694ad4042e9e38a90fc4845f638ce4fd69dbfb50e0fe56398e4d8410939fb",
        ),
        "details.headers": (
            802,
            "sha256:1cb468aac20a3e749b06544918e1ae1a9edda4d5a46e3f80bcdb40b4338900af",
        ),
        "duplicate.body": (
            22,
            "sha256:b54f47bf70e8dcc241e7ec45aad2e18fbd2a5fceab48a0bd077f3f96cf90a7c9",
        ),
        "duplicate.headers": (
            808,
            "sha256:7065ea113bb43e44d62d9460a5541814c9430032da2a6cadec25ba12799a595d",
        ),
        "ids.txt": (
            3508,
            "sha256:c900711cf6571ea3415562c7ad52c0aa06302ad5bb5a16b8052b7b7a82d69e86",
        ),
        "results.body": (
            939,
            "sha256:1779c703f6ff02f2f8c4e8b48d602d1b482e85c3af27487fa455f79cd75c1edc",
        ),
        "results.headers": (
            942,
            "sha256:03b1180b7b66f58cdc69730532af2d7d3b519a54c817dc8c4fb0760e5538badc",
        ),
        "request-identity.posthoc.json": (
            1288,
            "sha256:d4cf78b61ae013113f64d0ec63dac29a955d6ee4855e0a6d399442654f109009",
        ),
        "status-1.body": (
            23,
            "sha256:6d3d7aaf99fefa25e66df3d0004beb709cfc7a53c4fd922a1e2455f3ae51c479",
        ),
        "status-1.headers": (
            802,
            "sha256:38850077f4f806f30f5d490396f0682f18fa68173fcb862dd2ab3119e75e6548",
        ),
        "status-2.body": (
            23,
            "sha256:6d3d7aaf99fefa25e66df3d0004beb709cfc7a53c4fd922a1e2455f3ae51c479",
        ),
        "status-2.headers": (
            802,
            "sha256:1e37ae2afef9b03452e1e5761e0826599f4bb5055e72e1d1aa60e140e29e031a",
        ),
        "status-3.body": (
            23,
            "sha256:6d3d7aaf99fefa25e66df3d0004beb709cfc7a53c4fd922a1e2455f3ae51c479",
        ),
        "status-3.headers": (
            802,
            "sha256:1e37ae2afef9b03452e1e5761e0826599f4bb5055e72e1d1aa60e140e29e031a",
        ),
        "status-4.body": (
            23,
            "sha256:6d3d7aaf99fefa25e66df3d0004beb709cfc7a53c4fd922a1e2455f3ae51c479",
        ),
        "status-4.headers": (
            802,
            "sha256:18ade7ab0b114e03b1c591059750a298657719dc0932b576e1b1e4d5ea5ffbca",
        ),
        "status-5.body": (
            24,
            "sha256:796866f6f44dfffce3ed9c3e9e686ffd5958c2709738bcff9822f18f170a8078",
        ),
        "status-5.headers": (
            880,
            "sha256:03866d5c24971b66e57efed6c0f89b1573bfaaf2bbaaace9e32c4b4a51fa4c13",
        ),
        "submit.body": (
            22,
            "sha256:b54f47bf70e8dcc241e7ec45aad2e18fbd2a5fceab48a0bd077f3f96cf90a7c9",
        ),
        "submit.headers": (
            808,
            "sha256:c687ec03f3cf44af04f44bb8c5d1795b538186036b6988dfe24c586792dd38fc",
        ),
    },
    "invalid-duplicate-live": {
        "duplicate.body": (
            22,
            "sha256:56aa54d7e5cb580bb6ccbe9f2f7ef2320664fd2dc4f90f33683c1a0239c47d5b",
        ),
        "duplicate.headers": (
            808,
            "sha256:68f7fa79e4c372eb4e10f69ba997b4ea9815c6433da63eaa482ef21a4e57d406",
        ),
        "invalid.body": (
            191,
            "sha256:e09add968fc5341eac8d0eebeea08ddd7588fd5313d0db3e69ef756765f0b4ba",
        ),
        "invalid.headers": (
            808,
            "sha256:38f95ef25c10b5c88789160b359f77ec1926b4b38c08e70eaa708f8e3577e684",
        ),
        "status-1.body": (
            24,
            "sha256:796866f6f44dfffce3ed9c3e9e686ffd5958c2709738bcff9822f18f170a8078",
        ),
        "status-1.headers": (
            873,
            "sha256:920407209c243c179718280b304e0e26164a097a9b48d8c791f6218ed03ca6da",
        ),
        "status-2.body": (
            24,
            "sha256:796866f6f44dfffce3ed9c3e9e686ffd5958c2709738bcff9822f18f170a8078",
        ),
        "status-2.headers": (
            873,
            "sha256:a4f0105dc480ea5720b83a8d930026fd3d9092a7580e757e9ec3b4444482e074",
        ),
        "status-3.body": (
            24,
            "sha256:796866f6f44dfffce3ed9c3e9e686ffd5958c2709738bcff9822f18f170a8078",
        ),
        "status-3.headers": (
            873,
            "sha256:a4f0105dc480ea5720b83a8d930026fd3d9092a7580e757e9ec3b4444482e074",
        ),
        "submit.body": (
            22,
            "sha256:56aa54d7e5cb580bb6ccbe9f2f7ef2320664fd2dc4f90f33683c1a0239c47d5b",
        ),
        "submit.headers": (
            808,
            "sha256:dfcfaf9690582eb8650b3b6ef258617eda08abeb2bb598271d80d614baa28844",
        ),
    },
    "preterminal": {
        "pre-results.body": (
            104,
            "sha256:b9b3d449e881ad0214f6e5142e7d1b00f34f1011a6e805207420f6effcf30421",
        ),
        "pre-results.headers": (
            802,
            "sha256:3264d2f41c81f90b9d0d7e83375468c538675410b8ccfab1a32548f10e22e83a",
        ),
        "status-1.body": (
            23,
            "sha256:6d3d7aaf99fefa25e66df3d0004beb709cfc7a53c4fd922a1e2455f3ae51c479",
        ),
        "status-1.headers": (
            802,
            "sha256:dc2abdd3f11579a0621073f6fc20d227783c7520e978ec8bef216be97f5df742",
        ),
        "status-2.body": (
            23,
            "sha256:6d3d7aaf99fefa25e66df3d0004beb709cfc7a53c4fd922a1e2455f3ae51c479",
        ),
        "status-2.headers": (
            802,
            "sha256:c14598ddfe210fdd8e5724842a300d6c887daddf96d952f8b445783d683b5655",
        ),
        "status-3.body": (
            23,
            "sha256:6d3d7aaf99fefa25e66df3d0004beb709cfc7a53c4fd922a1e2455f3ae51c479",
        ),
        "status-3.headers": (
            802,
            "sha256:6994608102154eec5a472b04f9dbbfa65459a35adb0c7becf151165061259a96",
        ),
        "status-4.body": (
            24,
            "sha256:796866f6f44dfffce3ed9c3e9e686ffd5958c2709738bcff9822f18f170a8078",
        ),
        "status-4.headers": (
            881,
            "sha256:b957ff5513cdcd7bde7a2a162aeaa9d8338ad6b18e9e0d12b23c902db12e55a8",
        ),
        "submit.body": (
            22,
            "sha256:b86c5673380c65dec4ce49ab997a7cd78ce3f217da6c025446da6120ff995c96",
        ),
        "submit.headers": (
            808,
            "sha256:6bd97f577f979a316d1f0adf506629ad431419545a5cf33972e50b635a0d42a6",
        ),
    },
}
_HTTP_STATUS = re.compile(rb"^HTTP/\S+\s+(\d{3})(?:\s|$)")
_SYNTHETIC_UNKNOWN_STATUS_PATH = "/idmapping/status/datalox-nonexistent-20260902"
_SYNTHETIC_UNKNOWN_UNIREF_RESULT_PATH = (
    "/idmapping/uniref/results/datalox-nonexistent-uniref-20260902"
)
_UNIREF_RESULT_PATH_TEMPLATE = "/idmapping/uniref/results/{unknown_job_id}"
_UNIREF_RESULT_QUERY = {"format": "json", "size": "1"}


def _digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _file_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AssertionError("private receipt JSON contains a duplicate object key")
        value[key] = item
    return value


def _strict_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise AssertionError("private receipt JSON is not a regular file")
    try:
        text = path.read_bytes().decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as error:
        raise AssertionError("private receipt JSON is not UTF-8") from error
    except json.JSONDecodeError as error:
        raise AssertionError("private receipt JSON is invalid") from error


def _single_header(message: Any, name: str, *, required: bool = True) -> str | None:
    values = message.get_all(name, [])
    if not values:
        if required:
            raise AssertionError("private receipt is missing a required response header")
        return None
    if len(values) != 1:
        raise AssertionError("private receipt repeats a protected response header")
    return str(values[0]).strip()


def _parse_headers(path: Path) -> tuple[int | None, Any]:
    if not path.is_file() or path.is_symlink():
        raise AssertionError("private receipt headers are not a regular file")
    raw = path.read_bytes()
    first, separator, remainder = raw.partition(b"\n")
    status_match = _HTTP_STATUS.match(first.rstrip(b"\r"))
    status = int(status_match.group(1)) if status_match else None
    header_bytes = remainder if status_match and separator else raw
    try:
        message = BytesParser(policy=default).parsebytes(header_bytes, headersonly=True)
    except Exception as error:
        raise AssertionError("private receipt headers are invalid") from error
    if message.defects:
        raise AssertionError("private receipt headers contain parser defects")
    for name in ("Date", "Content-Type", "X-UniProt-Release", "X-API-Deployment-Date"):
        _single_header(message, name)
    return status, message


def _observed_at(message: Any) -> str:
    raw = _single_header(message, "Date")
    assert raw is not None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError) as error:
        raise AssertionError("private receipt Date header is invalid") from error
    if parsed.tzinfo is None:
        raise AssertionError("private receipt Date header has no timezone")
    return parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalized_http_date(value: str) -> str:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError) as error:
        raise AssertionError("private receipt manifest Date is invalid") from error
    if parsed.tzinfo is None:
        raise AssertionError("private receipt manifest Date has no timezone")
    return parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _content_type(message: Any) -> str:
    raw = _single_header(message, "Content-Type")
    assert raw is not None
    return raw.split(";", 1)[0].strip().lower()


def _assert_header_release(message: Any) -> tuple[str, str]:
    release = _single_header(message, "X-UniProt-Release")
    deployment = _single_header(message, "X-API-Deployment-Date")
    assert release is not None and deployment is not None
    if release != "2026_03" or deployment != "02-September-2026":
        raise AssertionError("private receipt provider release headers changed")
    if _content_type(message) != "application/json":
        raise AssertionError("private receipt content type changed")
    return release, deployment


def _assert_location(
    message: Any,
    *,
    expected_path_prefix: str,
    expected_job_id: str,
) -> None:
    location = _single_header(message, "Location")
    assert location is not None
    parsed = urlsplit(location)
    if parsed.scheme not in {"", "https"} or parsed.netloc not in {"", AUTHORITY}:
        raise AssertionError("private receipt Location authority changed")
    if parsed.query or parsed.fragment:
        raise AssertionError("private receipt Location unexpectedly contains query or fragment")
    if parsed.path != f"{expected_path_prefix}{expected_job_id}":
        raise AssertionError("private receipt Location no longer binds the submitted job")


def _manifest_digest(files: dict[str, tuple[int, str]]) -> str:
    return _digest(
        {name: {"sha256": digest, "size": size} for name, (size, digest) in sorted(files.items())}
    )


def _verify_exact_legacy_files(receipt_dir: Path, receipt_id: str) -> dict[str, Any]:
    expected = _LEGACY_RECEIPT_FILES[receipt_id]
    if not receipt_dir.is_dir() or receipt_dir.is_symlink():
        raise AssertionError("legacy private receipt directory is missing or unsafe")
    actual_names = {path.name for path in receipt_dir.iterdir()}
    if actual_names != set(expected):
        raise AssertionError("legacy private receipt inventory changed")
    for name, (expected_size, expected_sha256) in expected.items():
        path = receipt_dir / name
        if not path.is_file() or path.is_symlink():
            raise AssertionError("legacy private receipt contains a non-regular file")
        if path.stat().st_size != expected_size or _file_digest(path) != expected_sha256:
            raise AssertionError("legacy private receipt content changed")
    return {
        "file_count": len(expected),
        "content_manifest_sha256": _manifest_digest(expected),
    }


def _assert_legacy_content_binding(
    lifecycle: dict[str, Any], receipt_id: str, content_manifest_sha256: str
) -> None:
    receipts = lifecycle.get("private_source_receipts")
    if not isinstance(receipts, list):
        raise TypeError("sanitized lifecycle is missing private receipt bindings")
    matches = [
        item for item in receipts if isinstance(item, dict) and item.get("receipt_id") == receipt_id
    ]
    if len(matches) != 1 or matches[0].get("content_manifest_sha256") != content_manifest_sha256:
        raise AssertionError("sanitized lifecycle does not bind the exact legacy content set")


def _json_object(path: Path) -> dict[str, Any]:
    value = _strict_json(path)
    if not isinstance(value, dict):
        raise TypeError("private receipt JSON body is not an object")
    return value


def _job_id(path: Path) -> str:
    value = _json_object(path)
    if set(value) != {"jobId"} or not isinstance(value["jobId"], str) or not value["jobId"]:
        raise AssertionError("private receipt submit body has an invalid job identifier shape")
    return value["jobId"]


def _assert_status_body(path: Path, expected: str) -> None:
    if _json_object(path) != {"jobStatus": expected}:
        raise AssertionError("private receipt job status body changed")


def _verify_posthoc_request_identity(
    receipt_dir: Path,
    lifecycle: dict[str, Any],
) -> dict[str, Any]:
    manifest_path = receipt_dir / "request-identity.posthoc.json"
    manifest = _strict_json(manifest_path)
    if not isinstance(manifest, dict):
        raise TypeError("post-hoc request identity manifest is not an object")
    expected = {
        "schema_version": "datalox_private_posthoc_request_identity_v1",
        "receipt_id": "async_live",
        "authority": AUTHORITY,
        "signed_contemporaneous_receipt": False,
        "construction": "post_hoc_from_authoring_record_and_retained_identifier_artifact",
        "limitations": [
            "raw HTTP request bodies were not retained",
            "semantic request equality is investigator-attested rather than reconstructed from wire bytes",
        ],
        "identifier_set": {
            "path": "ids.txt",
            "sha256": _file_digest(receipt_dir / "ids.txt"),
            "size": (receipt_dir / "ids.txt").stat().st_size,
            "line_count": len((receipt_dir / "ids.txt").read_bytes().splitlines()),
        },
        "submit": {
            "method": "POST",
            "path": "/idmapping/run",
            "form": {
                "from": "UniProtKB_AC-ID",
                "to": "UniRef100",
                "ids": "identifier_set",
            },
            "response_body": {
                "path": "submit.body",
                "sha256": _file_digest(receipt_dir / "submit.body"),
                "size": (receipt_dir / "submit.body").stat().st_size,
            },
        },
        "duplicate": {
            "method": "POST",
            "path": "/idmapping/run",
            "form_relation": "same semantic form fields and exact identifier_set as submit",
            "response_body": {
                "path": "duplicate.body",
                "sha256": _file_digest(receipt_dir / "duplicate.body"),
                "size": (receipt_dir / "duplicate.body").stat().st_size,
            },
        },
    }
    if manifest != expected:
        raise AssertionError("post-hoc request identity manifest does not bind the retained files")
    receipts = lifecycle.get("private_source_receipts")
    if not isinstance(receipts, list):
        raise TypeError("sanitized lifecycle is missing its private receipt bindings")
    async_bindings = [
        item
        for item in receipts
        if isinstance(item, dict) and item.get("receipt_id") == "async_live"
    ]
    if len(async_bindings) != 1 or async_bindings[0].get(
        "post_hoc_request_identity_sha256"
    ) != _file_digest(manifest_path):
        raise AssertionError("sanitized lifecycle does not bind the post-hoc request identity")
    if (receipt_dir / "submit.body").read_bytes() != (receipt_dir / "duplicate.body").read_bytes():
        raise AssertionError("post-hoc duplicate response binding is no longer byte-equal")
    return {
        "status": "verified_unsigned_post_hoc_attestation",
        "manifest_sha256": _file_digest(manifest_path),
        "signed_contemporaneous_receipt": False,
        "request": {
            "method": "POST",
            "path": "/idmapping/run",
            "form": {
                "from": "UniProtKB_AC-ID",
                "to": "UniRef100",
                "ids": "identifier_set",
            },
            "identifier_set": {
                "sha256": manifest["identifier_set"]["sha256"],
                "size": manifest["identifier_set"]["size"],
                "line_count": manifest["identifier_set"]["line_count"],
            },
        },
        "duplicate_relation": "investigator_attested_same_semantic_form_and_exact_identifier_set",
        "raw_request_bytes_retained": False,
        "response_bytes_equal": True,
    }


def _verify_async_legacy(receipt_dir: Path, lifecycle: dict[str, Any]) -> dict[str, Any]:
    integrity = _verify_exact_legacy_files(receipt_dir, "async-live")
    _assert_legacy_content_binding(lifecycle, "async_live", integrity["content_manifest_sha256"])
    request_identity = _verify_posthoc_request_identity(receipt_dir, lifecycle)
    submitted_job_id = _job_id(receipt_dir / "submit.body")
    duplicate_job_id = _job_id(receipt_dir / "duplicate.body")
    if submitted_job_id != duplicate_job_id:
        raise AssertionError("legacy duplicate submit returned another job identifier")
    if (receipt_dir / "submit.body").read_bytes() != (receipt_dir / "duplicate.body").read_bytes():
        raise AssertionError("legacy duplicate submit response bytes changed")

    submit_status, submit_headers = _parse_headers(receipt_dir / "submit.headers")
    duplicate_status, duplicate_headers = _parse_headers(receipt_dir / "duplicate.headers")
    if submit_status != 200 or duplicate_status != 200:
        raise AssertionError("legacy submit status changed")

    pending_times: list[str] = []
    for index in range(1, 5):
        _assert_status_body(receipt_dir / f"status-{index}.body", "RUNNING")
        status, headers = _parse_headers(receipt_dir / f"status-{index}.headers")
        if status != 200:
            raise AssertionError("legacy pending status changed")
        _assert_header_release(headers)
        pending_times.append(_observed_at(headers))

    _assert_status_body(receipt_dir / "status-5.body", "FINISHED")
    terminal_status, terminal_headers = _parse_headers(receipt_dir / "status-5.headers")
    if terminal_status != 303:
        raise AssertionError("legacy terminal status changed")
    _assert_location(
        terminal_headers,
        expected_path_prefix="/idmapping/uniref/results/",
        expected_job_id=submitted_job_id,
    )

    results_status, results_headers = _parse_headers(receipt_dir / "results.headers")
    results = _json_object(receipt_dir / "results.body")
    if results_status != 200 or set(results) != {"results"}:
        raise AssertionError("legacy terminal result envelope changed")
    rows = results["results"]
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise AssertionError("legacy terminal result cardinality changed")
    result = rows[0]
    if set(result) != {"from", "to"} or not isinstance(result["from"], str):
        raise AssertionError("legacy terminal result item shape changed")
    target = result["to"]
    target_keys = {
        "commonTaxon",
        "entryType",
        "id",
        "memberCount",
        "memberIdTypes",
        "members",
        "name",
        "organismCount",
        "organisms",
        "representativeMember",
        "seedId",
        "updated",
    }
    if not isinstance(target, dict) or set(target) != target_keys:
        raise AssertionError("legacy terminal result target shape changed")
    expected_types: dict[str, type[Any]] = {
        "commonTaxon": dict,
        "entryType": str,
        "id": str,
        "memberCount": int,
        "memberIdTypes": list,
        "members": list,
        "name": str,
        "organismCount": int,
        "organisms": list,
        "representativeMember": dict,
        "seedId": str,
        "updated": str,
    }
    if any(type(target[key]) is not expected for key, expected in expected_types.items()):
        raise AssertionError("legacy terminal result target types changed")

    details_status, details_headers = _parse_headers(receipt_dir / "details.headers")
    _json_object(receipt_dir / "details.body")
    if details_status != 200:
        raise AssertionError("legacy details status changed")
    for headers in (
        submit_headers,
        duplicate_headers,
        terminal_headers,
        results_headers,
        details_headers,
    ):
        _assert_header_release(headers)

    return {
        **integrity,
        "request_identity": request_identity,
        "derived_response_facts": {
            "submit": {"status_code": 200, "job_id_shape": "non_empty_string"},
            "pending_status": {
                "status_code": 200,
                "job_status": "RUNNING",
                "observation_count": 4,
                "observed_at": pending_times,
            },
            "terminal_status": {
                "status_code": 303,
                "job_status": "FINISHED",
                "location_template": "/idmapping/uniref/results/{same_job_id}",
                "observed_at": _observed_at(terminal_headers),
            },
            "terminal_result": {
                "status_code": 200,
                "top_level_keys": ["results"],
                "result_count": 1,
                "item_keys": ["from", "to"],
                "to_keys": sorted(target_keys),
                "observed_at": _observed_at(results_headers),
            },
            "duplicate_submit": {
                "status_code": 200,
                "response_bytes_equal": True,
                "same_job_id": True,
            },
        },
    }


def _verify_preterminal_legacy(receipt_dir: Path, lifecycle: dict[str, Any]) -> dict[str, Any]:
    integrity = _verify_exact_legacy_files(receipt_dir, "preterminal")
    _assert_legacy_content_binding(lifecycle, "preterminal", integrity["content_manifest_sha256"])
    submitted_job_id = _job_id(receipt_dir / "submit.body")
    submit_status, submit_headers = _parse_headers(receipt_dir / "submit.headers")
    failure_status, failure_headers = _parse_headers(receipt_dir / "pre-results.headers")
    _json_object(receipt_dir / "pre-results.body")
    if submit_status != 200 or failure_status != 404:
        raise AssertionError("legacy preterminal response status changed")
    for index in range(1, 4):
        _assert_status_body(receipt_dir / f"status-{index}.body", "RUNNING")
        status, headers = _parse_headers(receipt_dir / f"status-{index}.headers")
        if status != 200:
            raise AssertionError("legacy preterminal pending status changed")
        _assert_header_release(headers)
    _assert_status_body(receipt_dir / "status-4.body", "FINISHED")
    terminal_status, terminal_headers = _parse_headers(receipt_dir / "status-4.headers")
    if terminal_status != 303:
        raise AssertionError("legacy preterminal terminal status changed")
    _assert_location(
        terminal_headers,
        expected_path_prefix="/idmapping/uniparc/results/",
        expected_job_id=submitted_job_id,
    )
    for headers in (submit_headers, failure_headers, terminal_headers):
        _assert_header_release(headers)
    return {
        **integrity,
        "derived_response_facts": {
            "submit_status_code": 200,
            "preterminal_failure_status_code": 404,
            "terminal_status_code": 303,
            "terminal_location_template": "/idmapping/uniparc/results/{same_job_id}",
        },
        "request_association": "investigator_attested_not_derived_from_retained_response_bytes",
    }


def _verify_invalid_duplicate_legacy(
    receipt_dir: Path, lifecycle: dict[str, Any]
) -> dict[str, Any]:
    integrity = _verify_exact_legacy_files(receipt_dir, "invalid-duplicate-live")
    _assert_legacy_content_binding(
        lifecycle, "invalid_duplicate_live", integrity["content_manifest_sha256"]
    )
    submitted_job_id = _job_id(receipt_dir / "submit.body")
    duplicate_job_id = _job_id(receipt_dir / "duplicate.body")
    if submitted_job_id != duplicate_job_id:
        raise AssertionError("legacy duplicate response changed job identifier")
    if (receipt_dir / "submit.body").read_bytes() != (receipt_dir / "duplicate.body").read_bytes():
        raise AssertionError("legacy duplicate response bytes changed")
    submit_status, submit_headers = _parse_headers(receipt_dir / "submit.headers")
    duplicate_status, duplicate_headers = _parse_headers(receipt_dir / "duplicate.headers")
    invalid_status, invalid_headers = _parse_headers(receipt_dir / "invalid.headers")
    _json_object(receipt_dir / "invalid.body")
    if (submit_status, duplicate_status, invalid_status) != (200, 200, 400):
        raise AssertionError("legacy duplicate or invalid status changed")
    for index in range(1, 4):
        _assert_status_body(receipt_dir / f"status-{index}.body", "FINISHED")
        status, headers = _parse_headers(receipt_dir / f"status-{index}.headers")
        if status != 303:
            raise AssertionError("legacy duplicate-session terminal status changed")
        _assert_location(
            headers,
            expected_path_prefix="/idmapping/results/",
            expected_job_id=submitted_job_id,
        )
        _assert_header_release(headers)
    for headers in (submit_headers, duplicate_headers, invalid_headers):
        _assert_header_release(headers)
    return {
        **integrity,
        "promotion_status": "retained_unpromoted",
        "reason": "exact_request_identity_not_retained",
    }


def _verify_manifest_files(receipt_dir: Path, manifest: dict[str, Any]) -> None:
    expected_names = {"manifest.json", "response.body", "response.headers"}
    actual_names = {path.name for path in receipt_dir.iterdir()}
    if actual_names != expected_names:
        raise AssertionError("private receipt manifest inventory changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != {"response.body", "response.headers"}:
        raise AssertionError("private receipt manifest file declarations changed")
    for name, declaration in files.items():
        if not isinstance(declaration, dict) or set(declaration) != {"sha256", "size"}:
            raise AssertionError("private receipt file declaration is invalid")
        path = receipt_dir / name
        if not path.is_file() or path.is_symlink():
            raise AssertionError("private receipt contains a non-regular file")
        if (
            type(declaration["size"]) is not int
            or declaration["size"] < 0
            or path.stat().st_size != declaration["size"]
            or _file_digest(path) != declaration["sha256"]
        ):
            raise AssertionError("private receipt file does not match its manifest")


def _verify_manifest_receipt(
    receipt_dir: Path,
    public_observation: dict[str, Any],
    *,
    kind: str,
) -> dict[str, Any]:
    if not receipt_dir.is_dir() or receipt_dir.is_symlink():
        raise AssertionError("manifest-backed private receipt directory is missing or unsafe")
    manifest_path = receipt_dir / "manifest.json"
    manifest = _strict_json(manifest_path)
    if not isinstance(manifest, dict):
        raise TypeError("private receipt manifest is not an object")
    public_receipt = public_observation.get("private_source_receipt")
    if not isinstance(public_receipt, dict):
        raise TypeError("sanitized observation is missing its private receipt binding")
    if _file_digest(manifest_path) != public_receipt.get("manifest_sha256"):
        raise AssertionError("private receipt manifest does not match the sanitized observation")
    if manifest.get("schema_version") != "datalox_private_provider_receipt_v1":
        raise AssertionError("private receipt manifest schema changed")
    if manifest.get("authority") != AUTHORITY:
        raise AssertionError("private receipt authority changed")
    validation = manifest.get("validation")
    if not isinstance(validation, dict) or validation.get("status") != "passed":
        raise AssertionError("private receipt validation did not pass")
    _verify_manifest_files(receipt_dir, manifest)

    request = manifest.get("request")
    if not isinstance(request, dict):
        raise TypeError("private receipt request declaration is invalid")
    if kind == "status_failure":
        expected_request = {
            "body_present": False,
            "credentials_present": False,
            "method": "GET",
            "path": _SYNTHETIC_UNKNOWN_STATUS_PATH,
        }
        operation = "GET /idmapping/status/{unknown_job_id}"
        query: dict[str, str] | None = None
        expected_validation = {
            "error_code": None,
            "expected_json_shape": {
                "json_type": "object",
                "messages_type": "list",
                "top_level_keys": ["messages", "url"],
            },
            "expected_status_code": 404,
            "status": "passed",
        }
    elif kind == "uniref_result_failure":
        expected_request = {
            "body_present": False,
            "credentials_present": False,
            "method": "GET",
            "path": _SYNTHETIC_UNKNOWN_UNIREF_RESULT_PATH,
            "path_template": _UNIREF_RESULT_PATH_TEMPLATE,
            "query": _UNIREF_RESULT_QUERY,
        }
        operation = f"GET {_UNIREF_RESULT_PATH_TEMPLATE}"
        query = dict(_UNIREF_RESULT_QUERY)
        expected_validation = {
            "error_code": None,
            "expected_content_type": "application/json",
            "expected_json_type": "object",
            "expected_status_code": 404,
            "status": "passed",
        }
    else:
        raise AssertionError("unsupported private receipt kind")
    if request != expected_request:
        raise AssertionError("private receipt request contract changed")
    if validation != expected_validation:
        raise AssertionError("private receipt validation contract changed")

    response = manifest.get("response")
    if not isinstance(response, dict):
        raise TypeError("private receipt response declaration is invalid")
    expected_response = {
        "content_type": "application/json",
        "date": response.get("date"),
        "deployment_date": "02-September-2026",
        "release": "2026_03",
        "status_code": 404,
    }
    if response != expected_response or not isinstance(response["date"], str):
        raise AssertionError("private receipt response metadata changed")

    header_status, headers = _parse_headers(receipt_dir / "response.headers")
    if header_status is not None:
        raise AssertionError("manifest-backed receipt unexpectedly embeds an HTTP status line")
    release, deployment = _assert_header_release(headers)
    if _observed_at(headers) != _normalized_http_date(response["date"]):
        raise AssertionError("private receipt manifest Date does not match raw headers")

    body = _json_object(receipt_dir / "response.body")
    if set(body) != {"messages", "url"}:
        raise AssertionError("private receipt failure body keys changed")
    if not isinstance(body["messages"], list) or not isinstance(body["url"], str):
        raise TypeError("private receipt failure body value types changed")

    observed_at = _observed_at(headers)
    expected_public = {
        "observed_at": observed_at,
        "release_header": release,
        "deployment_date_header": deployment,
        "operation": operation,
        "status_code": 404,
    }
    for key, expected in expected_public.items():
        if public_observation.get(key) != expected:
            raise AssertionError("sanitized observation no longer matches its private receipt")
    if query is not None and public_observation.get("query") != query:
        raise AssertionError("sanitized result-failure query no longer matches its private receipt")
    expected_response_facts: dict[str, Any] = {
        "content_type": "application/json",
        "json_type": "object",
        "top_level_keys": ["messages", "url"],
    }
    if kind == "status_failure":
        expected_response_facts["messages_type"] = "list"
    else:
        expected_response_facts["top_level_value_types"] = {
            "messages": "list",
            "url": "str",
        }
    if public_observation.get("response_facts") != expected_response_facts:
        raise AssertionError("sanitized response facts no longer match the private receipt")

    return {
        "manifest_sha256": _file_digest(manifest_path),
        "raw_file_count": 2,
        "observed_at": observed_at,
        "release_header": release,
        "deployment_date_header": deployment,
        "operation": operation,
        "exact_request_path_verified": True,
        "query": query,
        "status_code": 404,
        "response_shape": {
            "json_type": "object",
            "top_level_keys": ["messages", "url"],
            "top_level_value_types": {"messages": "list", "url": "str"},
        },
    }


def _verify_private_receipts(
    env: Path,
    lifecycle: dict[str, Any],
    status_failure: dict[str, Any],
    uniref_result_failure: dict[str, Any],
) -> dict[str, Any]:
    restricted = env / "evidence" / "restricted"
    capture_root = restricted / _RESTRICTED_CAPTURE_DATE
    if not restricted.exists():
        return {
            "status": "not_present_in_public_source",
            "exact_receipts_present": False,
        }
    if (
        not restricted.is_dir()
        or restricted.is_symlink()
        or not capture_root.is_dir()
        or capture_root.is_symlink()
    ):
        raise AssertionError("restricted UniProt receipt set is partial or unsafe")
    actual_dirs = {path.name for path in capture_root.iterdir() if path.is_dir()}
    if actual_dirs != _RESTRICTED_RECEIPT_DIRS:
        raise AssertionError("restricted UniProt receipt directory set changed")
    if any(not path.is_dir() for path in capture_root.iterdir()):
        raise AssertionError("restricted UniProt capture root contains an unexpected file")

    receipts = {
        "async_live": _verify_async_legacy(capture_root / "async-live", lifecycle),
        "preterminal": _verify_preterminal_legacy(capture_root / "preterminal", lifecycle),
        "invalid_duplicate_live": _verify_invalid_duplicate_legacy(
            capture_root / "invalid-duplicate-live", lifecycle
        ),
        "status_failure": _verify_manifest_receipt(
            capture_root / "status-404",
            status_failure,
            kind="status_failure",
        ),
        "uniref_result_failure": _verify_manifest_receipt(
            capture_root / "uniref-result-404",
            uniref_result_failure,
            kind="uniref_result_failure",
        ),
    }
    return {
        "status": "verified",
        "exact_receipts_present": True,
        "receipt_count": len(receipts),
        "receipts": receipts,
        "claim_boundary": {
            "derived": "response bytes, response headers, and manifest-backed synthetic GET identity",
            "investigator_attested": (
                "the admitted UniRef100 semantic POST identity; raw HTTP request bytes were not retained"
            ),
            "retained_unpromoted": "UniParc and ChEMBL response-only sessions",
        },
    }


def _request(
    method: str,
    path: str,
    *,
    body: Any = None,
    query: dict[str, str] | None = None,
) -> CallRequest:
    return CallRequest(
        method=method,
        path=path,
        scheme="https",
        authority=AUTHORITY,
        headers=({"content-type": "application/x-www-form-urlencoded"} if method == "POST" else {}),
        body=body,
        query=query or {},
    )


def _behavior_state(runtime: ProviderRuntime) -> dict[str, Any]:
    exported = runtime.export()["provider_state"]
    return {
        key: deepcopy(value)
        for key, value in exported.items()
        if key not in {"events", "verifier_events"}
    }


def _call(
    runtime: ProviderRuntime,
    step: str,
    request: CallRequest,
    expected_status: int,
) -> tuple[Any, dict[str, Any]]:
    before = _behavior_state(runtime)
    before_time = runtime.provider_time()["current_time"]
    response = runtime.handle(request)
    after = _behavior_state(runtime)
    after_time = runtime.provider_time()["current_time"]
    if response.status_code != expected_status:
        raise AssertionError(f"{step}: expected {expected_status}, received {response.status_code}")
    if after_time != before_time:
        raise AssertionError(f"{step}: data-plane polling advanced provider time")
    return response, {
        "step": step,
        "status_code": response.status_code,
        "state_changed": before != after,
        "provider_time": after_time,
    }


def _cycle(runtime: ProviderRuntime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    invalid_before = _behavior_state(runtime)
    response, row = _call(
        runtime,
        "authored_invalid_source",
        _request(
            "POST",
            "/idmapping/run",
            body={"from": "NOT_A_DB", "to": "ChEMBL", "ids": "DATALOX_INPUT_A"},
        ),
        400,
    )
    row["source"] = "G1_authored_completeness"
    row["atomic_rejection"] = _behavior_state(runtime) == invalid_before
    row["error_shape"] = sorted(response.body)
    rows.append(row)

    submit_request = _request(
        "POST",
        "/idmapping/run",
        body={
            "from": "UniProtKB_AC-ID",
            "to": "UniRef100",
            "ids": "DATALOX_INPUT_A",
        },
    )
    response, row = _call(runtime, "submit_job", submit_request, 200)
    job_id = response.body["jobId"]
    row["relation"] = "job_id_returned"
    rows.append(row)

    response, row = _call(
        runtime,
        "pending_status",
        _request("GET", f"/idmapping/status/{job_id}"),
        200,
    )
    row["job_status"] = response.body["jobStatus"]
    rows.append(row)
    response, row = _call(
        runtime,
        "unknown_status",
        _request("GET", "/idmapping/status/datalox-nonexistent-20260902"),
        404,
    )
    row["error_shape"] = {
        "keys": sorted(response.body),
        "messages_type": type(response.body["messages"]).__name__,
    }
    rows.append(row)
    response, row = _call(
        runtime,
        "unknown_uniref_result",
        _request(
            "GET",
            "/idmapping/uniref/results/datalox-nonexistent-uniref-20260902",
            query={"format": "json", "size": "1"},
        ),
        404,
    )
    row["error_shape"] = {
        "keys": sorted(response.body),
        "messages_type": type(response.body["messages"]).__name__,
        "url_type": type(response.body["url"]).__name__,
    }
    rows.append(row)

    before_advance = _behavior_state(runtime)
    advanced = runtime.advance_provider_time("2026-09-02T00:01:00Z")
    if len(advanced["delivered_events"]) != 1:
        raise AssertionError("provider-time advance did not complete exactly one job")
    rows.append(
        {
            "step": "authored_logical_poll_schedule",
            "source": "authored_logical_poll_schedule",
            "previous_time": advanced["previous_time"],
            "current_time": advanced["current_time"],
            "delivered_event_count": len(advanced["delivered_events"]),
            "state_changed": before_advance != _behavior_state(runtime),
        }
    )

    response, row = _call(
        runtime,
        "terminal_status",
        _request("GET", f"/idmapping/status/{job_id}"),
        303,
    )
    row["location_relation"] = response.headers["location"].endswith(
        f"/idmapping/uniref/results/{job_id}"
    )
    rows.append(row)
    response, row = _call(
        runtime,
        "terminal_results",
        _request(
            "GET",
            f"/idmapping/uniref/results/{job_id}",
            query={"format": "json", "size": "1"},
        ),
        200,
    )
    result_rows = response.body.get("results")
    if not isinstance(result_rows, list) or len(result_rows) != 1:
        raise AssertionError("terminal UniRef result cardinality changed")
    result_item = result_rows[0]
    if not isinstance(result_item, dict) or set(result_item) != {"from", "to"}:
        raise AssertionError("terminal UniRef result item shape changed")
    target = result_item["to"]
    if not isinstance(target, dict):
        raise TypeError("terminal UniRef result target is not an object")
    row["result_shape"] = {
        "top_level_keys": sorted(response.body),
        "results_type": type(result_rows).__name__,
        "result_count": len(result_rows),
        "item_keys": sorted(result_item),
        "from_type": type(result_item["from"]).__name__,
        "to_type": type(target).__name__,
        "to_keys": sorted(target),
    }
    rows.append(row)
    before_duplicate = _behavior_state(runtime)
    response, row = _call(runtime, "authored_duplicate_submit", submit_request, 200)
    row["source"] = "G1_authored_completeness"
    row["same_job_id"] = response.body["jobId"] == job_id
    row["state_unchanged"] = _behavior_state(runtime) == before_duplicate
    rows.append(row)
    before_repeat = _behavior_state(runtime)
    repeated = runtime.advance_provider_time("2026-09-02T00:01:00Z")
    if repeated["delivered_events"] or _behavior_state(runtime) != before_repeat:
        raise AssertionError("same-target provider-time advance was not stable")
    response, row = _call(
        runtime,
        "stable_terminal_results",
        _request(
            "GET",
            f"/idmapping/uniref/results/{job_id}",
            query={"format": "json", "size": "1"},
        ),
        200,
    )
    row["same_result"] = response.body["results"] == result_rows
    rows.append(row)
    return rows


def check(env: Path, *, evidence_env: Path | None = None) -> dict[str, Any]:
    env = env.resolve(strict=True)
    receipt_source = env if evidence_env is None else evidence_env.resolve(strict=True)
    lifecycle = json.loads(
        (env / "evidence" / "observed-lifecycle.json").read_text(encoding="utf-8")
    )
    status_failure = json.loads(
        (env / "evidence" / "observed-status-failure.json").read_text(encoding="utf-8")
    )
    uniref_result_failure = json.loads(
        (env / "evidence" / "observed-uniref-result-failure.json").read_text(encoding="utf-8")
    )
    private_receipt_verification = _verify_private_receipts(
        receipt_source,
        lifecycle,
        status_failure,
        uniref_result_failure,
    )
    programs = lifecycle.get("behavior_programs")
    if not isinstance(programs, list):
        raise TypeError("sanitized lifecycle behavior programs are missing")
    admitted = [item for item in programs if item.get("program_id") == "uniref100_async_lifecycle"]
    if len(admitted) != 1:
        raise AssertionError("sanitized UniRef100 lifecycle is missing or ambiguous")
    promoted_observations = [
        row
        for row in admitted[0]["observations"]
        if row.get("promotion_status") != "retained_unpromoted"
    ]
    expected_lifecycle = {
        row["observation_id"]: row["status_code"] for row in promoted_observations
    }
    if expected_lifecycle != {
        "uniref100_submit": 200,
        "uniref100_pending_status": 200,
        "uniref100_terminal_status": 303,
        "uniref100_terminal_result": 200,
    }:
        raise AssertionError("sanitized UniRef100 lifecycle statuses changed")
    expected_status_failure = status_failure["status_code"]
    expected_result_failure = uniref_result_failure["status_code"]
    with tempfile.TemporaryDirectory(prefix="datalox-uniprot-differential-") as temporary:
        runtime = ProviderRuntime(
            bundle_dir=env / "provider-runtime",
            admission_path=env / "provider-admission.json",
            run_dir=Path(temporary) / "run",
        )
        try:
            initial = _behavior_state(runtime)
            first = _cycle(runtime)
            reset = runtime.reset()
            if _behavior_state(runtime) != initial:
                raise AssertionError("local reset did not restore provider state/time/events")
            second = _cycle(runtime)
            reset_state = reset["provider_state"]
        finally:
            runtime.close()

    rows_by_step = {row["step"]: row for row in first}
    local_lifecycle = {
        "uniref100_submit": rows_by_step["submit_job"]["status_code"],
        "uniref100_pending_status": rows_by_step["pending_status"]["status_code"],
        "uniref100_terminal_status": rows_by_step["terminal_status"]["status_code"],
        "uniref100_terminal_result": rows_by_step["terminal_results"]["status_code"],
    }
    if local_lifecycle != expected_lifecycle:
        raise AssertionError("local UniRef100 lifecycle does not match retained provider facts")
    if rows_by_step["unknown_status"]["status_code"] != expected_status_failure:
        raise AssertionError("local unknown-status failure does not match retained provider fact")
    if rows_by_step["unknown_uniref_result"]["status_code"] != expected_result_failure:
        raise AssertionError("local unknown-result failure does not match retained provider fact")
    if not rows_by_step["terminal_status"]["location_relation"]:
        raise AssertionError("local terminal status does not bind the UniRef result route")
    observed_result_facts = next(
        item["response_facts"]
        for item in promoted_observations
        if item["observation_id"] == "uniref100_terminal_result"
    )
    if rows_by_step["terminal_results"]["result_shape"] != observed_result_facts:
        raise AssertionError("local terminal result shape does not match retained provider facts")
    if not rows_by_step["authored_invalid_source"]["atomic_rejection"]:
        raise AssertionError("authored invalid-write probe mutated provider state")
    if (
        not rows_by_step["authored_duplicate_submit"]["same_job_id"]
        or not rows_by_step["authored_duplicate_submit"]["state_unchanged"]
    ):
        raise AssertionError("authored duplicate-write probe changed its local contract")
    if not rows_by_step["stable_terminal_results"]["same_result"]:
        raise AssertionError("local terminal result changed after a same-target time advance")
    if first != second:
        raise AssertionError("lifecycle differs after functional reset")
    if reset_state["simulation_time"] != "2026-09-02T00:00:00+00:00":
        raise AssertionError("reset did not restore initial provider-local time")
    if reset_state["state"]["jobs"] or reset_state["scheduled_events"]:
        raise AssertionError("reset did not remove local jobs and scheduled events")
    return {
        "schema_version": "datalox_provider_temporal_differential_v1",
        "provider_id": "uniprot",
        "provider_release": lifecycle["release_header"],
        "source_observation_sha256s": {
            "lifecycle": _file_digest(env / "evidence" / "observed-lifecycle.json"),
            "status_failure": _file_digest(env / "evidence" / "observed-status-failure.json"),
            "uniref_result_failure": _file_digest(
                env / "evidence" / "observed-uniref-result-failure.json"
            ),
        },
        "private_receipt_verification": private_receipt_verification,
        "provider_runtime_sha256": _file_digest(env / "provider-runtime" / "provider-runtime.json"),
        "provider_admission_sha256": _file_digest(env / "provider-admission.json"),
        "cycles": 2,
        "grounded_observation_count": len(expected_lifecycle) + 2,
        "authored_schedule": "authored_logical_poll_schedule",
        "provider_wall_clock_claimed": False,
        "provider_reset_claimed": False,
        "first_cycle_sha256": _digest(first),
        "second_cycle_sha256": _digest(second),
        "steps": first,
        "status": "passed",
    }


def validate_public_report(env: Path) -> dict[str, Any]:
    env = env.resolve(strict=True)
    if (env / "evidence" / "restricted").exists():
        raise AssertionError(
            "public-report validation requires a source without restricted receipts"
        )
    report = _strict_json(env / "evidence" / "differential-report.json")
    if not isinstance(report, dict):
        raise TypeError("released UniProt differential report is not an object")
    current = check(env)
    current_private = current["private_receipt_verification"]
    if current_private != {
        "status": "not_present_in_public_source",
        "exact_receipts_present": False,
    }:
        raise AssertionError("public source unexpectedly exposes private receipt verification")
    released_private = report.get("private_receipt_verification")
    if (
        not isinstance(released_private, dict)
        or released_private.get("status") != "verified"
        or released_private.get("exact_receipts_present") is not True
        or released_private.get("receipt_count") != 5
        or set(released_private.get("receipts", {}))
        != {
            "async_live",
            "preterminal",
            "invalid_duplicate_live",
            "status_failure",
            "uniref_result_failure",
        }
    ):
        raise AssertionError(
            "released differential lacks the exact private receipt assurance summary"
        )
    comparable = deepcopy(report)
    comparable["private_receipt_verification"] = current_private
    if comparable != current:
        raise AssertionError(
            "released differential no longer matches the public runtime and evidence"
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    args = parser.parse_args()
    print(json.dumps(check(args.env), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
