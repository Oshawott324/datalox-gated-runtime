#!/usr/bin/env python3
"""Authoring-only acquisition of one read-only UniProt status-failure receipt.

Writable lifecycle acquisition requires a route-aware, raw-retaining utility
reviewed for the selected target family. This command intentionally cannot
submit a provider job.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

AUTHORITY = "rest.uniprot.org"
BASE_URL = f"https://{AUTHORITY}"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
NONEXISTENT_JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _decode_json(raw: bytes) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)


def _opener(proxy: str | None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [_NoRedirect()]
    if proxy is not None:
        handlers.insert(0, urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def _request_raw(
    opener: urllib.request.OpenerDirector,
    method: str,
    path: str,
) -> tuple[int, dict[str, str], bytes, bytes]:
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        method=method,
        headers={
            "Accept": "application/json",
            "User-Agent": "datalox-authoring-uniprot-idmapping/1",
        },
    )
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        status = error.code
        headers = {key.lower(): value for key, value in error.headers.items()}
        raw_headers = error.headers.as_bytes()
        body = error.read()
    else:
        with response:
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
            raw_headers = response.headers.as_bytes()
            body = response.read()
    return status, headers, raw_headers, body


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _resolve_new_private_dir(path: Path) -> Path:
    if path.exists() or path.is_symlink():
        raise ValueError("private receipt directory must not already exist")
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(REPOSITORY_ROOT)
    except ValueError:
        pass
    else:
        raise ValueError("private receipt directory must be outside the repository")
    return resolved


def acquire_status_failure(
    *,
    nonexistent_job_id: str,
    proxy: str | None,
    private_receipt_dir: Path,
) -> dict[str, Any]:
    if NONEXISTENT_JOB_ID_PATTERN.fullmatch(nonexistent_job_id) is None:
        raise ValueError("nonexistent job id must be one conservative URL path segment")
    receipt_dir = _resolve_new_private_dir(private_receipt_dir)
    opener = _opener(proxy)
    path = f"/idmapping/status/{nonexistent_job_id}"
    status, headers, raw_headers, raw_body = _request_raw(opener, "GET", path)

    receipt_dir.mkdir(parents=True, mode=0o700)
    header_path = receipt_dir / "response.headers"
    body_path = receipt_dir / "response.body"
    header_path.write_bytes(raw_headers)
    body_path.write_bytes(raw_body)
    header_path.chmod(0o600)
    body_path.chmod(0o600)

    files = {
        "response.body": {
            "sha256": _sha256_bytes(raw_body),
            "size": len(raw_body),
        },
        "response.headers": {
            "sha256": _sha256_bytes(raw_headers),
            "size": len(raw_headers),
        },
    }
    validation_error: str | None = None
    shape: dict[str, Any] | None = None
    observed_at: datetime | None = None
    if status != 404:
        validation_error = "unexpected_status"
    else:
        try:
            parsed = _decode_json(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            validation_error = "response_body_not_json"
        else:
            shape = _shape(parsed)
            if shape != {
                "json_type": "object",
                "top_level_keys": ["messages", "url"],
                "messages_type": "list",
            }:
                validation_error = "unexpected_json_shape"
    provider_date = headers.get("date")
    if validation_error is None and provider_date is None:
        validation_error = "provider_date_missing"
    if validation_error is None:
        try:
            parsed_date = parsedate_to_datetime(provider_date)
        except (TypeError, ValueError):
            validation_error = "provider_date_invalid"
        else:
            if parsed_date.tzinfo is None:
                validation_error = "provider_date_invalid"
            else:
                observed_at = parsed_date.astimezone(UTC)

    manifest = {
        "schema_version": "datalox_private_provider_receipt_v1",
        "authority": AUTHORITY,
        "request": {
            "method": "GET",
            "path": path,
            "body_present": False,
            "credentials_present": False,
        },
        "response": {
            "status_code": status,
            "date": headers.get("date"),
            "content_type": headers.get("content-type"),
            "release": headers.get("x-uniprot-release"),
            "deployment_date": headers.get("x-api-deployment-date"),
        },
        "files": files,
        "validation": {
            "status": "passed" if validation_error is None else "failed",
            "error_code": validation_error,
            "expected_status_code": 404,
            "expected_json_shape": {
                "json_type": "object",
                "top_level_keys": ["messages", "url"],
                "messages_type": "list",
            },
        },
    }
    manifest_bytes = _canonical_json_bytes(manifest)
    manifest_path = receipt_dir / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    manifest_path.chmod(0o600)

    if validation_error is not None:
        raise RuntimeError(
            f"UniProt nonexistent-status receipt failed validation: {validation_error}"
        )
    assert shape is not None and observed_at is not None
    return {
        "schema_version": "datalox_sanitized_provider_status_failure_observation_v1",
        "provider": "UniProt REST API",
        "authority": AUTHORITY,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "source_class": "public_production_probe",
        "authoring_utility": {
            "path": "scripts/providers/acquire-uniprot-idmapping-lifecycle.py",
            "sha256": _sha256_bytes(Path(__file__).read_bytes()),
        },
        "private_source_receipt": {
            "manifest_sha256": _sha256_bytes(manifest_bytes),
            "signed_contemporaneous_receipt": False,
        },
        "release_header": headers.get("x-uniprot-release"),
        "deployment_date_header": headers.get("x-api-deployment-date"),
        "operation": "GET /idmapping/status/{unknown_job_id}",
        "request_relation": "synthetic nonexistent job identifier",
        "status_code": status,
        "response_facts": {
            "content_type": headers.get("content-type"),
            "json_type": shape["json_type"],
            "top_level_keys": shape["top_level_keys"],
            "messages_type": shape["messages_type"],
        },
        "retention": {
            "public_raw_request_bytes": False,
            "public_raw_response_bytes": False,
            "private_raw_response_bytes": True,
            "provider_generated_job_ids": False,
            "submitted_provider_identifiers": False,
            "tenant_data": False,
            "credentials": False,
        },
    }


def _shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"json_type": type(value).__name__, "top_level_keys": None}
    return {
        "json_type": "object",
        "top_level_keys": sorted(value),
        "messages_type": (type(value["messages"]).__name__ if "messages" in value else None),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status-failure-only", action="store_true", required=True)
    parser.add_argument("--nonexistent-job-id", default="datalox-nonexistent-authoring")
    parser.add_argument("--proxy")
    parser.add_argument("--private-receipt-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.out.exists() or args.out.is_symlink():
        parser.error("--out must not already exist")
    try:
        result = acquire_status_failure(
            nonexistent_job_id=args.nonexistent_job_id,
            proxy=args.proxy,
            private_receipt_dir=args.private_receipt_dir,
        )
    except ValueError as error:
        parser.error(str(error))
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
