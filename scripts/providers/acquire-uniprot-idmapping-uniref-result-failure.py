#!/usr/bin/env python3
"""Authoring-only acquisition of one unknown UniRef result failure."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import UTC
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
AUTHORING_PATH = ROOT / "scripts/providers/acquire-uniprot-idmapping-lifecycle.py"
AUTHORITY = "rest.uniprot.org"


def _authoring() -> Any:
    spec = importlib.util.spec_from_file_location(
        "datalox_uniprot_lifecycle_authoring", AUTHORING_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the reviewed UniProt authoring utility")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def acquire(
    *,
    nonexistent_job_id: str,
    proxy: str | None,
    private_receipt_dir: Path,
    authoring: Any | None = None,
) -> dict[str, Any]:
    support = _authoring() if authoring is None else authoring
    if support.NONEXISTENT_JOB_ID_PATTERN.fullmatch(nonexistent_job_id) is None:
        raise ValueError("nonexistent job id must be one conservative URL path segment")
    receipt_dir = support._resolve_new_private_dir(private_receipt_dir)
    path = f"/idmapping/uniref/results/{nonexistent_job_id}?format=json&size=1"
    status, headers, raw_headers, raw_body = support._request_raw(
        support._opener(proxy), "GET", path
    )

    receipt_dir.mkdir(parents=True, mode=0o700)
    raw_files = {
        "response.headers": raw_headers,
        "response.body": raw_body,
    }
    for name, payload in raw_files.items():
        destination = receipt_dir / name
        destination.write_bytes(payload)
        destination.chmod(0o600)

    validation_error: str | None = None
    shape: dict[str, Any] | None = None
    observed_at = None
    if status != 404:
        validation_error = "unexpected_status"
    else:
        try:
            parsed = support._decode_json(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            validation_error = "response_body_not_json"
        else:
            if not isinstance(parsed, dict):
                validation_error = "response_body_not_object"
            else:
                shape = {
                    "json_type": "object",
                    "top_level_keys": sorted(parsed),
                    "top_level_value_types": {
                        key: type(value).__name__ for key, value in sorted(parsed.items())
                    },
                }
    content_type = headers.get("content-type")
    if validation_error is None and (
        not isinstance(content_type, str)
        or content_type.split(";", 1)[0].strip().lower() != "application/json"
    ):
        validation_error = "response_content_type_not_json"
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
            "path": f"/idmapping/uniref/results/{nonexistent_job_id}",
            "path_template": "/idmapping/uniref/results/{unknown_job_id}",
            "query": {"format": "json", "size": "1"},
            "body_present": False,
            "credentials_present": False,
        },
        "response": {
            "status_code": status,
            "date": provider_date,
            "content_type": content_type,
            "release": headers.get("x-uniprot-release"),
            "deployment_date": headers.get("x-api-deployment-date"),
        },
        "files": {
            name: {
                "sha256": support._sha256_bytes(payload),
                "size": len(payload),
            }
            for name, payload in sorted(raw_files.items())
        },
        "validation": {
            "status": "passed" if validation_error is None else "failed",
            "error_code": validation_error,
            "expected_status_code": 404,
            "expected_content_type": "application/json",
            "expected_json_type": "object",
        },
    }
    manifest_bytes = support._canonical_json_bytes(manifest)
    manifest_path = receipt_dir / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    manifest_path.chmod(0o600)
    if validation_error is not None:
        raise RuntimeError(f"UniRef unknown-result receipt failed validation: {validation_error}")
    assert shape is not None and observed_at is not None
    return {
        "schema_version": "datalox_sanitized_provider_result_failure_observation_v1",
        "provider": "UniProt REST API",
        "authority": AUTHORITY,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "source_class": "public_production_probe",
        "authoring_utility": {
            "path": "scripts/providers/acquire-uniprot-idmapping-uniref-result-failure.py",
            "sha256": support._sha256_bytes(Path(__file__).read_bytes()),
        },
        "private_source_receipt": {
            "manifest_sha256": support._sha256_bytes(manifest_bytes),
            "signed_contemporaneous_receipt": False,
        },
        "release_header": headers.get("x-uniprot-release"),
        "deployment_date_header": headers.get("x-api-deployment-date"),
        "operation": "GET /idmapping/uniref/results/{unknown_job_id}",
        "query": {"format": "json", "size": "1"},
        "request_relation": "synthetic nonexistent job identifier",
        "status_code": status,
        "response_facts": {
            "content_type": content_type,
            **shape,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uniref-result-failure-only", action="store_true")
    parser.add_argument("--nonexistent-job-id", default="datalox-nonexistent-uniref-authoring")
    parser.add_argument("--proxy")
    parser.add_argument("--private-receipt-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.uniref_result_failure_only:
        parser.error("--uniref-result-failure-only is required for provider access")
    if args.out.exists() or args.out.is_symlink():
        parser.error("--out must not already exist")
    try:
        result = acquire(
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
