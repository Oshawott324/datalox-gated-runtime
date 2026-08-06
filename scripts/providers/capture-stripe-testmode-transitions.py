#!/usr/bin/env python3
"""Capture a reviewed Stripe TEST-MODE transition manifest.

This is an authoring-only program, not a runtime live-write mode. It refuses to
run without an explicit execution flag and externally supplied SHA-256
identities for this runner, the fixed manifest, and its source pins.

Every request is durably journaled as in-flight before transmission. A timeout,
transport interruption, redirect, retry signal, asynchronous acceptance, or
ambiguous response framing after a write is terminal: the runner does not
retry, resume, or guess whether Stripe completed the operation.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import sys
import time
from typing import Any
from urllib.parse import urlencode


RUNNER_PATH = Path(__file__).resolve()
ROOT = RUNNER_PATH.parents[2]
ENV_DIR = ROOT / "envs" / "stripe_billing_ops_v0"
EVIDENCE_DIR = ENV_DIR / "evidence"
MANIFEST_PATH = EVIDENCE_DIR / "testmode_transition_manifest.json"
SOURCE_PINS_PATH = EVIDENCE_DIR / "official_source_pins.json"
PROVIDER_ROUTES_PATH = ENV_DIR / "world" / "v1" / "provider_routes.json"
OUTPUT_PATH = EVIDENCE_DIR / "testmode_transition_capture_v1.json"
JOURNAL_PATH = EVIDENCE_DIR / "testmode_transition_capture_v1.partial.json"

HOST = "api.stripe.com"
PORT = 443
BASE = "https://api.stripe.com"
STRIPE_VERSION = "2026-06-24.dahlia"
METHODS = {"GET", "POST", "DELETE"}
WRITE_METHODS = {"POST", "DELETE"}
USER_AGENT = "datalox-stripe-testmode-transition-authoring/1.0"
KEY_ENV = "DATALOX_STRIPE_TEST_SECRET_KEY"
KEY_PATTERN = re.compile(r"sk_test_[A-Za-z0-9_]{8,240}", re.ASCII)
ACCOUNT_ID_PATTERN = re.compile(r"acct_[A-Za-z0-9]+", re.ASCII)
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
TOKEN_PATTERN = re.compile(r"\$\{([a-z][a-z0-9_]*)\}", re.ASCII)
HEADER_NAME_PATTERN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
STATUS_LINE_PATTERN = re.compile(rb"HTTP/1[.]1 ([0-9]{3}) ([\x20-\x7e]*)")
CONTENT_LENGTH_PATTERN = re.compile(r"0|[1-9][0-9]*", re.ASCII)
ORIGIN_PATH_PATTERN = re.compile(r"/v1/[A-Za-z0-9_.\-/]+", re.ASCII)
RUN_NONCE_PATTERN = re.compile(r"[0-9a-f]{32}", re.ASCII)
RESOURCE_ID_LITERAL_PATTERN = re.compile(
    r"(?:acct|cus|prod|price|ii|in|il|pi|pm|re|cn|ch|ip|cbtxn)_[A-Za-z0-9_]+",
    re.ASCII,
)
OFFICIAL_TEST_FIXTURE_TOKENS = {"pm_card_visa"}
RESOURCE_TYPE_BY_COLLECTION = {
    "customers": "stripe.customer_id",
    "products": "stripe.product_id",
    "prices": "stripe.price_id",
    "invoiceitems": "stripe.invoice_item_id",
    "invoices": "stripe.invoice_id",
    "credit_notes": "stripe.credit_note_id",
    "payment_intents": "stripe.payment_intent_id",
    "refunds": "stripe.refund_id",
}
RESOURCE_PATTERN_BY_TYPE = {
    "stripe.customer_id": r"^cus_[A-Za-z0-9]+$",
    "stripe.product_id": r"^prod_[A-Za-z0-9]+$",
    "stripe.price_id": r"^price_[A-Za-z0-9]+$",
    "stripe.invoice_item_id": r"^ii_[A-Za-z0-9]+$",
    "stripe.invoice_id": r"^in_[A-Za-z0-9]+$",
    "stripe.invoice_line_item_id": r"^il_[A-Za-z0-9]+$",
    "stripe.credit_note_id": r"^cn_[A-Za-z0-9]+$",
    "stripe.payment_intent_id": r"^pi_[A-Za-z0-9]+$",
    "stripe.refund_id": r"^re_[A-Za-z0-9]+$",
}
DISPATCHABLE_PROGRAM_IDS = ("idempotency_parameter_conflict",)
AUTHORING_CANDIDATE_PROGRAM_IDS = (
    "idempotency_parameter_conflict",
    "product_lifecycle_delete_constraints",
    "invoice_item_pending_mutation_delete",
    "draft_invoice_line_propagation_delete",
    "invoice_finalize_send_and_void",
    "invoice_pay_success_out_of_band",
    "prepayment_credit_note_void",
    "payment_intent_automatic_success",
    "payment_intent_manual_capture",
)
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SOURCE_PINS_BYTES = 256 * 1024
MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_RESPONSE_HEADER_BYTES = 64 * 1024
MAX_RESPONSE_BODY_BYTES = 4 * 1024 * 1024
MAX_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_RECORDS = 180
MAX_JOURNAL_BYTES = 96 * 1024 * 1024
MIN_INTERVAL_SECONDS = 0.25
DEFAULT_TIMEOUT_SECONDS = 20.0
SAFE_RESPONSE_HEADERS = {
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "date",
    "idempotency-key",
    "request-id",
    "stripe-version",
    "strict-transport-security",
}
SENSITIVE_KEY_FRAGMENTS = (
    "client_secret",
    "secret",
    "token",
    "hosted_invoice_url",
    "invoice_pdf",
    "receipt_url",
    "verification_url",
)
SECRET_BYTE_PATTERNS = (
    re.compile(rb"(?:sk|rk|pk)_(?:test|live)_[A-Za-z0-9]{8,}"),
    re.compile(rb"pi_[A-Za-z0-9]+_secret_[A-Za-z0-9]+"),
    re.compile(rb"(?i)authorization\s*:"),
    re.compile(rb"(?i)bearer\s+[A-Za-z0-9._~-]{8,}"),
)


class CaptureHalt(RuntimeError):
    """Terminal capture condition that must not be retried or resumed."""

    def __init__(self, code: str, detail: str, *, completion_unknown: bool) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.completion_unknown = completion_unknown


class StrictJsonError(ValueError):
    """Strict JSON parsing failure."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


LOADED_RUNNER_SHA256 = sha256_bytes(RUNNER_PATH.read_bytes())


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, *, maximum_bytes: int) -> Any:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise CaptureHalt(
            "reviewed_input_unreadable",
            f"cannot stat {path.relative_to(ROOT)}: {error}",
            completion_unknown=False,
        ) from error
    if size > maximum_bytes:
        raise CaptureHalt(
            "reviewed_input_too_large",
            f"{path.relative_to(ROOT)} exceeds {maximum_bytes} bytes",
            completion_unknown=False,
        )
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                StrictJsonError(f"non-finite number: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJsonError) as error:
        raise CaptureHalt(
            "reviewed_input_invalid",
            f"invalid strict JSON in {path.relative_to(ROOT)}: {error}",
            completion_unknown=False,
        ) from error


def read_reviewed_file(path: Path, *, maximum_bytes: int) -> bytes:
    """Read a reviewed repo file once through symlink-safe directory handles."""
    try:
        relative = path.relative_to(ROOT)
    except ValueError as error:
        raise CaptureHalt(
            "reviewed_input_unsafe",
            "reviewed input is outside the repository",
            completion_unknown=False,
        ) from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise CaptureHalt(
            "reviewed_input_unsafe",
            "reviewed input path is not canonical",
            completion_unknown=False,
        )
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(ROOT, directory_flags))
        for component in relative.parts[:-1]:
            descriptors.append(os.open(component, directory_flags, dir_fd=descriptors[-1]))
        descriptor = os.open(relative.parts[-1], file_flags, dir_fd=descriptors[-1])
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise CaptureHalt(
                "reviewed_input_unsafe",
                f"{relative} is not a bounded single-link regular file",
                completion_unknown=False,
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise CaptureHalt(
                    "reviewed_input_too_large",
                    f"{relative} exceeds {maximum_bytes} bytes",
                    completion_unknown=False,
                )
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or total != before.st_size:
            raise CaptureHalt(
                "reviewed_input_changed_during_read",
                f"{relative} changed while its reviewed bytes were loaded",
                completion_unknown=False,
            )
        return b"".join(chunks)
    except CaptureHalt:
        raise
    except OSError as error:
        raise CaptureHalt(
            "reviewed_input_unsafe",
            f"cannot safely open {relative}: {error}",
            completion_unknown=False,
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def parse_reviewed_json(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                StrictJsonError(f"non-finite number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, StrictJsonError) as error:
        raise CaptureHalt(
            "reviewed_input_invalid",
            f"invalid strict JSON in {label}: {error}",
            completion_unknown=False,
        ) from error


def validate_digest(value: str | None, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CaptureHalt(
            "reviewed_identity_missing",
            f"{label} must be sha256:<64 lowercase hex>",
            completion_unknown=False,
        )
    return value


def verify_reviewed_identity(
    *,
    expected_runner_sha256: str | None,
    expected_manifest_sha256: str | None,
    expected_source_pins_sha256: str | None,
    manifest_raw: bytes,
    source_pins_raw: bytes,
) -> dict[str, str]:
    expected = {
        "capture_runner_sha256": validate_digest(
            expected_runner_sha256,
            label="expected runner SHA-256",
        ),
        "manifest_sha256": validate_digest(
            expected_manifest_sha256,
            label="expected manifest SHA-256",
        ),
        "source_pins_sha256": validate_digest(
            expected_source_pins_sha256,
            label="expected source-pins SHA-256",
        ),
    }
    actual = {
        "capture_runner_sha256": sha256_file(RUNNER_PATH),
        "manifest_sha256": sha256_bytes(manifest_raw),
        "source_pins_sha256": sha256_bytes(source_pins_raw),
    }
    if LOADED_RUNNER_SHA256 != expected["capture_runner_sha256"]:
        raise CaptureHalt(
            "loaded_runner_identity_mismatch",
            "loaded runner does not match the externally reviewed SHA-256",
            completion_unknown=False,
        )
    if actual != expected:
        differing = sorted(key for key in actual if actual[key] != expected[key])
        raise CaptureHalt(
            "reviewed_identity_mismatch",
            f"reviewed artifacts drifted: {differing}",
            completion_unknown=False,
        )
    return expected


def load_reviewed_inputs(
    *,
    expected_runner_sha256: str | None,
    expected_manifest_sha256: str | None,
    expected_source_pins_sha256: str | None,
) -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    manifest_raw = read_reviewed_file(
        MANIFEST_PATH,
        maximum_bytes=MAX_MANIFEST_BYTES,
    )
    source_pins_raw = read_reviewed_file(
        SOURCE_PINS_PATH,
        maximum_bytes=MAX_SOURCE_PINS_BYTES,
    )
    identities = verify_reviewed_identity(
        expected_runner_sha256=expected_runner_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_source_pins_sha256=expected_source_pins_sha256,
        manifest_raw=manifest_raw,
        source_pins_raw=source_pins_raw,
    )
    manifest = parse_reviewed_json(
        manifest_raw,
        label=str(MANIFEST_PATH.relative_to(ROOT)),
    )
    source_pins = parse_reviewed_json(
        source_pins_raw,
        label=str(SOURCE_PINS_PATH.relative_to(ROOT)),
    )
    if not isinstance(manifest, dict) or not isinstance(source_pins, dict):
        raise CaptureHalt(
            "reviewed_input_invalid",
            "reviewed manifest and source pins must be JSON objects",
            completion_unknown=False,
        )
    return identities, manifest, source_pins


def validate_local_source_pins(pins: Any) -> None:
    if not isinstance(pins, dict) or pins.get("provider_id") != "stripe":
        raise CaptureHalt(
            "source_pins_invalid",
            "source pins provider identity differs",
            completion_unknown=False,
        )
    claims = pins.get("claims")
    if claims != {
        "provider_write_evidence_present": False,
        "provider_requests_sent_by_construction": False,
        "runtime_live_write_enabled": False,
        "documentation_refs_are_live_evidence": False,
    }:
        raise CaptureHalt(
            "source_pins_invalid",
            "source pin claims are not fail-closed",
            completion_unknown=False,
        )
    records = pins.get("local_contract_pins")
    if not isinstance(records, list) or len(records) != 4:
        raise CaptureHalt(
            "source_pins_invalid",
            "four local contract pins are required",
            completion_unknown=False,
        )
    expected_paths = {
        "envs/stripe_billing_ops_v0/world/v1/provider_routes.json",
        "envs/stripe_billing_ops_v0/provider_core_coverage.json",
        "envs/stripe_billing_ops_v0/world/v1/sources.json",
        "envs/stripe_billing_ops_v0/gate_config.json",
    }
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "role"}:
            raise CaptureHalt(
                "source_pins_invalid",
                "local source pin shape differs",
                completion_unknown=False,
            )
        path_text = record["path"]
        if not isinstance(path_text, str) or path_text not in expected_paths or path_text in seen:
            raise CaptureHalt(
                "source_pins_invalid",
                "local source pin path differs or is duplicated",
                completion_unknown=False,
            )
        seen.add(path_text)
        if sha256_file(ROOT / path_text) != record["sha256"]:
            raise CaptureHalt(
                "source_pin_drift",
                f"local source pin drifted: {path_text}",
                completion_unknown=False,
            )
    if seen != expected_paths:
        raise CaptureHalt(
            "source_pins_invalid",
            "local source pin set differs",
            completion_unknown=False,
        )


def replace_fixture_tokens(value: Any, prefix: str) -> Any:
    if isinstance(value, str):
        return value.replace("${binding_prefix}", prefix).replace("${fixture_", "${" + prefix + "_")
    if isinstance(value, list):
        return [replace_fixture_tokens(item, prefix) for item in value]
    if isinstance(value, dict):
        result = {key: replace_fixture_tokens(item, prefix) for key, item in value.items()}
        if "binding" in result and isinstance(result["binding"], str):
            binding = result["binding"]
            if binding.startswith("fixture_"):
                result["binding"] = prefix + binding[len("fixture") :]
        return result
    return value


def fixture_chain(
    templates: dict[str, Any],
    fixture_id: str,
    *,
    stack: tuple[str, ...] = (),
) -> list[tuple[str, dict[str, Any]]]:
    if fixture_id in stack:
        raise CaptureHalt(
            "manifest_fixture_cycle",
            f"fixture inheritance cycle: {' -> '.join((*stack, fixture_id))}",
            completion_unknown=False,
        )
    fixture = templates.get(fixture_id)
    if not isinstance(fixture, dict):
        raise CaptureHalt(
            "manifest_fixture_unknown",
            f"unknown fixture: {fixture_id}",
            completion_unknown=False,
        )
    result: list[tuple[str, dict[str, Any]]] = []
    parent = fixture.get("extends")
    if parent is not None:
        if not isinstance(parent, str):
            raise CaptureHalt(
                "manifest_fixture_invalid",
                f"fixture {fixture_id} has invalid extends",
                completion_unknown=False,
            )
        result.extend(fixture_chain(templates, parent, stack=(*stack, fixture_id)))
    steps = fixture.get("steps")
    if not isinstance(steps, list) or not steps:
        raise CaptureHalt(
            "manifest_fixture_invalid",
            f"fixture {fixture_id} has no exact steps",
            completion_unknown=False,
        )
    result.extend((fixture_id, deepcopy(step)) for step in steps)
    return result


def expand_capture_programs(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    ready = manifest.get("capture_ready_program_ids")
    programs = manifest.get("capture_programs")
    templates = manifest.get("fixture_templates")
    if (
        not isinstance(ready, list)
        or not isinstance(programs, list)
        or not isinstance(templates, dict)
        or tuple(ready) != DISPATCHABLE_PROGRAM_IDS
        or tuple(program.get("id") for program in programs) != AUTHORING_CANDIDATE_PROGRAM_IDS
    ):
        raise CaptureHalt(
            "manifest_dispatch_boundary_invalid",
            "dispatch and authoring-candidate program IDs differ from review",
            completion_unknown=False,
        )
    catalog = manifest.get("complete_behavior_program_catalog")
    if not isinstance(catalog, list) or len(catalog) != 22:
        raise CaptureHalt(
            "manifest_scope_invalid",
            "complete 22-program behavior catalog is required",
            completion_unknown=False,
        )
    catalog_status = {
        item.get("id"): item.get("capture_status") for item in catalog if isinstance(item, dict)
    }
    if any(catalog_status.get(identifier) != "capture_manifest_ready" for identifier in ready):
        raise CaptureHalt(
            "manifest_dispatch_boundary_invalid",
            "a dispatched program is not cataloged capture-ready",
            completion_unknown=False,
        )
    expanded: list[dict[str, Any]] = []
    sequence_index = 0
    for program in programs:
        program_id = program["id"]
        if program_id not in ready:
            continue
        fixture = program.get("fixture")
        if fixture is not None:
            if not isinstance(fixture, dict) or set(fixture) != {"kind", "binding_prefix"}:
                raise CaptureHalt(
                    "manifest_fixture_invalid",
                    f"{program_id} fixture shape differs",
                    completion_unknown=False,
                )
            prefix = fixture["binding_prefix"]
            if not isinstance(prefix, str) or re.fullmatch(r"[a-z][a-z0-9_]*", prefix) is None:
                raise CaptureHalt(
                    "manifest_fixture_invalid",
                    f"{program_id} fixture prefix differs",
                    completion_unknown=False,
                )
            for template_id, step in fixture_chain(templates, fixture["kind"]):
                step = replace_fixture_tokens(step, prefix)
                step["id"] = f"{program_id}.fixture.{template_id}.{step['id']}"
                if "idempotency_slot" in step:
                    step["idempotency_slot"] = (
                        f"{program_id}-{template_id}-{step['idempotency_slot']}"
                    )
                expanded.append(
                    {
                        "sequence_index": sequence_index,
                        "program_id": program_id,
                        "fixture": True,
                        "step": step,
                    }
                )
                sequence_index += 1
        steps = program.get("steps")
        if not isinstance(steps, list) or not steps:
            raise CaptureHalt(
                "manifest_program_invalid",
                f"{program_id} has no exact steps",
                completion_unknown=False,
            )
        for step in steps:
            expanded.append(
                {
                    "sequence_index": sequence_index,
                    "program_id": program_id,
                    "fixture": False,
                    "step": deepcopy(step),
                }
            )
            sequence_index += 1
    if not expanded or len(expanded) > MAX_CAPTURE_RECORDS:
        raise CaptureHalt(
            "manifest_capture_count_invalid",
            "expanded capture count is empty or exceeds its reviewed cap",
            completion_unknown=False,
        )
    return expanded


def validate_provider_reference_value(value: str, *, label: str) -> str:
    if (
        RESOURCE_ID_LITERAL_PATTERN.fullmatch(value) is not None
        and value not in OFFICIAL_TEST_FIXTURE_TOKENS
    ):
        raise CaptureHalt(
            "manifest_literal_provider_resource_forbidden",
            f"{label} contains an unreviewed literal provider resource ID",
            completion_unknown=False,
        )
    return value


def validate_path_resource_bindings(
    *,
    path: str,
    official_path: str,
    available_bindings: dict[str, str],
    label: str,
) -> None:
    path_parts = path.split("/")
    official_parts = official_path.split("/")
    if len(path_parts) != len(official_parts):
        raise CaptureHalt(
            "manifest_path_binding_invalid",
            f"{label} path shape differs",
            completion_unknown=False,
        )
    for source, official in zip(path_parts, official_parts, strict=True):
        if not (official.startswith("{") and official.endswith("}")):
            continue
        match = TOKEN_PATTERN.fullmatch(source)
        binding = match.group(1) if match is not None else None
        expected_type = (
            "stripe.invoice_line_item_id"
            if official == "{line_item_id}"
            else RESOURCE_TYPE_BY_COLLECTION.get(official_parts[2])
        )
        if (
            binding is None
            or binding not in available_bindings
            or expected_type is None
            or available_bindings[binding] != expected_type
        ):
            raise CaptureHalt(
                "manifest_path_binding_invalid",
                f"{label} provider resource path IDs must use earlier typed response bindings",
                completion_unknown=False,
            )


def official_path_pattern(path: str) -> re.Pattern[str]:
    parts = path.split("/")
    return re.compile(
        "^"
        + "/".join(
            r"[^/]+" if part.startswith("{") and part.endswith("}") else re.escape(part)
            for part in parts
        )
        + "$",
        re.ASCII,
    )


def operation_for_step(
    step: dict[str, Any],
    *,
    routes: list[dict[str, Any]],
    prior_operations: dict[str, str],
) -> str:
    if "repeat_of" in step:
        reference = step["repeat_of"]
        if reference not in prior_operations:
            raise CaptureHalt(
                "manifest_repeat_invalid",
                f"{step.get('id')} repeats an unknown step",
                completion_unknown=False,
            )
        return prior_operations[reference]
    method = step.get("method")
    path = step.get("path")
    if method not in METHODS or not isinstance(path, str):
        raise CaptureHalt(
            "manifest_request_invalid",
            f"{step.get('id')} method/path differs",
            completion_unknown=False,
        )
    template_path = TOKEN_PATTERN.sub("DATALOXTOKEN", path)
    matches = [
        route
        for route in routes
        if route.get("method") == method
        and official_path_pattern(route.get("official_path", "")).fullmatch(template_path)
    ]
    if len(matches) != 1:
        raise CaptureHalt(
            "manifest_route_invalid",
            f"{step.get('id')} does not match exactly one declared route",
            completion_unknown=False,
        )
    return matches[0]["tool_id"]


def validate_execution_manifest(manifest: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "datalox_stripe_testmode_transition_manifest_v1"
        or manifest.get("provider_id") != "stripe"
        or manifest.get("provider_base_url") != BASE
        or manifest.get("allowed_host") != HOST
        or manifest.get("allowed_port") != PORT
        or manifest.get("stripe_version") != STRIPE_VERSION
        or manifest.get("execution_lane") != "authoring_only_testmode_writes_not_runtime_live"
        or manifest.get("runtime_live_write_eligible") is not False
    ):
        raise CaptureHalt(
            "manifest_execution_boundary_invalid",
            "manifest identity or authoring-only boundary differs",
            completion_unknown=False,
        )
    constraints = manifest.get("fixed_constraints")
    if (
        not isinstance(constraints, dict)
        or constraints.get("authentication_environment_variable") != KEY_ENV
        or constraints.get("accepted_key_prefix") != "sk_test_"
        or constraints.get("credential_persisted") is not False
        or constraints.get("redirects_followed") is not False
        or constraints.get("retries") != 0
        or constraints.get("concurrency") != 1
        or constraints.get("requires_fresh_non_overwrite_output") is not True
        or constraints.get("unknown_write_completion_is_terminal") is not True
    ):
        raise CaptureHalt(
            "manifest_execution_boundary_invalid",
            "manifest fixed safety constraints differ",
            completion_unknown=False,
        )
    expanded = expand_capture_programs(manifest)
    routes_document = load_json(PROVIDER_ROUTES_PATH, maximum_bytes=2 * 1024 * 1024)
    routes = routes_document.get("operations")
    if not isinstance(routes, list) or len(routes) != 65:
        raise CaptureHalt(
            "provider_routes_invalid",
            "exact 65-operation provider route inventory is required",
            completion_unknown=False,
        )
    seen_steps: set[str] = set()
    available_resource_bindings: dict[str, str] = {}
    prior_operations: dict[str, str] = {}
    for entry in expanded:
        step = entry["step"]
        step_id = step.get("id")
        if not isinstance(step_id, str) or step_id in seen_steps or len(step_id) > 180:
            raise CaptureHalt(
                "manifest_step_invalid",
                "step IDs must be unique and bounded",
                completion_unknown=False,
            )
        seen_steps.add(step_id)
        operation_id = operation_for_step(
            step,
            routes=routes,
            prior_operations=prior_operations,
        )
        entry["operation_id"] = operation_id
        prior_operations[step_id] = operation_id
        if "repeat_of" not in step:
            route = next(item for item in routes if item["tool_id"] == operation_id)
            validate_path_resource_bindings(
                path=step["path"],
                official_path=route["official_path"],
                available_bindings=available_resource_bindings,
                label=step_id,
            )
            for field in ("query", "form"):
                pairs = step.get(field, [])
                if not isinstance(pairs, list):
                    raise CaptureHalt(
                        "manifest_pairs_invalid",
                        f"{step_id} {field} must be ordered pairs",
                        completion_unknown=False,
                    )
                for pair in pairs:
                    if (
                        not isinstance(pair, list)
                        or len(pair) != 2
                        or not all(isinstance(item, str) for item in pair)
                    ):
                        raise CaptureHalt(
                            "manifest_pairs_invalid",
                            f"{step_id} {field} entries must be string pairs",
                            completion_unknown=False,
                        )
                    validate_provider_reference_value(
                        pair[1],
                        label=f"{step_id} {field}",
                    )
        captures = step.get("capture", [])
        if captures is not None:
            if not isinstance(captures, list):
                raise CaptureHalt(
                    "manifest_capture_invalid",
                    f"{step_id} capture must be a list",
                    completion_unknown=False,
                )
            for capture in captures:
                binding = capture.get("binding") if isinstance(capture, dict) else None
                resource_type = capture.get("type") if isinstance(capture, dict) else None
                pattern = capture.get("pattern") if isinstance(capture, dict) else None
                if (
                    not isinstance(binding, str)
                    or re.fullmatch(r"[a-z][a-z0-9_]*", binding, re.ASCII) is None
                    or binding in available_resource_bindings
                    or resource_type not in RESOURCE_PATTERN_BY_TYPE
                    or pattern != RESOURCE_PATTERN_BY_TYPE[resource_type]
                ):
                    raise CaptureHalt(
                        "manifest_capture_invalid",
                        f"{step_id} capture binding differs",
                        completion_unknown=False,
                    )
                available_resource_bindings[binding] = resource_type
    return expanded, routes


def substitute(value: str, bindings: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in bindings:
            raise CaptureHalt(
                "runtime_binding_missing",
                f"missing binding: {name}",
                completion_unknown=False,
            )
        return bindings[name]

    result = TOKEN_PATTERN.sub(replace, value)
    if TOKEN_PATTERN.search(result):
        raise CaptureHalt(
            "runtime_binding_unresolved",
            "unresolved runtime binding",
            completion_unknown=False,
        )
    return result


def substitute_pairs(value: Any, bindings: dict[str, str]) -> list[list[str]]:
    if not isinstance(value, list):
        raise CaptureHalt(
            "manifest_pairs_invalid",
            "query/form must be ordered pairs",
            completion_unknown=False,
        )
    result: list[list[str]] = []
    for pair in value:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(item, str) for item in pair)
        ):
            raise CaptureHalt(
                "manifest_pairs_invalid",
                "query/form entries must be string pairs",
                completion_unknown=False,
            )
        result.append([pair[0], substitute(pair[1], bindings)])
    return result


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def request_fingerprint(request: dict[str, Any]) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "method": request["method"],
                "path": request["path"],
                "query": request["query"],
                "request_body_sha256": request["request_body_sha256"],
                "idempotency_key": request["idempotency_key"],
                "stripe_version": STRIPE_VERSION,
            }
        )
    )


def build_request(
    step: dict[str, Any],
    *,
    bindings: dict[str, str],
    prior_requests: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if "repeat_of" in step:
        reference = step["repeat_of"]
        if reference not in prior_requests:
            raise CaptureHalt(
                "manifest_repeat_invalid",
                f"{step.get('id')} repeats an unknown request",
                completion_unknown=False,
            )
        return deepcopy(prior_requests[reference])
    method = step.get("method")
    if method not in METHODS:
        raise CaptureHalt(
            "manifest_method_invalid",
            f"{step.get('id')} method differs",
            completion_unknown=False,
        )
    path = substitute(step["path"], bindings)
    if (
        ORIGIN_PATH_PATTERN.fullmatch(path) is None
        or "//" in path
        or "/../" in path
        or "/./" in path
    ):
        raise CaptureHalt(
            "manifest_path_invalid",
            f"{step.get('id')} path is not canonical origin-form",
            completion_unknown=False,
        )
    query = substitute_pairs(step.get("query", []), bindings)
    form = substitute_pairs(step.get("form", []), bindings)
    if method != "POST" and form:
        raise CaptureHalt(
            "manifest_body_invalid",
            f"{step.get('id')} non-POST has form data",
            completion_unknown=False,
        )
    body = urlencode([tuple(pair) for pair in form]).encode("ascii") if form else b""
    if len(body) > MAX_REQUEST_BODY_BYTES:
        raise CaptureHalt(
            "request_body_too_large",
            f"{step.get('id')} request body exceeds cap",
            completion_unknown=False,
        )
    idempotency_key: str | None = None
    if "idempotency_slot" in step:
        idempotency_key = f"datalox-stripe-v1-{bindings['run_nonce']}-{step['idempotency_slot']}"
    elif "idempotency_key_from" in step:
        reference = step["idempotency_key_from"]
        if reference not in prior_requests:
            raise CaptureHalt(
                "manifest_idempotency_reference_invalid",
                f"{step.get('id')} reuses an unknown key",
                completion_unknown=False,
            )
        idempotency_key = prior_requests[reference]["idempotency_key"]
    if method == "POST" and idempotency_key is None:
        raise CaptureHalt(
            "manifest_post_without_idempotency",
            f"{step.get('id')} POST has no reviewed idempotency key",
            completion_unknown=False,
        )
    headers = {
        "accept": "application/json",
        "accept-encoding": "identity",
        "connection": "close",
        "host": HOST,
        "stripe-version": STRIPE_VERSION,
        "user-agent": USER_AGENT,
    }
    if method in WRITE_METHODS:
        headers["content-length"] = str(len(body))
        headers["content-type"] = "application/x-www-form-urlencoded"
    if idempotency_key is not None:
        headers["idempotency-key"] = idempotency_key
    request = {
        "method": method,
        "path": path,
        "query": query,
        "request_headers": headers,
        "request_body_base64": base64.b64encode(body).decode("ascii"),
        "request_body_bytes": len(body),
        "request_body_sha256": sha256_bytes(body),
        "idempotency_key": idempotency_key,
    }
    request["url"] = (
        BASE + path + ("?" + urlencode([tuple(pair) for pair in query]) if query else "")
    )
    request["request_fingerprint_sha256"] = request_fingerprint(request)
    return request


def validate_test_key(value: str | None) -> str:
    if (
        not isinstance(value, str)
        or KEY_PATTERN.fullmatch(value) is None
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        raise CaptureHalt(
            "testmode_credential_invalid",
            f"{KEY_ENV} must be a bounded sk_test_ credential",
            completion_unknown=False,
        )
    return value


def validate_expected_account_id(value: str | None) -> str:
    if (
        not isinstance(value, str)
        or ACCOUNT_ID_PATTERN.fullmatch(value) is None
        or len(value) > 255
    ):
        raise CaptureHalt(
            "expected_account_id_required",
            "an exact reviewed --expected-account-id acct_... is required",
            completion_unknown=False,
        )
    return value


def resolve_public_addresses() -> list[tuple[int, str]]:
    try:
        answers = socket.getaddrinfo(
            HOST,
            PORT,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as error:
        raise CaptureHalt(
            "provider_dns_failed",
            f"DNS resolution failed: {error}",
            completion_unknown=False,
        ) from error
    unique: dict[str, int] = {}
    for family, socktype, protocol, _canonname, address in answers:
        if (
            family not in {socket.AF_INET, socket.AF_INET6}
            or socktype != socket.SOCK_STREAM
            or protocol not in {0, socket.IPPROTO_TCP}
        ):
            continue
        text = address[0]
        try:
            parsed = ipaddress.ip_address(text)
        except ValueError as error:
            raise CaptureHalt(
                "provider_dns_invalid",
                f"DNS returned an invalid address: {text}",
                completion_unknown=False,
            ) from error
        if not parsed.is_global:
            raise CaptureHalt(
                "provider_dns_nonpublic",
                f"DNS returned non-global address: {text}",
                completion_unknown=False,
            )
        unique[text] = family
    if not unique:
        raise CaptureHalt(
            "provider_dns_empty",
            "DNS returned no reviewed public TCP address",
            completion_unknown=False,
        )
    return sorted(
        ((family, address) for address, family in unique.items()),
        key=lambda item: (item[0] != socket.AF_INET, item[1]),
    )


def socket_address(family: int, address: str) -> tuple[Any, ...]:
    return (address, PORT) if family == socket.AF_INET else (address, PORT, 0, 0)


def wire_request_bytes(request: dict[str, Any], test_key: str) -> bytes:
    body = base64.b64decode(request["request_body_base64"], validate=True)
    query = urlencode([tuple(pair) for pair in request["query"]])
    target = request["path"] + ("?" + query if query else "")
    headers = deepcopy(request["request_headers"])
    headers["authorization"] = f"Bearer {test_key}"
    lines = [f"{request['method']} {target} HTTP/1.1"]
    lines.extend(
        f"{'-'.join(part.capitalize() for part in name.split('-'))}: {value}"
        for name, value in sorted(headers.items())
    )
    encoded = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body
    if any(pattern.search(encoded) for pattern in SECRET_BYTE_PATTERNS[:1]) is False:
        raise CaptureHalt(
            "authorization_injection_failed",
            "wire request lacks the validated test-mode key",
            completion_unknown=False,
        )
    return encoded


def parse_response_headers(raw: bytes) -> tuple[int, bytes, list[tuple[bytes, bytes]]]:
    lines = raw.split(b"\r\n")
    if not lines or STATUS_LINE_PATTERN.fullmatch(lines[0]) is None:
        raise CaptureHalt(
            "response_status_line_invalid",
            "provider response is not canonical HTTP/1.1",
            completion_unknown=True,
        )
    match = STATUS_LINE_PATTERN.fullmatch(lines[0])
    assert match is not None
    status = int(match.group(1))
    fields: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise CaptureHalt(
                "response_header_invalid",
                "provider response has an empty, folded, or malformed header field",
                completion_unknown=True,
            )
        name, value = line.split(b":", 1)
        if (
            HEADER_NAME_PATTERN.fullmatch(name) is None
            or not value.startswith(b" ")
            or any(byte < 0x20 or byte == 0x7F for byte in value[1:])
        ):
            raise CaptureHalt(
                "response_header_invalid",
                "provider response has a noncanonical header field",
                completion_unknown=True,
            )
        fields.append((name, value))
    return status, lines[0], fields


def framing_and_safe_headers(
    fields: list[tuple[bytes, bytes]],
) -> tuple[int, dict[str, str], list[dict[str, str]], dict[str, Any]]:
    lengths: list[str] = []
    transfer_count = 0
    encoding_count = 0
    retained: dict[str, str] = {}
    retained_fields: list[dict[str, str]] = []
    for raw_name, raw_value in fields:
        name = raw_name.decode("ascii").lower()
        value = raw_value[1:].decode("ascii")
        if name == "content-length":
            lengths.append(value)
        elif name == "transfer-encoding":
            transfer_count += 1
        elif name == "content-encoding":
            encoding_count += 1
        if name in SAFE_RESPONSE_HEADERS:
            if name in retained:
                raise CaptureHalt(
                    "response_safe_header_duplicate",
                    f"provider repeated retained header: {name}",
                    completion_unknown=True,
                )
            retained[name] = value
            retained_fields.append(
                {
                    "name": raw_name.decode("ascii"),
                    "value_base64": base64.b64encode(raw_value).decode("ascii"),
                }
            )
    if transfer_count:
        raise CaptureHalt(
            "response_transfer_encoding_forbidden",
            "Transfer-Encoding is forbidden in this fixed HTTP/1.1 evidence lane",
            completion_unknown=True,
        )
    if encoding_count:
        raise CaptureHalt(
            "response_content_encoding_forbidden",
            "Content-Encoding is forbidden after requesting identity",
            completion_unknown=True,
        )
    if len(lengths) != 1 or CONTENT_LENGTH_PATTERN.fullmatch(lengths[0]) is None:
        raise CaptureHalt(
            "response_content_length_invalid",
            "exactly one canonical Content-Length is required",
            completion_unknown=True,
        )
    length = int(lengths[0])
    if length > MAX_RESPONSE_BODY_BYTES:
        raise CaptureHalt(
            "response_body_too_large",
            f"provider Content-Length {length} exceeds cap",
            completion_unknown=True,
        )
    framing = {
        "http_version": "HTTP/1.1",
        "content_length_count": 1,
        "transfer_encoding_count": 0,
        "content_encoding_count": 0,
        "connection_close_requested": True,
        "connection_eof_observed": True,
    }
    return length, retained, retained_fields, framing


def receive_response(tls_socket: ssl.SSLSocket) -> dict[str, Any]:
    buffer = bytearray()
    delimiter = b"\r\n\r\n"
    while delimiter not in buffer:
        if len(buffer) >= MAX_RESPONSE_HEADER_BYTES:
            raise CaptureHalt(
                "response_headers_too_large",
                "provider response headers exceed cap",
                completion_unknown=True,
            )
        chunk = tls_socket.recv(min(16 * 1024, MAX_RESPONSE_HEADER_BYTES - len(buffer)))
        if not chunk:
            raise CaptureHalt(
                "response_closed_before_headers",
                "provider closed before complete headers",
                completion_unknown=True,
            )
        buffer.extend(chunk)
    header_block, remainder = bytes(buffer).split(delimiter, 1)
    if len(header_block) > MAX_RESPONSE_HEADER_BYTES:
        raise CaptureHalt(
            "response_headers_too_large",
            "provider response headers exceed cap",
            completion_unknown=True,
        )
    status, status_line, fields = parse_response_headers(header_block)
    length, headers, retained_fields, framing = framing_and_safe_headers(fields)
    if len(remainder) > length:
        raise CaptureHalt(
            "response_framing_extra_bytes",
            "provider sent bytes beyond Content-Length in the first body frame",
            completion_unknown=True,
        )
    body = bytearray(remainder)
    while len(body) < length:
        chunk = tls_socket.recv(min(64 * 1024, length - len(body)))
        if not chunk:
            raise CaptureHalt(
                "response_closed_before_body",
                "provider closed before the complete Content-Length body",
                completion_unknown=True,
            )
        body.extend(chunk)
    try:
        trailing = tls_socket.recv(1)
    except (OSError, ssl.SSLError, socket.timeout) as error:
        raise CaptureHalt(
            "response_eof_interrupted",
            f"provider EOF proof interrupted: {type(error).__name__}",
            completion_unknown=True,
        ) from error
    if trailing:
        raise CaptureHalt(
            "response_framing_extra_bytes",
            "provider sent bytes beyond Content-Length",
            completion_unknown=True,
        )
    if headers.get("content-type") != "application/json":
        raise CaptureHalt(
            "response_content_type_invalid",
            "Stripe evidence responses must use exact application/json",
            completion_unknown=True,
        )
    return {
        "status": status,
        "status_line": status_line,
        "header_block": header_block,
        "headers": headers,
        "header_fields": retained_fields,
        "framing": framing,
        "body": bytes(body),
    }


def perform_request(
    request: dict[str, Any],
    *,
    test_key: str,
    selected_address: tuple[int, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    family, address = selected_address
    raw_socket = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    raw_socket.settimeout(timeout_seconds)
    tls_socket: ssl.SSLSocket | None = None
    try:
        raw_socket.connect(socket_address(family, address))
        peer = raw_socket.getpeername()[0]
        if ipaddress.ip_address(peer) != ipaddress.ip_address(address):
            raise CaptureHalt(
                "provider_peer_address_mismatch",
                "connected peer differs from the reviewed DNS address",
                completion_unknown=True,
            )
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_alpn_protocols(["http/1.1"])
        tls_socket = context.wrap_socket(raw_socket, server_hostname=HOST)
        if tls_socket.selected_alpn_protocol() != "http/1.1":
            raise CaptureHalt(
                "provider_alpn_mismatch",
                "provider did not negotiate reviewed HTTP/1.1 ALPN",
                completion_unknown=True,
            )
        if tls_socket.version() not in {"TLSv1.2", "TLSv1.3"}:
            raise CaptureHalt(
                "provider_tls_version_mismatch",
                "provider negotiated an unsupported TLS version",
                completion_unknown=True,
            )
        tls_socket.sendall(wire_request_bytes(request, test_key))
        return receive_response(tls_socket)
    except CaptureHalt:
        raise
    except (OSError, ssl.SSLError, socket.timeout) as error:
        raise CaptureHalt(
            "provider_transport_interrupted",
            f"provider transport interrupted: {type(error).__name__}",
            completion_unknown=True,
        ) from error
    finally:
        if tls_socket is not None:
            try:
                tls_socket.close()
            except OSError:
                pass
        else:
            try:
                raw_socket.close()
            except OSError:
                pass


def json_pointer(path: tuple[str, ...]) -> str:
    return "/" + "/".join(component.replace("~", "~0").replace("/", "~1") for component in path)


def string_is_sensitive(value: str) -> bool:
    encoded = value.encode("utf-8", errors="ignore")
    if any(pattern.search(encoded) for pattern in SECRET_BYTE_PATTERNS):
        return True
    lower = value.lower()
    return value.startswith(("https://invoice.stripe.com/", "https://pay.stripe.com/")) or (
        "?" in value and any(token in lower for token in ("secret=", "token=", "?s="))
    )


def sanitize_json(
    value: Any,
    *,
    path: tuple[str, ...] = (),
) -> tuple[Any, list[str]]:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        paths: list[str] = []
        for key, item in value.items():
            key_lower = key.lower()
            child_path = (*path, key)
            if (
                any(fragment in key_lower for fragment in SENSITIVE_KEY_FRAGMENTS)
                and item is not None
            ):
                result[key] = "[REDACTED]"
                paths.append(json_pointer(child_path))
            else:
                sanitized, child_paths = sanitize_json(item, path=child_path)
                result[key] = sanitized
                paths.extend(child_paths)
        return result, paths
    if isinstance(value, list):
        result_list: list[Any] = []
        paths = []
        for index, item in enumerate(value):
            sanitized, child_paths = sanitize_json(item, path=(*path, str(index)))
            result_list.append(sanitized)
            paths.extend(child_paths)
        return result_list, paths
    if isinstance(value, str) and string_is_sensitive(value):
        return "[REDACTED]", [json_pointer(path)]
    return value, []


def parse_secret_safe_provider_json(raw: bytes) -> tuple[Any, bytes]:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                StrictJsonError(f"non-finite number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, StrictJsonError) as error:
        raise CaptureHalt(
            "provider_body_not_strict_json",
            f"provider response is not strict UTF-8 JSON: {error}",
            completion_unknown=False,
        ) from error
    sanitized, paths = sanitize_json(parsed)
    encoded = canonical_json_bytes(sanitized)
    if (
        paths
        or any(pattern.search(raw) for pattern in SECRET_BYTE_PATTERNS)
        or any(pattern.search(encoded) for pattern in SECRET_BYTE_PATTERNS)
    ):
        raise CaptureHalt(
            "provider_response_requires_redaction",
            "provider response is not eligible for exact-raw evidence without redaction",
            completion_unknown=False,
        )
    return parsed, encoded


def parse_and_sanitize_provider_json(raw: bytes) -> tuple[Any, bytes, list[str]]:
    """Compatibility surface with fail-closed zero-redaction semantics."""
    parsed, encoded = parse_secret_safe_provider_json(raw)
    return parsed, encoded, []


def path_value(body: Any, path: list[str], *, label: str) -> Any:
    current = body
    for component in path:
        if isinstance(current, dict):
            if component not in current:
                raise CaptureHalt(
                    "provider_semantic_assertion_failed",
                    f"{label} missing body path component: {component}",
                    completion_unknown=False,
                )
            current = current[component]
        elif isinstance(current, list) and component.isdigit():
            index = int(component)
            if index >= len(current):
                raise CaptureHalt(
                    "provider_semantic_assertion_failed",
                    f"{label} body index out of range: {component}",
                    completion_unknown=False,
                )
            current = current[index]
        else:
            raise CaptureHalt(
                "provider_semantic_assertion_failed",
                f"{label} cannot descend through body path: {component}",
                completion_unknown=False,
            )
    return current


def validate_provider_semantics(
    *,
    step: dict[str, Any],
    parsed: Any,
    sanitized_body: bytes,
    bindings: dict[str, str],
    prior_bodies: dict[str, bytes],
    status: int,
) -> None:
    expect = step.get("expect")
    classify_provider_status(status=status, step_id=step["id"])
    if not isinstance(expect, dict) or status not in expect.get("statuses", []):
        raise CaptureHalt(
            "provider_status_outside_review",
            f"{step['id']} returned unreviewed status {status}",
            completion_unknown=False,
        )
    if "same_body_as" in expect:
        reference = expect["same_body_as"]
        if reference not in prior_bodies or prior_bodies[reference] != sanitized_body:
            raise CaptureHalt(
                "provider_idempotent_replay_differs",
                f"{step['id']} response differs from {reference}",
                completion_unknown=False,
            )
    if "error_type" in expect:
        if path_value(parsed, ["error", "type"], label=step["id"]) != expect["error_type"]:
            raise CaptureHalt(
                "provider_error_type_differs",
                f"{step['id']} error type differs",
                completion_unknown=False,
            )
    if "error_code" in expect:
        if path_value(parsed, ["error", "code"], label=step["id"]) != expect["error_code"]:
            raise CaptureHalt(
                "provider_error_code_differs",
                f"{step['id']} error code differs",
                completion_unknown=False,
            )
    if "error_param" in expect:
        if path_value(parsed, ["error", "param"], label=step["id"]) != expect["error_param"]:
            raise CaptureHalt(
                "provider_error_param_differs",
                f"{step['id']} error parameter differs",
                completion_unknown=False,
            )
    if "object" in expect:
        if not isinstance(parsed, dict) or parsed.get("object") != expect["object"]:
            raise CaptureHalt(
                "provider_object_differs",
                f"{step['id']} object differs",
                completion_unknown=False,
            )
    if "livemode" in expect:
        if not isinstance(parsed, dict) or parsed.get("livemode") is not False:
            raise CaptureHalt(
                "provider_not_testmode",
                f"{step['id']} does not prove livemode=false",
                completion_unknown=False,
            )
    for assertion in expect.get("field_equals", []):
        expected = assertion["value"]
        if isinstance(expected, str):
            expected = substitute(expected, bindings)
        actual = path_value(parsed, assertion["path"], label=step["id"])
        if actual != expected:
            raise CaptureHalt(
                "provider_field_differs",
                f"{step['id']} field {assertion['path']} differs",
                completion_unknown=False,
            )


def classify_provider_status(*, status: int, step_id: str) -> None:
    if 300 <= status < 400:
        raise CaptureHalt(
            "provider_redirect_forbidden",
            f"{step_id} returned redirect {status}",
            completion_unknown=True,
        )
    if (200 <= status < 300 and status != 200) or status in {408, 409, 425, 429} or status >= 500:
        raise CaptureHalt(
            "provider_completion_unknown",
            f"{step_id} returned completion-ambiguous status {status}",
            completion_unknown=True,
        )


def response_record(
    wire: dict[str, Any],
    *,
    canonical_body: bytes,
    body_transfer: str,
) -> dict[str, Any]:
    raw_body = wire["body"]
    return {
        "status": wire["status"],
        "response_headers": wire["headers"],
        "response_header_fields": wire["header_fields"],
        "response_status_line_base64": base64.b64encode(wire["status_line"]).decode("ascii"),
        "provider_header_block_sha256": sha256_bytes(wire["header_block"]),
        "provider_body_bytes": len(raw_body),
        "provider_body_sha256": sha256_bytes(raw_body),
        "provider_body_base64": base64.b64encode(raw_body).decode("ascii"),
        "body_base64": base64.b64encode(canonical_body).decode("ascii"),
        "body_bytes": len(canonical_body),
        "body_sha256": sha256_bytes(canonical_body),
        "body_transfer": body_transfer,
        "body_complete": True,
        "captured_at": utc_now(),
        "redaction": {
            "credentials_persisted": False,
            "authorization_header_persisted": False,
            "sensitive_response_fields_replaced": 0,
            "redacted_json_paths": [],
        },
        "framing": wire["framing"],
    }


def process_transition_response(
    wire: dict[str, Any],
    *,
    step: dict[str, Any],
    bindings: dict[str, str],
    prior_bodies: dict[str, bytes],
) -> tuple[Any, bytes, dict[str, Any]]:
    classify_provider_status(status=wire["status"], step_id=step["id"])
    parsed, canonical_body = parse_secret_safe_provider_json(wire["body"])
    validate_provider_semantics(
        step=step,
        parsed=parsed,
        sanitized_body=canonical_body,
        bindings=bindings,
        prior_bodies=prior_bodies,
        status=wire["status"],
    )
    response = response_record(
        wire,
        canonical_body=canonical_body,
        body_transfer="canonical_json_from_secret_safe_raw_provider_body",
    )
    return parsed, canonical_body, response


def account_preflight_request() -> dict[str, Any]:
    body = b""
    request = {
        "method": "GET",
        "path": "/v1/account",
        "query": [],
        "request_headers": {
            "accept": "application/json",
            "accept-encoding": "identity",
            "connection": "close",
            "host": HOST,
            "stripe-version": STRIPE_VERSION,
            "user-agent": USER_AGENT,
        },
        "request_body_base64": "",
        "request_body_bytes": 0,
        "request_body_sha256": sha256_bytes(body),
        "idempotency_key": None,
    }
    request["url"] = BASE + "/v1/account"
    request["request_fingerprint_sha256"] = request_fingerprint(request)
    return request


def validate_account_preflight(
    wire: dict[str, Any],
    *,
    expected_account_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    classify_provider_status(status=wire["status"], step_id="account.retrieve")
    if wire["status"] != 200:
        raise CaptureHalt(
            "account_preflight_status_invalid",
            f"Stripe account preflight returned {wire['status']}, expected 200",
            completion_unknown=False,
        )
    parsed, _canonical = parse_secret_safe_provider_json(wire["body"])
    if (
        not isinstance(parsed, dict)
        or parsed.get("object") != "account"
        or parsed.get("id") != expected_account_id
    ):
        raise CaptureHalt(
            "account_preflight_mismatch",
            "test key resolved to an account other than the explicitly reviewed account",
            completion_unknown=False,
        )
    projection = {
        "id": expected_account_id,
        "object": "account",
    }
    projected_body = canonical_json_bytes(projection)
    response = response_record(
        wire,
        canonical_body=projected_body,
        body_transfer="account_identity_projection_from_secret_safe_raw_body",
    )
    return projection, response


def validate_safe_parent() -> int:
    try:
        relative = EVIDENCE_DIR.relative_to(ROOT)
    except ValueError as error:
        raise CaptureHalt(
            "output_path_outside_repo",
            "evidence directory is outside the repository",
            completion_unknown=False,
        ) from error
    current = ROOT
    for component in relative.parts:
        current = current / component
        try:
            info = current.lstat()
        except OSError as error:
            raise CaptureHalt(
                "output_parent_unreadable",
                f"cannot inspect output parent: {current.relative_to(ROOT)}",
                completion_unknown=False,
            ) from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise CaptureHalt(
                "output_parent_unsafe",
                f"output parent is a symlink or non-directory: {current.relative_to(ROOT)}",
                completion_unknown=False,
            )
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(EVIDENCE_DIR, flags)
    except OSError as error:
        raise CaptureHalt(
            "output_parent_unreadable",
            f"cannot open evidence directory safely: {error}",
            completion_unknown=False,
        ) from error


def stat_at(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def validate_existing_journal(directory_fd: int) -> None:
    info = stat_at(directory_fd, JOURNAL_PATH.name)
    if info is None:
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.getuid()
        or info.st_size > MAX_JOURNAL_BYTES
    ):
        raise CaptureHalt(
            "partial_journal_unsafe",
            "existing partial journal is not a private owned regular file",
            completion_unknown=False,
        )


def ensure_fresh_outputs(directory_fd: int) -> None:
    if stat_at(directory_fd, OUTPUT_PATH.name) is not None:
        raise CaptureHalt(
            "capture_output_exists",
            "capture output already exists; overwrite is forbidden",
            completion_unknown=False,
        )
    if stat_at(directory_fd, JOURNAL_PATH.name) is not None:
        raise CaptureHalt(
            "partial_journal_exists",
            "partial journal exists; resume and overwrite are forbidden",
            completion_unknown=False,
        )


def write_all(file_descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(file_descriptor, view)
        if written <= 0:
            raise OSError("short journal write")
        view = view[written:]


def write_journal(directory_fd: int, document: dict[str, Any]) -> None:
    raw = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    if len(raw) > MAX_JOURNAL_BYTES:
        raise CaptureHalt(
            "partial_journal_too_large",
            "serialized partial journal exceeds cap",
            completion_unknown=document.get("in_flight") is not None,
        )
    if any(pattern.search(raw) for pattern in SECRET_BYTE_PATTERNS):
        raise CaptureHalt(
            "partial_journal_contains_secret",
            "partial journal contains secret-shaped material",
            completion_unknown=document.get("in_flight") is not None,
        )
    validate_existing_journal(directory_fd)
    temporary = f".{JOURNAL_PATH.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        write_all(descriptor, raw)
        os.fsync(descriptor)
    except OSError as error:
        raise CaptureHalt(
            "partial_journal_write_failed",
            f"cannot write partial journal: {error}",
            completion_unknown=document.get("in_flight") is not None,
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        os.replace(
            temporary,
            JOURNAL_PATH.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except OSError as error:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise CaptureHalt(
            "partial_journal_publish_failed",
            f"cannot atomically publish partial journal: {error}",
            completion_unknown=document.get("in_flight") is not None,
        ) from error


def publish_without_overwrite(directory_fd: int) -> None:
    validate_existing_journal(directory_fd)
    if stat_at(directory_fd, OUTPUT_PATH.name) is not None:
        raise CaptureHalt(
            "capture_output_exists",
            "capture output appeared before publication",
            completion_unknown=False,
        )
    try:
        os.link(
            JOURNAL_PATH.name,
            OUTPUT_PATH.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.fsync(directory_fd)
        os.unlink(JOURNAL_PATH.name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as error:
        raise CaptureHalt(
            "capture_publication_failed",
            f"non-overwrite publication failed: {error}",
            completion_unknown=False,
        ) from error


def initial_journal(
    *,
    identities: dict[str, str],
    nonce: str,
    addresses: list[tuple[int, str]],
    expected_count: int,
    expected_account_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": "datalox_stripe_testmode_transition_capture_v1",
        "provider_id": "stripe",
        "environment_id": "stripe_billing_ops_v0",
        "provider_base_url": BASE,
        "allowed_host": HOST,
        "execution_lane": "authoring_only_testmode_writes_not_runtime_live",
        "runtime_live_write_eligible": False,
        **identities,
        "run_nonce": nonce,
        "testmode_key_prefix_validated": True,
        "expected_account_id": expected_account_id,
        "account_preflight": None,
        "wire_transport": "direct_verified_tls_http_1_1_connection_close",
        "resolved_provider_addresses": [address for _family, address in addresses],
        "retry_count": 0,
        "redirect_count": 0,
        "concurrency": 1,
        "expected_capture_count": expected_count,
        "capture_count": 0,
        "total_provider_response_bytes": 0,
        "complete": False,
        "in_flight": None,
        "halt": None,
        "program_results": [],
        "captures": [],
    }


def halt_record(error: CaptureHalt, *, step_id: str | None) -> dict[str, Any]:
    return {
        "code": error.code,
        "detail": error.detail,
        "step_id": step_id,
        "completion_unknown": error.completion_unknown,
        "terminal": True,
        "retry_permitted": False,
        "resume_permitted": False,
        "recorded_at": utc_now(),
    }


def execute_capture(
    *,
    identities: dict[str, str],
    manifest: dict[str, Any],
    pins: dict[str, Any],
    test_key: str,
    expected_account_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    validate_local_source_pins(pins)
    expanded, _routes = validate_execution_manifest(manifest)
    addresses = resolve_public_addresses()
    selected_address = addresses[0]
    nonce = secrets.token_hex(16)
    if RUN_NONCE_PATTERN.fullmatch(nonce) is None:
        raise CaptureHalt(
            "run_nonce_generation_failed",
            "generated run nonce differs",
            completion_unknown=False,
        )
    directory_fd = validate_safe_parent()
    try:
        ensure_fresh_outputs(directory_fd)
        journal = initial_journal(
            identities=identities,
            nonce=nonce,
            addresses=addresses,
            expected_count=len(expanded),
            expected_account_id=expected_account_id,
        )
        write_journal(directory_fd, journal)
        preflight_request = account_preflight_request()
        journal["in_flight"] = {
            "sequence_index": -1,
            "program_id": "account_preflight",
            "step_id": "account.retrieve",
            "phase": "credential_scope_preflight",
            "method": "GET",
            "request_fingerprint_sha256": preflight_request["request_fingerprint_sha256"],
            "request": preflight_request,
            "started_at": utc_now(),
            "provider_completion": "unknown_until_complete_framed_response",
        }
        write_journal(directory_fd, journal)
        try:
            preflight_wire = perform_request(
                preflight_request,
                test_key=test_key,
                selected_address=selected_address,
                timeout_seconds=timeout_seconds,
            )
            _projection, preflight_response = validate_account_preflight(
                preflight_wire,
                expected_account_id=expected_account_id,
            )
            journal["account_preflight"] = {
                "expected_account_id": expected_account_id,
                "verified_account_id": expected_account_id,
                "complete": True,
                "request": preflight_request,
                "response": preflight_response,
            }
            journal["total_provider_response_bytes"] += preflight_response["provider_body_bytes"]
            journal["in_flight"] = None
            write_journal(directory_fd, journal)
        except CaptureHalt as error:
            journal["halt"] = halt_record(error, step_id="account.retrieve")
            if not error.completion_unknown:
                journal["in_flight"] = None
            try:
                write_journal(directory_fd, journal)
            except CaptureHalt:
                pass
            raise
        bindings = {"run_nonce": nonce}
        prior_requests: dict[str, dict[str, Any]] = {}
        prior_bodies: dict[str, bytes] = {}
        program_counts = {identifier: 0 for identifier in manifest["capture_ready_program_ids"]}
        last_completion = 0.0
        for entry in expanded:
            step = entry["step"]
            step_id = step["id"]
            request = build_request(
                step,
                bindings=bindings,
                prior_requests=prior_requests,
            )
            elapsed = time.monotonic() - last_completion
            if last_completion and elapsed < MIN_INTERVAL_SECONDS:
                time.sleep(MIN_INTERVAL_SECONDS - elapsed)
            journal["in_flight"] = {
                "sequence_index": entry["sequence_index"],
                "program_id": entry["program_id"],
                "step_id": step_id,
                "phase": step["phase"],
                "method": request["method"],
                "request_fingerprint_sha256": request["request_fingerprint_sha256"],
                "request": request,
                "started_at": utc_now(),
                "provider_completion": "unknown_until_complete_framed_response",
            }
            write_journal(directory_fd, journal)
            try:
                wire = perform_request(
                    request,
                    test_key=test_key,
                    selected_address=selected_address,
                    timeout_seconds=timeout_seconds,
                )
                parsed, canonical_body, response = process_transition_response(
                    wire,
                    step=step,
                    bindings=bindings,
                    prior_bodies=prior_bodies,
                )
                for capture in step.get("capture", []):
                    captured = path_value(parsed, capture["path"], label=step_id)
                    if (
                        not isinstance(captured, str)
                        or re.fullmatch(capture["pattern"], captured, re.ASCII) is None
                    ):
                        raise CaptureHalt(
                            "provider_binding_shape_differs",
                            f"{step_id} binding {capture['binding']} differs",
                            completion_unknown=False,
                        )
                    bindings[capture["binding"]] = captured
                record = {
                    "sequence_index": entry["sequence_index"],
                    "program_id": entry["program_id"],
                    "step_id": step_id,
                    "phase": step["phase"],
                    "fixture": entry["fixture"],
                    "operation_id": entry["operation_id"],
                    "request": request,
                    "response": response,
                }
                journal["captures"].append(record)
                journal["capture_count"] = len(journal["captures"])
                journal["total_provider_response_bytes"] += response["provider_body_bytes"]
                if journal["total_provider_response_bytes"] > MAX_TOTAL_RESPONSE_BYTES:
                    raise CaptureHalt(
                        "total_response_body_cap_exceeded",
                        "aggregate provider body bytes exceed cap",
                        completion_unknown=False,
                    )
                prior_requests[step_id] = deepcopy(request)
                prior_bodies[step_id] = canonical_body
                program_counts[entry["program_id"]] += 1
                journal["in_flight"] = None
                write_journal(directory_fd, journal)
                last_completion = time.monotonic()
            except CaptureHalt as error:
                journal["halt"] = halt_record(error, step_id=step_id)
                if not error.completion_unknown:
                    journal["in_flight"] = None
                try:
                    write_journal(directory_fd, journal)
                except CaptureHalt:
                    pass
                raise
        journal["program_results"] = [
            {
                "program_id": identifier,
                "capture_count": program_counts[identifier],
                "complete": True,
            }
            for identifier in manifest["capture_ready_program_ids"]
        ]
        journal["complete"] = True
        journal["in_flight"] = None
        journal["halt"] = None
        write_journal(directory_fd, journal)
        publish_without_overwrite(directory_fd)
        return journal
    finally:
        os.close(directory_fd)


def failure_payload(error: CaptureHalt) -> dict[str, Any]:
    return {
        "schema_version": "datalox_stripe_testmode_transition_capture_failure_v1",
        "provider_id": "stripe",
        "code": error.code,
        "detail": error.detail,
        "completion_unknown": error.completion_unknown,
        "terminal": True,
        "retry_permitted": False,
        "resume_permitted": False,
        "provider_requests_retried": False,
        "runtime_live_write_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-reviewed-testmode-writes", action="store_true")
    parser.add_argument("--expected-runner-sha256")
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--expected-source-pins-sha256")
    parser.add_argument("--expected-account-id")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    arguments = parser.parse_args()
    if not arguments.execute_reviewed_testmode_writes:
        failure = CaptureHalt(
            "explicit_execution_flag_required",
            "authoring-only Stripe test-mode writes require the explicit reviewed flag",
            completion_unknown=False,
        )
        print(json.dumps(failure_payload(failure), indent=2, sort_keys=True))
        return 2
    if not 1.0 <= arguments.timeout_seconds <= 30.0:
        failure = CaptureHalt(
            "timeout_outside_reviewed_bounds",
            "timeout must be between 1 and 30 seconds",
            completion_unknown=False,
        )
        print(json.dumps(failure_payload(failure), indent=2, sort_keys=True))
        return 2
    try:
        identities, manifest, pins = load_reviewed_inputs(
            expected_runner_sha256=arguments.expected_runner_sha256,
            expected_manifest_sha256=arguments.expected_manifest_sha256,
            expected_source_pins_sha256=arguments.expected_source_pins_sha256,
        )
        expected_account_id = validate_expected_account_id(arguments.expected_account_id)
        test_key = validate_test_key(os.environ.get(KEY_ENV))
        result = execute_capture(
            identities=identities,
            manifest=manifest,
            pins=pins,
            test_key=test_key,
            expected_account_id=expected_account_id,
            timeout_seconds=arguments.timeout_seconds,
        )
    except CaptureHalt as error:
        print(json.dumps(failure_payload(error), indent=2, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "schema_version": result["schema_version"],
                "provider_id": result["provider_id"],
                "capture_count": result["capture_count"],
                "complete": result["complete"],
                "output": str(OUTPUT_PATH.relative_to(ROOT)),
                "provider_requests_retried": False,
                "runtime_live_write_enabled": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
