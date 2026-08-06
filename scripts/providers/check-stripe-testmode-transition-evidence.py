#!/usr/bin/env python3
"""Fail-closed Stripe test-mode transition evidence validator.

This checker validates the fixed authoring manifest and any resulting sanitized
capture. It never sends a request. A locally implemented shadow transition is
not provider evidence, and a missing capture remains an explicit gap.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlencode


CHECKER_PATH = Path(__file__).resolve()
ROOT = CHECKER_PATH.parents[2]
ENV_DIR = ROOT / "envs" / "stripe_billing_ops_v0"
MANIFEST_PATH = ENV_DIR / "evidence" / "testmode_transition_manifest.json"
SOURCE_PINS_PATH = ENV_DIR / "evidence" / "official_source_pins.json"
CAPTURE_PATH = ENV_DIR / "evidence" / "testmode_transition_capture_v1.json"
PROVIDER_ROUTES_PATH = ENV_DIR / "world" / "v1" / "provider_routes.json"
CORE_COVERAGE_PATH = ENV_DIR / "provider_core_coverage.json"
CAPTURE_RUNNER_PATH = ROOT / "scripts" / "providers" / "capture-stripe-testmode-transitions.py"

MAX_JSON_BYTES = 96 * 1024 * 1024
MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_RESPONSE_BODY_BYTES = 4 * 1024 * 1024
MAX_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_RECORDS = 180
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
TOKEN_PATTERN = re.compile(r"\$\{([a-z][a-z0-9_]*)\}", re.ASCII)
RUN_NONCE_PATTERN = re.compile(r"[0-9a-f]{32}", re.ASCII)
ACCOUNT_ID_PATTERN = re.compile(r"acct_[A-Za-z0-9]+", re.ASCII)
ORIGIN_PATH_PATTERN = re.compile(r"/v1/[A-Za-z0-9${}_.\-/]+", re.ASCII)
SAFE_FORM_KEY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_.-]+\])*", re.ASCII)
SAFE_VALUE_PATTERN = re.compile(r"[\x20-\x7e]*", re.ASCII)
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
SENSITIVE_KEY_FRAGMENTS = (
    "client_secret",
    "secret",
    "token",
    "hosted_invoice_url",
    "invoice_pdf",
    "receipt_url",
    "verification_url",
)
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
WRITE_METHODS = {"POST", "DELETE"}
ALLOWED_METHODS = {"GET", "POST", "DELETE"}
ALLOWED_STATUSES = {200, 400, 402, 404}
ALLOWED_PROGRAM_STATUSES = {
    "capture_manifest_ready",
    "missing_exact_official_fixture",
    "missing_nonmutation_oracle",
    "missing_side_effect_review",
    "missing_special_payment_fixture",
}
READY_PROGRAM_IDS = ("idempotency_parameter_conflict",)
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
PROGRAM_IDS = (
    "idempotency_parameter_conflict",
    "customer_lifecycle_tombstone",
    "product_lifecycle_delete_constraints",
    "price_lifecycle_transfer_lookup_key",
    "invoice_item_pending_mutation_delete",
    "draft_invoice_line_propagation_delete",
    "invoice_preview_nonmutation",
    "invoice_finalize_send_and_void",
    "invoice_pay_decline_recovery",
    "invoice_pay_success_out_of_band",
    "invoice_attach_payment",
    "invoice_uncollectible_paid_void",
    "prepayment_credit_note_void",
    "postpayment_credit_note_splits",
    "payment_intent_automatic_success",
    "payment_intent_failure_cancel",
    "payment_intent_manual_capture",
    "payment_intent_incremental_authorization",
    "payment_intent_customer_balance",
    "payment_intent_microdeposit_verification",
    "refund_synchronous_partial_full_over",
    "refund_async_pending_cancel",
)
FIXTURE_TEMPLATE_IDS = (
    "fresh_customer_product_price",
    "fresh_pending_invoice_item",
    "fresh_draft_invoice_with_line",
    "fresh_open_invoice_with_line",
)
KNOWN_GAP_IDS = (
    "concurrent_same_key_requests_unobserved",
    "timeout_after_request_unknown_completion_unobserved",
    "webhook_and_eventual_consistency_unobserved",
)
SUPPORTING_OBJECT_IDS = (
    "charges",
    "payment_methods",
    "invoice_payments",
    "cash_balance_transactions",
    "events",
    "test_helpers",
)
LOCAL_MISMATCH_IDS = (
    "list_ordering",
    "search_eventual_consistency",
    "invoice_line_remove_behavior",
    "attach_partial_payments",
    "uncollectible_transitions",
    "credit_split_and_void_restrictions",
    "special_fixture_eligibility",
    "refund_charge_relationship",
    "price_transfer_lookup_key",
)

# Frozen construction identities. Any later edit requires a fresh review and
# deliberate repin before a capture can validate as evidence.
REVIEWED_MANIFEST_SHA256 = "sha256:59c34ea273c707d2c191f8c7ca6f72c4366e422f3da3da922d169d4c078e8445"
REVIEWED_SOURCE_PINS_SHA256 = (
    "sha256:b7a6b50d9c1c0b618269d1a95fcc613cba9fd719366dd2414bfd2d7ebe9967ce"
)
REVIEWED_CAPTURE_RUNNER_SHA256 = (
    "sha256:3cd576baead6b64e9e4fa1697337b3611182520a27780bdf4c879ec8abb84500"
)


class EvidenceError(ValueError):
    """A deterministic construction or evidence validation failure."""


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> Any:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise EvidenceError(f"cannot stat {path.relative_to(ROOT)}: {error}") from error
    if size > maximum_bytes:
        raise EvidenceError(f"{path.relative_to(ROOT)} exceeds {maximum_bytes} bytes")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                EvidenceError(f"non-finite JSON number: {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid JSON in {path.relative_to(ROOT)}: {error}") from error


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require_exact_keys(value: Any, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise EvidenceError(
            f"{label} keys differ; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def require_string(value: Any, *, label: str, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
        or SAFE_VALUE_PATTERN.fullmatch(value) is None
    ):
        raise EvidenceError(f"{label} must be bounded printable ASCII")
    return value


def validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def validate_source_pins() -> dict[str, Any]:
    pins = require_exact_keys(
        load_json(SOURCE_PINS_PATH),
        {
            "schema_version",
            "provider_id",
            "selected_scope",
            "official_openapi",
            "local_contract_pins",
            "official_documentation_refs",
            "claims",
        },
        label="source pins",
    )
    if pins["schema_version"] != "datalox_stripe_transition_source_pins_v1":
        raise EvidenceError("source pins schema_version differs")
    if pins["provider_id"] != "stripe":
        raise EvidenceError("source pins provider_id differs")
    openapi = require_exact_keys(
        pins["official_openapi"],
        {"repository", "commit", "file", "version", "sha256"},
        label="source pins official_openapi",
    )
    routes = load_json(PROVIDER_ROUTES_PATH)
    expected_openapi = {
        "repository": routes["source"]["repository"],
        "commit": routes["source"]["commit"],
        "file": routes["source"]["file"],
        "version": routes["source"]["version"],
        "sha256": "sha256:" + routes["source"]["sha256"],
    }
    if openapi != expected_openapi:
        raise EvidenceError("source pins OpenAPI identity differs from provider_routes.json")
    expected_local = {
        "envs/stripe_billing_ops_v0/world/v1/provider_routes.json",
        "envs/stripe_billing_ops_v0/provider_core_coverage.json",
        "envs/stripe_billing_ops_v0/world/v1/sources.json",
        "envs/stripe_billing_ops_v0/gate_config.json",
    }
    records = pins["local_contract_pins"]
    if not isinstance(records, list) or len(records) != len(expected_local):
        raise EvidenceError("source pins local_contract_pins must contain four records")
    seen: set[str] = set()
    for index, record in enumerate(records):
        item = require_exact_keys(
            record,
            {"path", "sha256", "role"},
            label=f"source pin {index}",
        )
        path_text = require_string(item["path"], label=f"source pin {index} path")
        if path_text in seen or path_text not in expected_local:
            raise EvidenceError(f"unexpected or duplicate source pin path: {path_text}")
        seen.add(path_text)
        path = ROOT / path_text
        expected_digest = validate_sha256(item["sha256"], label=f"source pin {index} sha256")
        if sha256_file(path) != expected_digest:
            raise EvidenceError(f"source pin drift: {path_text}")
        require_string(item["role"], label=f"source pin {index} role")
    if seen != expected_local:
        raise EvidenceError("source pin path set differs")
    docs = pins["official_documentation_refs"]
    if not isinstance(docs, list) or len(docs) != 6:
        raise EvidenceError("six official documentation references are required")
    doc_ids: set[str] = set()
    for index, document in enumerate(docs):
        item = require_exact_keys(
            document,
            {"id", "url", "supports"},
            label=f"official documentation ref {index}",
        )
        identifier = require_string(item["id"], label=f"official documentation ref {index} id")
        if identifier in doc_ids:
            raise EvidenceError(f"duplicate official documentation id: {identifier}")
        doc_ids.add(identifier)
        url = require_string(item["url"], label=f"official documentation ref {index} url")
        if not url.startswith("https://docs.stripe.com/"):
            raise EvidenceError(f"non-Stripe official documentation URL: {url}")
        if (
            not isinstance(item["supports"], list)
            or not item["supports"]
            or any(not isinstance(entry, str) or not entry for entry in item["supports"])
        ):
            raise EvidenceError(f"official documentation ref {identifier} has invalid supports")
    if pins["claims"] != {
        "provider_write_evidence_present": False,
        "provider_requests_sent_by_construction": False,
        "runtime_live_write_enabled": False,
        "documentation_refs_are_live_evidence": False,
    }:
        raise EvidenceError("source pin claims must remain fail-closed")
    return pins


def template_tokens(value: Any) -> set[str]:
    if isinstance(value, str):
        return set(TOKEN_PATTERN.findall(value))
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(template_tokens(item))
        return result
    if isinstance(value, dict):
        result = set()
        for item in value.values():
            result.update(template_tokens(item))
        return result
    return set()


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
        raise EvidenceError(f"fixture inheritance cycle: {' -> '.join((*stack, fixture_id))}")
    fixture = templates.get(fixture_id)
    if not isinstance(fixture, dict):
        raise EvidenceError(f"unknown fixture template: {fixture_id}")
    result: list[tuple[str, dict[str, Any]]] = []
    parent = fixture.get("extends")
    if parent is not None:
        if not isinstance(parent, str):
            raise EvidenceError(f"fixture {fixture_id} extends must be a string")
        result.extend(fixture_chain(templates, parent, stack=(*stack, fixture_id)))
    steps = fixture.get("steps")
    if not isinstance(steps, list) or not steps:
        raise EvidenceError(f"fixture {fixture_id} must have exact steps")
    result.extend((fixture_id, deepcopy(step)) for step in steps)
    return result


def expand_capture_programs(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    templates = manifest["fixture_templates"]
    expanded: list[dict[str, Any]] = []
    sequence_index = 0
    for program in manifest["capture_programs"]:
        program_id = program["id"]
        if program_id not in manifest["capture_ready_program_ids"]:
            continue
        fixture = program.get("fixture")
        if fixture is not None:
            fixture = require_exact_keys(
                fixture,
                {"kind", "binding_prefix"},
                label=f"{program_id} fixture",
            )
            fixture_id = fixture["kind"]
            prefix = fixture["binding_prefix"]
            require_string(prefix, label=f"{program_id} fixture binding_prefix", maximum=32)
            for template_id, step in fixture_chain(templates, fixture_id):
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
        for source_step in program["steps"]:
            expanded.append(
                {
                    "sequence_index": sequence_index,
                    "program_id": program_id,
                    "fixture": False,
                    "step": deepcopy(source_step),
                }
            )
            sequence_index += 1
    return expanded


def normalized_template_path(path: str) -> str:
    return TOKEN_PATTERN.sub("DATALOXTOKEN", path)


def official_path_pattern(path: str) -> re.Pattern[str]:
    parts = path.split("/")
    encoded = [
        r"[^/]+" if part.startswith("{") and part.endswith("}") else re.escape(part)
        for part in parts
    ]
    return re.compile("^" + "/".join(encoded) + "$", re.ASCII)


def infer_operation(
    *,
    method: str,
    path: str,
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized = normalized_template_path(path)
    matches = [
        operation
        for operation in operations
        if operation["method"] == method
        and official_path_pattern(operation["official_path"]).fullmatch(normalized)
    ]
    if len(matches) != 1:
        raise EvidenceError(
            f"step route must match exactly one declared operation: {method} {path}; "
            f"matches={[item['tool_id'] for item in matches]}"
        )
    return matches[0]


def validate_provider_reference_value(value: str, *, label: str) -> str:
    if (
        RESOURCE_ID_LITERAL_PATTERN.fullmatch(value) is not None
        and value not in OFFICIAL_TEST_FIXTURE_TOKENS
    ):
        raise EvidenceError(f"{label} contains an unreviewed literal provider resource ID")
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
        raise EvidenceError(f"{label} path shape differs")
    for index, (source, official) in enumerate(zip(path_parts, official_parts, strict=True)):
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
            raise EvidenceError(
                f"{label} provider resource path ID at segment {index} must use an "
                "earlier response binding of the exact provider resource type"
            )


def validate_pairs(value: Any, *, label: str) -> list[list[str]]:
    if not isinstance(value, list):
        raise EvidenceError(f"{label} must be an ordered pair list")
    result: list[list[str]] = []
    for index, pair in enumerate(value):
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(item, str) for item in pair)
        ):
            raise EvidenceError(f"{label}[{index}] must be [name, value]")
        name, raw = pair
        if (
            not name
            or SAFE_FORM_KEY_PATTERN.fullmatch(name) is None
            or len(name) > 256
            or len(raw) > 4096
            or SAFE_VALUE_PATTERN.fullmatch(raw) is None
        ):
            raise EvidenceError(f"{label}[{index}] is not bounded printable form data")
        validate_provider_reference_value(raw, label=f"{label}[{index}] value")
        result.append(pair)
    return result


def validate_expect(value: Any, *, label: str) -> dict[str, Any]:
    allowed = {
        "statuses",
        "object",
        "livemode",
        "field_equals",
        "error_type",
        "error_code",
        "error_param",
        "same_body_as",
        "post_state_assertion_step",
    }
    if not isinstance(value, dict) or not set(value).issubset(allowed):
        raise EvidenceError(f"{label} contains unsupported assertions")
    statuses = value.get("statuses")
    if (
        not isinstance(statuses, list)
        or not statuses
        or len(statuses) != len(set(statuses))
        or any(status not in ALLOWED_STATUSES for status in statuses)
    ):
        raise EvidenceError(f"{label}.statuses is invalid")
    if "livemode" in value and value["livemode"] is not False:
        raise EvidenceError(f"{label}.livemode may only assert false")
    if "object" in value:
        require_string(value["object"], label=f"{label}.object", maximum=64)
    if "error_type" in value:
        if value["error_type"] not in {"invalid_request_error", "idempotency_error"}:
            raise EvidenceError(f"{label}.error_type is unsupported")
        if any(status == 200 for status in statuses):
            raise EvidenceError(f"{label}.error_type cannot accept status 200")
        if value["error_type"] == "invalid_request_error" and not {
            "error_code",
            "error_param",
        }.issubset(value):
            raise EvidenceError(
                f"{label} generic invalid_request_error requires exact code and param"
            )
    for field in ("error_code", "error_param", "post_state_assertion_step"):
        if field in value:
            require_string(value[field], label=f"{label}.{field}", maximum=180)
    if "field_equals" in value:
        assertions = value["field_equals"]
        if not isinstance(assertions, list) or not assertions:
            raise EvidenceError(f"{label}.field_equals must be nonempty")
        for index, assertion in enumerate(assertions):
            item = require_exact_keys(
                assertion,
                {"path", "value"},
                label=f"{label}.field_equals[{index}]",
            )
            path = item["path"]
            if (
                not isinstance(path, list)
                or not path
                or any(not isinstance(part, str) or not part for part in path)
            ):
                raise EvidenceError(f"{label}.field_equals[{index}].path is invalid")
            if isinstance(item["value"], float):
                raise EvidenceError(f"{label}.field_equals[{index}] floats are forbidden")
    return value


def validate_capture_specs(value: Any, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise EvidenceError(f"{label} must be a nonempty list")
    result: list[dict[str, Any]] = []
    for index, capture in enumerate(value):
        item = require_exact_keys(
            capture,
            {"binding", "type", "path", "pattern"},
            label=f"{label}[{index}]",
        )
        binding = require_string(item["binding"], label=f"{label}[{index}].binding", maximum=64)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", binding, re.ASCII):
            raise EvidenceError(f"{label}[{index}].binding is invalid")
        resource_type = require_string(
            item["type"],
            label=f"{label}[{index}].type",
            maximum=64,
        )
        if resource_type not in RESOURCE_PATTERN_BY_TYPE:
            raise EvidenceError(f"{label}[{index}].type is not reviewed")
        path = item["path"]
        if (
            not isinstance(path, list)
            or not path
            or any(not isinstance(part, str) or not part for part in path)
        ):
            raise EvidenceError(f"{label}[{index}].path is invalid")
        pattern = require_string(item["pattern"], label=f"{label}[{index}].pattern", maximum=256)
        if pattern != RESOURCE_PATTERN_BY_TYPE[resource_type]:
            raise EvidenceError(f"{label}[{index}].pattern differs from its resource type")
        try:
            re.compile(pattern, re.ASCII)
        except re.error as error:
            raise EvidenceError(f"{label}[{index}].pattern is invalid: {error}") from error
        result.append(item)
    return result


def validate_dispatchable_delete_sequences(expanded: list[dict[str, Any]]) -> None:
    for entry in expanded:
        step = entry["step"]
        expect = step.get("expect", {})
        if step.get("method") != "DELETE" or 200 not in expect.get("statuses", []):
            continue
        later = [
            candidate
            for candidate in expanded
            if candidate["program_id"] == entry["program_id"]
            and candidate["sequence_index"] > entry["sequence_index"]
        ]
        repeats = [
            candidate["step"]
            for candidate in later
            if candidate["step"].get("repeat_of") == step["id"]
        ]
        reads = [
            candidate["step"]
            for candidate in later
            if candidate["step"].get("method") == "GET"
            and candidate["step"].get("path") == step["path"]
        ]
        if len(repeats) != 1 or len(reads) != 1:
            raise EvidenceError(
                f"{step['id']} successful DELETE requires one exact duplicate and "
                "one post-delete retrieval"
            )
        for label, assertion in (
            ("duplicate DELETE", repeats[0].get("expect", {})),
            ("post-delete retrieval", reads[0].get("expect", {})),
        ):
            statuses = assertion.get("statuses", [])
            if 200 in statuses:
                if not assertion.get("object") or not assertion.get("field_equals"):
                    raise EvidenceError(f"{step['id']} {label} tombstone is underasserted")
            elif not {
                "error_type",
                "error_code",
                "error_param",
            }.issubset(assertion):
                raise EvidenceError(f"{step['id']} {label} error is not exact")


def validate_manifest() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    pins = validate_source_pins()
    manifest = require_exact_keys(
        load_json(MANIFEST_PATH),
        {
            "schema_version",
            "provider_id",
            "environment_id",
            "provider_base_url",
            "allowed_host",
            "allowed_port",
            "stripe_version",
            "execution_lane",
            "runtime_live_write_eligible",
            "source_pins_path",
            "fixed_constraints",
            "complete_behavior_program_catalog",
            "capture_ready_program_ids",
            "capture_programs",
            "fixture_templates",
            "known_behavior_gaps",
            "supporting_provider_objects",
            "known_local_behavior_mismatches",
            "evidence_state",
        },
        label="transition manifest",
    )
    expected_identity = {
        "schema_version": "datalox_stripe_testmode_transition_manifest_v1",
        "provider_id": "stripe",
        "environment_id": "stripe_billing_ops_v0",
        "provider_base_url": "https://api.stripe.com",
        "allowed_host": "api.stripe.com",
        "allowed_port": 443,
        "stripe_version": "2026-06-24.dahlia",
        "execution_lane": "authoring_only_testmode_writes_not_runtime_live",
        "runtime_live_write_eligible": False,
        "source_pins_path": "envs/stripe_billing_ops_v0/evidence/official_source_pins.json",
    }
    if any(manifest[key] != value for key, value in expected_identity.items()):
        raise EvidenceError("transition manifest identity or execution boundary differs")
    constraints = manifest["fixed_constraints"]
    if constraints != {
        "authentication_environment_variable": "DATALOX_STRIPE_TEST_SECRET_KEY",
        "accepted_key_prefix": "sk_test_",
        "credential_persisted": False,
        "redirects_followed": False,
        "retries": 0,
        "concurrency": 1,
        "requires_fresh_non_overwrite_output": True,
        "requires_explicit_execution_flag": "--execute-reviewed-testmode-writes",
        "unknown_write_completion_is_terminal": True,
        "test_payment_method": "pm_card_visa",
        "synthetic_email_domain": "example.invalid",
    }:
        raise EvidenceError("transition manifest fixed constraints differ")
    routes = load_json(PROVIDER_ROUTES_PATH)
    operations = routes["operations"]
    operation_ids = {item["tool_id"] for item in operations}
    coverage = load_json(CORE_COVERAGE_PATH)
    write_ids = {item["id"] for item in coverage["operations"] if item["effect"] == "write"}
    if len(write_ids) != 38:
        raise EvidenceError("Stripe declared write count drifted from 38")
    family_ids = {item["id"] for item in coverage["core_families"]}
    if family_ids != {
        "customers",
        "products",
        "prices",
        "invoice_items",
        "invoices",
        "credit_notes",
        "payment_intents",
        "refunds",
    }:
        raise EvidenceError("Stripe core family set differs")
    catalog = manifest["complete_behavior_program_catalog"]
    if not isinstance(catalog, list) or tuple(item.get("id") for item in catalog) != PROGRAM_IDS:
        raise EvidenceError("complete behavior program catalog IDs/order differ")
    catalog_operations: set[str] = set()
    catalog_by_id: dict[str, dict[str, Any]] = {}
    for index, program in enumerate(catalog):
        if not isinstance(program, dict):
            raise EvidenceError(f"program catalog item {index} must be an object")
        required = {
            "id",
            "families",
            "operations",
            "required_behavior",
            "capture_status",
        }
        optional = {"missing_prerequisite", "remaining_missing_prerequisite"}
        if not required.issubset(program) or not set(program).issubset(required | optional):
            raise EvidenceError(f"program catalog item {index} keys differ")
        identifier = program["id"]
        status = program["capture_status"]
        if status not in ALLOWED_PROGRAM_STATUSES:
            raise EvidenceError(f"program {identifier} has unsupported capture_status")
        families = program["families"]
        if not isinstance(families, list) or not families or not set(families).issubset(family_ids):
            raise EvidenceError(f"program {identifier} has invalid families")
        program_operations = program["operations"]
        if (
            not isinstance(program_operations, list)
            or not program_operations
            or not set(program_operations).issubset(operation_ids)
        ):
            raise EvidenceError(f"program {identifier} has invalid operations")
        if status != "capture_manifest_ready" and "missing_prerequisite" not in program:
            raise EvidenceError(f"non-ready program {identifier} must state missing_prerequisite")
        require_string(
            program["required_behavior"],
            label=f"program {identifier} required_behavior",
        )
        catalog_operations.update(program_operations)
        catalog_by_id[identifier] = program
    if catalog_operations & write_ids != write_ids:
        raise EvidenceError(
            f"program catalog omits writes: {sorted(write_ids - catalog_operations)}"
        )
    if catalog_operations != operation_ids:
        raise EvidenceError(
            "program catalog must map all 65 declared operations; "
            f"missing={sorted(operation_ids - catalog_operations)}, "
            f"extra={sorted(catalog_operations - operation_ids)}"
        )
    if set(manifest["capture_ready_program_ids"]) != set(READY_PROGRAM_IDS):
        raise EvidenceError("capture_ready_program_ids differ")
    if (
        tuple(program["id"] for program in manifest["capture_programs"])
        != AUTHORING_CANDIDATE_PROGRAM_IDS
    ):
        raise EvidenceError("authoring-candidate capture_program IDs/order differ")
    for identifier in READY_PROGRAM_IDS:
        if catalog_by_id[identifier]["capture_status"] != "capture_manifest_ready":
            raise EvidenceError(f"capture program {identifier} is not cataloged ready")
    templates = manifest["fixture_templates"]
    if not isinstance(templates, dict) or tuple(templates) != FIXTURE_TEMPLATE_IDS:
        raise EvidenceError("fixture template IDs/order differ")
    for fixture_id, fixture in templates.items():
        allowed = {"description", "operations", "idempotent", "steps", "extends"}
        required = {"description", "operations", "idempotent", "steps"}
        if (
            not isinstance(fixture, dict)
            or not required.issubset(fixture)
            or not set(fixture).issubset(allowed)
            or fixture["idempotent"] is not True
        ):
            raise EvidenceError(f"fixture {fixture_id} shape differs")
        if (
            not isinstance(fixture["operations"], list)
            or not fixture["operations"]
            or not set(fixture["operations"]).issubset(operation_ids)
        ):
            raise EvidenceError(f"fixture {fixture_id} operations differ")
        fixture_chain(templates, fixture_id)
    gaps = manifest["known_behavior_gaps"]
    if not isinstance(gaps, list) or tuple(item.get("id") for item in gaps) != KNOWN_GAP_IDS:
        raise EvidenceError("known behavior gaps IDs/order differ")
    for gap in gaps:
        require_exact_keys(
            gap,
            {"id", "blocking_for_full_behavioral_fidelity", "reason"},
            label=f"known behavior gap {gap.get('id')}",
        )
        if gap["blocking_for_full_behavioral_fidelity"] is not True:
            raise EvidenceError(f"known behavior gap {gap['id']} must remain blocking")
        require_string(gap["reason"], label=f"known behavior gap {gap['id']} reason")
    supporting = manifest["supporting_provider_objects"]
    if (
        not isinstance(supporting, list)
        or tuple(item.get("id") for item in supporting) != SUPPORTING_OBJECT_IDS
    ):
        raise EvidenceError("supporting provider object IDs/order differ")
    for item in supporting:
        require_exact_keys(
            item,
            {"id", "role", "selected_scope_status", "dispatch_status"},
            label=f"supporting provider object {item.get('id')}",
        )
        require_string(item["role"], label=f"supporting provider object {item['id']} role")
        require_string(
            item["selected_scope_status"],
            label=f"supporting provider object {item['id']} selected_scope_status",
        )
        require_string(
            item["dispatch_status"],
            label=f"supporting provider object {item['id']} dispatch_status",
        )
    mismatches = manifest["known_local_behavior_mismatches"]
    if (
        not isinstance(mismatches, list)
        or tuple(item.get("id") for item in mismatches) != LOCAL_MISMATCH_IDS
    ):
        raise EvidenceError("known local behavior mismatch IDs/order differ")
    for item in mismatches:
        require_exact_keys(
            item,
            {"id", "current_local_risk", "required_provider_evidence"},
            label=f"known local behavior mismatch {item.get('id')}",
        )
        require_string(
            item["current_local_risk"],
            label=f"known local behavior mismatch {item['id']} risk",
        )
        require_string(
            item["required_provider_evidence"],
            label=f"known local behavior mismatch {item['id']} evidence",
        )
    if manifest["evidence_state"] != {
        "capture_output_path": (
            "envs/stripe_billing_ops_v0/evidence/testmode_transition_capture_v1.json"
        ),
        "partial_journal_path": (
            "envs/stripe_billing_ops_v0/evidence/testmode_transition_capture_v1.partial.json"
        ),
        "provider_requests_sent": False,
        "complete_capture_present": False,
        "all_38_declared_writes_accounted_for_by_program_catalog": True,
        "all_38_declared_writes_provider_observed": False,
    }:
        raise EvidenceError("manifest evidence_state must remain pre-capture and fail-closed")
    expanded = expand_capture_programs(manifest)
    if not expanded or len(expanded) > MAX_CAPTURE_RECORDS:
        raise EvidenceError("expanded capture record count is empty or exceeds cap")
    seen_steps: set[str] = set()
    seen_bindings = {"run_nonce"}
    seen_resource_bindings: dict[str, str] = {}
    prior_steps: dict[str, dict[str, Any]] = {}
    idempotency_slots: set[str] = set()
    has_parameter_conflict = False
    invalid_transition_post_states: list[tuple[int, str, str]] = []
    for entry in expanded:
        step = entry["step"]
        label = f"step {step.get('id', '<missing>')}"
        identifier = require_string(step.get("id"), label=f"{label} id", maximum=180)
        if identifier in seen_steps:
            raise EvidenceError(f"duplicate step ID: {identifier}")
        seen_steps.add(identifier)
        phase = step.get("phase")
        if phase not in {
            "initial_read",
            "fixture_write",
            "write",
            "duplicate",
            "invalid_transition",
            "recovery",
            "resulting_state",
            "related_state",
        }:
            raise EvidenceError(f"{label} has unsupported phase")
        if "repeat_of" in step:
            if set(step) != {"id", "phase", "repeat_of", "expect"}:
                raise EvidenceError(f"{label} repeat step contains mutable request fields")
            reference = step["repeat_of"]
            prior = prior_steps.get(reference)
            if prior is None:
                raise EvidenceError(f"{label} repeat_of must reference an earlier step")
            if phase != "duplicate" or prior["method"] not in {"POST", "DELETE"}:
                raise EvidenceError(
                    f"{label} may only repeat an earlier POST or DELETE as duplicate"
                )
            expect = validate_expect(step["expect"], label=f"{label} expect")
            if prior["method"] == "POST":
                if expect.get("same_body_as") != reference:
                    raise EvidenceError(f"{label} must assert the repeated POST response body")
            elif "same_body_as" in expect:
                raise EvidenceError(
                    f"{label} must not invent same-body idempotency for repeated DELETE"
                )
            step["_operation"] = prior["_operation"]
            prior_steps[identifier] = step
            continue
        allowed_keys = {
            "id",
            "phase",
            "method",
            "path",
            "query",
            "form",
            "idempotency_slot",
            "idempotency_key_from",
            "expect",
            "capture",
        }
        required_keys = {"id", "phase", "method", "path", "expect"}
        if not required_keys.issubset(step) or not set(step).issubset(allowed_keys):
            raise EvidenceError(f"{label} request keys differ")
        method = step["method"]
        path = step["path"]
        if method not in ALLOWED_METHODS:
            raise EvidenceError(f"{label} method is unsupported")
        if (
            not isinstance(path, str)
            or ORIGIN_PATH_PATTERN.fullmatch(path) is None
            or "//" in path
            or "/../" in path
            or "/./" in path
        ):
            raise EvidenceError(f"{label} path is not canonical origin-form")
        operation = infer_operation(method=method, path=path, operations=operations)
        step["_operation"] = operation["tool_id"]
        validate_path_resource_bindings(
            path=path,
            official_path=operation["official_path"],
            available_bindings=seen_resource_bindings,
            label=label,
        )
        query = validate_pairs(step.get("query", []), label=f"{label} query")
        form = validate_pairs(step.get("form", []), label=f"{label} form")
        if method == "GET" and form:
            raise EvidenceError(f"{label} GET cannot have a form body")
        if method == "DELETE" and form:
            raise EvidenceError(f"{label} DELETE cannot have a form body")
        if method != "POST" and ("idempotency_slot" in step or "idempotency_key_from" in step):
            raise EvidenceError(f"{label} idempotency is permitted only on POST")
        if "idempotency_slot" in step and "idempotency_key_from" in step:
            raise EvidenceError(f"{label} cannot define and reuse an idempotency key")
        if (
            method == "POST"
            and "idempotency_slot" not in step
            and "idempotency_key_from" not in step
            and phase != "related_state"
        ):
            raise EvidenceError(f"{label} POST must have a reviewed idempotency key")
        if "idempotency_slot" in step:
            slot = require_string(
                step["idempotency_slot"],
                label=f"{label} idempotency_slot",
                maximum=160,
            )
            if slot in idempotency_slots:
                raise EvidenceError(f"duplicate idempotency slot: {slot}")
            idempotency_slots.add(slot)
        if "idempotency_key_from" in step:
            reference = step["idempotency_key_from"]
            prior = prior_steps.get(reference)
            if prior is None or "idempotency_slot" not in prior:
                raise EvidenceError(f"{label} idempotency_key_from must reference keyed POST")
            if method != prior["method"] or path != prior["path"]:
                raise EvidenceError(f"{label} idempotency conflict must use the same route")
            if query == prior.get("query", []) and form == prior.get("form", []):
                raise EvidenceError(f"{label} idempotency conflict must change parameters")
            has_parameter_conflict = True
        expect = validate_expect(step["expect"], label=f"{label} expect")
        if phase == "invalid_transition":
            reference = expect.get("post_state_assertion_step")
            if not isinstance(reference, str):
                raise EvidenceError(
                    f"{label} invalid transition requires an exact post-state assertion step"
                )
            invalid_transition_post_states.append((entry["sequence_index"], identifier, reference))
        used_tokens = template_tokens(
            {key: value for key, value in step.items() if key != "capture"}
        )
        missing_tokens = used_tokens - seen_bindings
        if missing_tokens:
            raise EvidenceError(f"{label} uses unavailable bindings: {sorted(missing_tokens)}")
        if "capture" in step:
            captures = validate_capture_specs(step["capture"], label=f"{label} capture")
            for capture in captures:
                binding = capture["binding"]
                if binding in seen_bindings:
                    raise EvidenceError(f"{label} redefines binding: {binding}")
                seen_bindings.add(binding)
                seen_resource_bindings[binding] = capture["type"]
        prior_steps[identifier] = step
    if not has_parameter_conflict:
        raise EvidenceError("manifest lacks same-key/different-parameter idempotency evidence")
    by_identifier = {
        entry["step"]["id"]: (entry["sequence_index"], entry["step"]) for entry in expanded
    }
    for sequence_index, identifier, reference in invalid_transition_post_states:
        target = by_identifier.get(reference)
        if target is None or target[0] <= sequence_index:
            raise EvidenceError(f"invalid transition {identifier} post-state step must occur later")
        target_step = target[1]
        if (
            target_step.get("method") != "GET"
            or target_step.get("phase") not in {"resulting_state", "related_state"}
            or not target_step.get("expect", {}).get("field_equals")
        ):
            raise EvidenceError(f"invalid transition {identifier} post-state step is underasserted")
    validate_dispatchable_delete_sequences(expanded)
    return manifest, expanded, pins


def substitute(value: str, bindings: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in bindings:
            raise EvidenceError(f"missing runtime binding: {name}")
        return bindings[name]

    result = TOKEN_PATTERN.sub(replace, value)
    if TOKEN_PATTERN.search(result):
        raise EvidenceError("unresolved template token")
    return result


def substitute_pairs(pairs: list[list[str]], bindings: dict[str, str]) -> list[list[str]]:
    return [[name, substitute(value, bindings)] for name, value in pairs]


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def request_fingerprint(request: dict[str, Any]) -> str:
    canonical = {
        "method": request["method"],
        "path": request["path"],
        "query": request["query"],
        "request_body_sha256": request["request_body_sha256"],
        "idempotency_key": request.get("idempotency_key"),
        "stripe_version": "2026-06-24.dahlia",
    }
    return sha256_bytes(canonical_json_bytes(canonical))


def decode_base64(value: Any, *, maximum: int, label: str) -> bytes:
    if not isinstance(value, str) or not value.isascii() or len(value) > 4 * ((maximum + 2) // 3):
        raise EvidenceError(f"{label} is not bounded ASCII base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise EvidenceError(f"{label} is not canonical base64") from error
    if len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        raise EvidenceError(f"{label} exceeds cap or is not canonical base64")
    return decoded


def path_value(body: Any, path: list[str], *, label: str) -> Any:
    current = body
    for component in path:
        if isinstance(current, dict):
            if component not in current:
                raise EvidenceError(f"{label} missing body path component: {component}")
            current = current[component]
        elif isinstance(current, list) and component.isdigit():
            index = int(component)
            if index >= len(current):
                raise EvidenceError(f"{label} body list index out of range: {component}")
            current = current[index]
        else:
            raise EvidenceError(f"{label} cannot descend through body path: {component}")
    return current


def contains_secret_material(raw: bytes) -> bool:
    patterns = (
        rb"(?:sk|rk|pk)_(?:test|live)_[A-Za-z0-9]{8,}",
        rb"pi_[A-Za-z0-9]+_secret_[A-Za-z0-9]+",
        rb"(?i)authorization\s*:",
        rb"(?i)bearer\s+[A-Za-z0-9._~-]{8,}",
    )
    return any(re.search(pattern, raw) is not None for pattern in patterns)


def json_pointer(path: tuple[str, ...]) -> str:
    return "/" + "/".join(component.replace("~", "~0").replace("/", "~1") for component in path)


def string_is_sensitive(value: str) -> bool:
    encoded = value.encode("utf-8", errors="ignore")
    if contains_secret_material(encoded):
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
            child_path = (*path, key)
            if (
                any(fragment in key.lower() for fragment in SENSITIVE_KEY_FRAGMENTS)
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
        paths: list[str] = []
        for index, item in enumerate(value):
            sanitized, child_paths = sanitize_json(item, path=(*path, str(index)))
            result_list.append(sanitized)
            paths.extend(child_paths)
        return result_list, paths
    if isinstance(value, str) and string_is_sensitive(value):
        return "[REDACTED]", [json_pointer(path)]
    return value, []


def strict_json_body(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                EvidenceError(f"{label} has non-finite JSON number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} is not strict UTF-8 JSON: {error}") from error


def expected_request(
    step: dict[str, Any],
    *,
    bindings: dict[str, str],
    prior_requests: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if "repeat_of" in step:
        return deepcopy(prior_requests[step["repeat_of"]])
    method = step["method"]
    path = substitute(step["path"], bindings)
    query = substitute_pairs(step.get("query", []), bindings)
    form = substitute_pairs(step.get("form", []), bindings)
    body = urlencode([tuple(pair) for pair in form]).encode("ascii") if form else b""
    if len(body) > MAX_REQUEST_BODY_BYTES:
        raise EvidenceError(f"request body for {step['id']} exceeds cap")
    idempotency_key: str | None = None
    if "idempotency_slot" in step:
        idempotency_key = f"datalox-stripe-v1-{bindings['run_nonce']}-{step['idempotency_slot']}"
    elif "idempotency_key_from" in step:
        idempotency_key = prior_requests[step["idempotency_key_from"]]["idempotency_key"]
    headers = {
        "accept": "application/json",
        "accept-encoding": "identity",
        "connection": "close",
        "host": "api.stripe.com",
        "stripe-version": "2026-06-24.dahlia",
        "user-agent": "datalox-stripe-testmode-transition-authoring/1.0",
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
        "https://api.stripe.com"
        + path
        + ("?" + urlencode([tuple(pair) for pair in query]) if query else "")
    )
    request["request_fingerprint_sha256"] = request_fingerprint(request)
    return request


def expected_account_preflight_request() -> dict[str, Any]:
    body = b""
    request = {
        "method": "GET",
        "path": "/v1/account",
        "query": [],
        "request_headers": {
            "accept": "application/json",
            "accept-encoding": "identity",
            "connection": "close",
            "host": "api.stripe.com",
            "stripe-version": "2026-06-24.dahlia",
            "user-agent": "datalox-stripe-testmode-transition-authoring/1.0",
        },
        "request_body_base64": "",
        "request_body_bytes": 0,
        "request_body_sha256": sha256_bytes(body),
        "idempotency_key": None,
    }
    request["url"] = "https://api.stripe.com/v1/account"
    request["request_fingerprint_sha256"] = request_fingerprint(request)
    return request


def validate_response(
    response: Any,
    *,
    expect: dict[str, Any],
    bindings: dict[str, str],
    prior_bodies: dict[str, bytes],
    step_id: str,
) -> tuple[Any, bytes]:
    value = require_exact_keys(
        response,
        {
            "status",
            "response_headers",
            "response_header_fields",
            "response_status_line_base64",
            "provider_header_block_sha256",
            "provider_body_bytes",
            "provider_body_sha256",
            "provider_body_base64",
            "body_base64",
            "body_bytes",
            "body_sha256",
            "body_transfer",
            "body_complete",
            "captured_at",
            "redaction",
            "framing",
        },
        label=f"{step_id} response",
    )
    status = value["status"]
    if status not in expect["statuses"]:
        raise EvidenceError(f"{step_id} status {status} is outside reviewed expectation")
    headers = value["response_headers"]
    if not isinstance(headers, dict) or any(
        not isinstance(name, str) or name not in SAFE_RESPONSE_HEADERS or not isinstance(raw, str)
        for name, raw in headers.items()
    ):
        raise EvidenceError(f"{step_id} response_headers are not safe and normalized")
    framing = value["framing"]
    if framing != {
        "http_version": "HTTP/1.1",
        "content_length_count": 1,
        "transfer_encoding_count": 0,
        "content_encoding_count": 0,
        "connection_close_requested": True,
        "connection_eof_observed": True,
    }:
        raise EvidenceError(f"{step_id} response framing differs")
    provider_bytes = value["provider_body_bytes"]
    if (
        not isinstance(provider_bytes, int)
        or isinstance(provider_bytes, bool)
        or provider_bytes < 0
        or provider_bytes > MAX_RESPONSE_BODY_BYTES
    ):
        raise EvidenceError(f"{step_id} provider_body_bytes is invalid")
    validate_sha256(value["provider_body_sha256"], label=f"{step_id} provider_body_sha256")
    validate_sha256(
        value["provider_header_block_sha256"],
        label=f"{step_id} provider_header_block_sha256",
    )
    if headers.get("content-length") != str(provider_bytes):
        raise EvidenceError(f"{step_id} provider Content-Length differs")
    if headers.get("content-type") != "application/json":
        raise EvidenceError(f"{step_id} provider Content-Type is not exact application/json")
    raw_provider_body = decode_base64(
        value["provider_body_base64"],
        maximum=MAX_RESPONSE_BODY_BYTES,
        label=f"{step_id} raw provider body",
    )
    if (
        len(raw_provider_body) != provider_bytes
        or sha256_bytes(raw_provider_body) != value["provider_body_sha256"]
    ):
        raise EvidenceError(f"{step_id} raw provider body provenance differs")
    raw_parsed = strict_json_body(
        raw_provider_body,
        label=f"{step_id} raw provider body",
    )
    sanitized, redacted_paths = sanitize_json(raw_parsed)
    if redacted_paths or contains_secret_material(raw_provider_body):
        raise EvidenceError(f"{step_id} raw provider body requires redaction")
    status_line = decode_base64(
        value["response_status_line_base64"],
        maximum=1024,
        label=f"{step_id} response status line",
    )
    if not status_line.startswith(f"HTTP/1.1 {status} ".encode("ascii")):
        raise EvidenceError(f"{step_id} response status line differs")
    fields = value["response_header_fields"]
    if not isinstance(fields, list):
        raise EvidenceError(f"{step_id} response_header_fields must be a list")
    reconstructed: dict[str, str] = {}
    for index, field in enumerate(fields):
        item = require_exact_keys(
            field,
            {"name", "value_base64"},
            label=f"{step_id} response header field {index}",
        )
        name = require_string(
            item["name"],
            label=f"{step_id} response header field {index} name",
            maximum=128,
        ).lower()
        if name not in SAFE_RESPONSE_HEADERS or name in reconstructed:
            raise EvidenceError(f"{step_id} response header field is unsafe or duplicate")
        raw_value = decode_base64(
            item["value_base64"],
            maximum=8192,
            label=f"{step_id} response header field {index} value",
        )
        if not raw_value.startswith(b" ") or any(
            byte < 0x20 or byte == 0x7F for byte in raw_value[1:]
        ):
            raise EvidenceError(f"{step_id} response header field raw value is invalid")
        reconstructed[name] = raw_value[1:].decode("ascii")
    if reconstructed != headers:
        raise EvidenceError(f"{step_id} response raw/normalized headers differ")
    body = decode_base64(
        value["body_base64"],
        maximum=MAX_RESPONSE_BODY_BYTES,
        label=f"{step_id} sanitized response body",
    )
    if value["body_transfer"] == "canonical_json_from_secret_safe_raw_provider_body":
        derived_body = canonical_json_bytes(sanitized)
    elif value["body_transfer"] == "account_identity_projection_from_secret_safe_raw_body":
        if (
            not isinstance(raw_parsed, dict)
            or not isinstance(raw_parsed.get("id"), str)
            or raw_parsed.get("object") != "account"
        ):
            raise EvidenceError(f"{step_id} account identity projection source differs")
        derived_body = canonical_json_bytes(
            {
                "id": raw_parsed["id"],
                "object": "account",
            }
        )
    else:
        raise EvidenceError(f"{step_id} response body transfer is unsupported")
    if (
        value["body_bytes"] != len(body)
        or value["body_sha256"] != sha256_bytes(body)
        or body != derived_body
        or value["body_complete"] is not True
    ):
        raise EvidenceError(f"{step_id} sanitized response body metadata differs")
    if contains_secret_material(body):
        raise EvidenceError(f"{step_id} sanitized response retains secret material")
    redaction = require_exact_keys(
        value["redaction"],
        {
            "credentials_persisted",
            "authorization_header_persisted",
            "sensitive_response_fields_replaced",
            "redacted_json_paths",
        },
        label=f"{step_id} redaction",
    )
    if (
        redaction["credentials_persisted"] is not False
        or redaction["authorization_header_persisted"] is not False
        or redaction["sensitive_response_fields_replaced"] != 0
        or redaction["redacted_json_paths"] != []
    ):
        raise EvidenceError(f"{step_id} redaction metadata differs")
    try:
        datetime.fromisoformat(value["captured_at"])
    except (TypeError, ValueError) as error:
        raise EvidenceError(f"{step_id} captured_at is invalid") from error
    parsed = strict_json_body(body, label=f"{step_id} response body")
    if "same_body_as" in expect:
        reference = expect["same_body_as"]
        if reference not in prior_bodies or body != prior_bodies[reference]:
            raise EvidenceError(f"{step_id} repeated response body differs from {reference}")
    if "error_type" in expect:
        if path_value(parsed, ["error", "type"], label=step_id) != expect["error_type"]:
            raise EvidenceError(f"{step_id} provider error type differs")
    if "error_code" in expect:
        if path_value(parsed, ["error", "code"], label=step_id) != expect["error_code"]:
            raise EvidenceError(f"{step_id} provider error code differs")
    if "error_param" in expect:
        if path_value(parsed, ["error", "param"], label=step_id) != expect["error_param"]:
            raise EvidenceError(f"{step_id} provider error parameter differs")
    if "object" in expect:
        if not isinstance(parsed, dict) or parsed.get("object") != expect["object"]:
            raise EvidenceError(f"{step_id} provider object differs")
    if "livemode" in expect:
        if not isinstance(parsed, dict) or parsed.get("livemode") is not False:
            raise EvidenceError(f"{step_id} is not a test-mode object")
    for assertion in expect.get("field_equals", []):
        actual = path_value(parsed, assertion["path"], label=step_id)
        expected = assertion["value"]
        if isinstance(expected, str):
            expected = substitute(expected, bindings)
        if actual != expected:
            raise EvidenceError(
                f"{step_id} field {assertion['path']} differs: {actual!r} != {expected!r}"
            )
    return parsed, body


def validate_capture(
    manifest: dict[str, Any],
    expanded: list[dict[str, Any]],
    *,
    expected_account_id: str | None,
) -> dict[str, Any]:
    capture = require_exact_keys(
        load_json(CAPTURE_PATH),
        {
            "schema_version",
            "provider_id",
            "environment_id",
            "provider_base_url",
            "allowed_host",
            "execution_lane",
            "runtime_live_write_eligible",
            "manifest_sha256",
            "source_pins_sha256",
            "capture_runner_sha256",
            "run_nonce",
            "testmode_key_prefix_validated",
            "expected_account_id",
            "account_preflight",
            "wire_transport",
            "resolved_provider_addresses",
            "retry_count",
            "redirect_count",
            "concurrency",
            "expected_capture_count",
            "capture_count",
            "total_provider_response_bytes",
            "complete",
            "in_flight",
            "halt",
            "program_results",
            "captures",
        },
        label="Stripe transition capture",
    )
    if capture["schema_version"] != "datalox_stripe_testmode_transition_capture_v1":
        raise EvidenceError("capture schema_version differs")
    expected_identity = {
        "provider_id": "stripe",
        "environment_id": "stripe_billing_ops_v0",
        "provider_base_url": "https://api.stripe.com",
        "allowed_host": "api.stripe.com",
        "execution_lane": "authoring_only_testmode_writes_not_runtime_live",
        "runtime_live_write_eligible": False,
        "testmode_key_prefix_validated": True,
        "wire_transport": "direct_verified_tls_http_1_1_connection_close",
        "retry_count": 0,
        "redirect_count": 0,
        "concurrency": 1,
        "expected_capture_count": len(expanded),
        "capture_count": len(expanded),
        "complete": True,
        "in_flight": None,
        "halt": None,
    }
    if any(capture[key] != value for key, value in expected_identity.items()):
        raise EvidenceError("capture identity, boundary, or completion fields differ")
    if capture["manifest_sha256"] != REVIEWED_MANIFEST_SHA256:
        raise EvidenceError("capture manifest digest is not independently reviewed")
    if capture["source_pins_sha256"] != REVIEWED_SOURCE_PINS_SHA256:
        raise EvidenceError("capture source-pins digest is not independently reviewed")
    if capture["capture_runner_sha256"] != REVIEWED_CAPTURE_RUNNER_SHA256:
        raise EvidenceError("capture runner digest is not independently reviewed")
    if sha256_file(MANIFEST_PATH) != REVIEWED_MANIFEST_SHA256:
        raise EvidenceError("reviewed manifest drifted")
    if sha256_file(SOURCE_PINS_PATH) != REVIEWED_SOURCE_PINS_SHA256:
        raise EvidenceError("reviewed source pins drifted")
    if sha256_file(CAPTURE_RUNNER_PATH) != REVIEWED_CAPTURE_RUNNER_SHA256:
        raise EvidenceError("reviewed capture runner drifted")
    nonce = capture["run_nonce"]
    if not isinstance(nonce, str) or RUN_NONCE_PATTERN.fullmatch(nonce) is None:
        raise EvidenceError("capture run_nonce differs")
    if (
        not isinstance(expected_account_id, str)
        or ACCOUNT_ID_PATTERN.fullmatch(expected_account_id) is None
        or capture["expected_account_id"] != expected_account_id
    ):
        raise EvidenceError(
            "capture validation requires the exact independently reviewed account ID"
        )
    preflight = require_exact_keys(
        capture["account_preflight"],
        {
            "expected_account_id",
            "verified_account_id",
            "complete",
            "request",
            "response",
        },
        label="capture account_preflight",
    )
    if (
        preflight["expected_account_id"] != expected_account_id
        or preflight["verified_account_id"] != expected_account_id
        or preflight["complete"] is not True
        or preflight["request"] != expected_account_preflight_request()
    ):
        raise EvidenceError("capture account preflight identity or request differs")
    preflight_body, _preflight_bytes = validate_response(
        preflight["response"],
        expect={
            "statuses": [200],
            "object": "account",
            "field_equals": [
                {
                    "path": ["id"],
                    "value": expected_account_id,
                }
            ],
        },
        bindings={"run_nonce": nonce},
        prior_bodies={},
        step_id="account.retrieve",
    )
    if preflight_body != {"id": expected_account_id, "object": "account"}:
        raise EvidenceError("capture account preflight retained more than ID/object")
    addresses = capture["resolved_provider_addresses"]
    if not isinstance(addresses, list) or not addresses:
        raise EvidenceError("capture resolved_provider_addresses must be nonempty")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as error:
            raise EvidenceError(f"capture has invalid provider address: {address}") from error
        if not parsed.is_global:
            raise EvidenceError(f"capture has non-global provider address: {address}")
    records = capture["captures"]
    if not isinstance(records, list) or len(records) != len(expanded):
        raise EvidenceError("capture record count differs from expanded manifest")
    bindings = {"run_nonce": nonce}
    prior_requests: dict[str, dict[str, Any]] = {}
    prior_bodies: dict[str, bytes] = {}
    total_provider_bytes = preflight["response"]["provider_body_bytes"]
    program_counts = {identifier: 0 for identifier in READY_PROGRAM_IDS}
    for entry, record in zip(expanded, records, strict=True):
        step = entry["step"]
        step_id = step["id"]
        item = require_exact_keys(
            record,
            {
                "sequence_index",
                "program_id",
                "step_id",
                "phase",
                "fixture",
                "operation_id",
                "request",
                "response",
            },
            label=f"capture record {entry['sequence_index']}",
        )
        if (
            item["sequence_index"] != entry["sequence_index"]
            or item["program_id"] != entry["program_id"]
            or item["step_id"] != step_id
            or item["phase"] != step["phase"]
            or item["fixture"] is not entry["fixture"]
            or item["operation_id"] != step["_operation"]
        ):
            raise EvidenceError(f"capture record {entry['sequence_index']} identity differs")
        expected = expected_request(
            step,
            bindings=bindings,
            prior_requests=prior_requests,
        )
        if item["request"] != expected:
            raise EvidenceError(f"{step_id} request differs from reviewed manifest")
        parsed, body = validate_response(
            item["response"],
            expect=step["expect"],
            bindings=bindings,
            prior_bodies=prior_bodies,
            step_id=step_id,
        )
        for capture_spec in step.get("capture", []):
            captured = path_value(parsed, capture_spec["path"], label=step_id)
            if (
                not isinstance(captured, str)
                or re.fullmatch(capture_spec["pattern"], captured, re.ASCII) is None
            ):
                raise EvidenceError(f"{step_id} captured binding shape differs")
            bindings[capture_spec["binding"]] = captured
        prior_requests[step_id] = expected
        prior_bodies[step_id] = body
        total_provider_bytes += item["response"]["provider_body_bytes"]
        program_counts[entry["program_id"]] += 1
    if total_provider_bytes != capture["total_provider_response_bytes"]:
        raise EvidenceError("capture total_provider_response_bytes differs")
    if total_provider_bytes > MAX_TOTAL_RESPONSE_BYTES:
        raise EvidenceError("capture total provider response bytes exceeds cap")
    expected_results = [
        {
            "program_id": identifier,
            "capture_count": program_counts[identifier],
            "complete": True,
        }
        for identifier in READY_PROGRAM_IDS
    ]
    if capture["program_results"] != expected_results:
        raise EvidenceError("capture program_results differ")
    return capture


def report(
    *,
    require_capture_ready_complete: bool,
    require_all_behavior_complete: bool,
    expected_account_id: str | None = None,
) -> dict:
    manifest, expanded, _pins = validate_manifest()
    capture_present = CAPTURE_PATH.exists()
    capture_valid = False
    if capture_present:
        validate_capture(
            manifest,
            expanded,
            expected_account_id=expected_account_id,
        )
        capture_valid = True
    catalog = manifest["complete_behavior_program_catalog"]
    deferred = [
        item["id"]
        for item in catalog
        if item["capture_status"] != "capture_manifest_ready"
        or "remaining_missing_prerequisite" in item
    ]
    missing_programs = deferred if capture_valid else [item["id"] for item in catalog]
    coverage = load_json(CORE_COVERAGE_PATH)
    declared_writes = sorted(
        item["id"] for item in coverage["operations"] if item["effect"] == "write"
    )
    provider_observed_write_operations: list[str] = []
    if capture_valid:
        provider_observed_write_operations = sorted(
            {
                entry["step"]["_operation"]
                for entry in expanded
                if entry["step"].get("method") in WRITE_METHODS
                and 200 in entry["step"]["expect"]["statuses"]
            }
        )
    missing_write_operations = sorted(
        set(declared_writes) - set(provider_observed_write_operations)
    )
    result = {
        "schema_version": "datalox_stripe_transition_evidence_report_v1",
        "provider_id": "stripe",
        "environment_id": "stripe_billing_ops_v0",
        "construction_valid": True,
        "provider_requests_sent_by_check": False,
        "runtime_live_write_enabled": False,
        "declared_core_family_count": 8,
        "declared_write_operation_count": 38,
        "complete_behavior_program_count": 22,
        "authoring_candidate_program_count": len(AUTHORING_CANDIDATE_PROGRAM_IDS),
        "capture_ready_program_count": len(READY_PROGRAM_IDS),
        "expanded_capture_step_count": len(expanded),
        "capture_artifact_present": capture_present,
        "capture_artifact_valid": capture_valid,
        "capture_ready_complete": capture_valid,
        "full_behavioral_complete": capture_valid and not missing_programs,
        "provider_observed_write_operations": provider_observed_write_operations,
        "missing_provider_observed_write_operations": missing_write_operations,
        "missing_behavior_programs": missing_programs,
        "known_behavior_gaps": [item["id"] for item in manifest["known_behavior_gaps"]],
        "supporting_provider_objects": [
            item["id"] for item in manifest["supporting_provider_objects"]
        ],
        "known_local_behavior_mismatches": [
            item["id"] for item in manifest["known_local_behavior_mismatches"]
        ],
        "require_capture_ready_complete": require_capture_ready_complete,
        "require_all_behavior_complete": require_all_behavior_complete,
        "expected_account_id_supplied_for_capture_validation": (expected_account_id is not None),
    }
    if require_capture_ready_complete and not result["capture_ready_complete"]:
        raise EvidenceError("reviewed capture-ready Stripe transition evidence is incomplete")
    if require_all_behavior_complete and not result["full_behavioral_complete"]:
        raise EvidenceError("full Stripe behavioral evidence remains incomplete")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline", action="store_true", help="Accepted for explicitness; always offline."
    )
    parser.add_argument("--require-capture-ready-complete", action="store_true")
    parser.add_argument("--require-all-behavior-complete", action="store_true")
    parser.add_argument("--expected-account-id")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    try:
        result = report(
            require_capture_ready_complete=arguments.require_capture_ready_complete,
            require_all_behavior_complete=arguments.require_all_behavior_complete,
            expected_account_id=arguments.expected_account_id,
        )
    except EvidenceError as error:
        failure = {
            "schema_version": "datalox_stripe_transition_evidence_report_v1",
            "provider_id": "stripe",
            "construction_valid": False,
            "code": "stripe_transition_evidence_invalid_or_incomplete",
            "detail": str(error),
            "provider_requests_sent_by_check": False,
            "runtime_live_write_enabled": False,
        }
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
