from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qsl

from datalox_gated_runtime.engineering_proof import (
    EngineeringProofContractError,
    GeneratedIdBinding,
    PathPrefixMapping,
    PrincipalMapping,
    ProofOutputBuilder,
    WorldTargetSpec,
    reference_trace_program,
    run_engineering_proof,
)
from datalox_gated_runtime.reference.contracts import (
    ObservationRequest,
    ObservedResponse,
    ReferenceStep,
    ReferenceTrace,
    ReferenceCall,
)
from datalox_gated_runtime.world_v1.interop import export_world_interop

PROGRAM_ID = "idempotency_parameter_conflict"
EPISODE_ID = "stripe-one-off-invoicing-001"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class StripeEngineeringProofError(ValueError):
    """The reviewed Stripe proof input or one proof stage failed closed."""


class StripeProjectionProfile:
    """Compare exactly the response fields asserted by the reviewed capture program."""

    profile_id = "stripe_idempotency_parameter_conflict_v1"

    def __init__(self, projections: dict[str, dict[str, Any]]) -> None:
        self.projections = projections

    def normalize_response(
        self, *, step: ReferenceStep, response: ObservedResponse
    ) -> ObservedResponse:
        projection = self.projections[step.step_id]
        body = response.body
        selected: dict[str, Any]
        if projection["kind"] == "error":
            selected = {"error": {"type": _at(body, ("error", "type"))}}
        else:
            selected = {
                "id": "$customer_id",
                "object": _at(body, ("object",)),
                "livemode": _at(body, ("livemode",)),
            }
            for path in projection["field_paths"]:
                _assign(selected, path, _at(body, path))
        return ObservedResponse(status_code=response.status_code, body=selected, headers={})

    def normalize_observation(self, *, request: ObservationRequest, value: Any) -> Any:
        return value


def validate_and_compile_capture(
    *,
    repo_root: Path,
    capture_path: Path,
    expected_capture_sha256: str,
    expected_account_id: str,
) -> tuple[ReferenceTrace, StripeProjectionProfile, dict[str, Any]]:
    if _DIGEST.fullmatch(expected_capture_sha256) is None:
        raise StripeEngineeringProofError(
            "expected capture digest must be sha256:<64 lowercase hexadecimal characters>"
        )
    if not capture_path.is_file():
        raise StripeEngineeringProofError(f"reviewed Stripe capture is missing: {capture_path}")
    actual_digest = _sha256(capture_path)
    if actual_digest != expected_capture_sha256:
        raise StripeEngineeringProofError(
            f"reviewed Stripe capture digest differs: {actual_digest}"
        )

    checker = _load_checker(repo_root)
    checker.CAPTURE_PATH = capture_path.resolve()
    try:
        manifest, expanded, _pins = checker.validate_manifest()
        capture = checker.validate_capture(
            manifest,
            expanded,
            expected_account_id=expected_account_id,
        )
    except checker.EvidenceError as error:
        raise StripeEngineeringProofError(
            f"reviewed Stripe capture validation failed: {error}"
        ) from error
    records = [record for record in capture["captures"] if record["program_id"] == PROGRAM_ID]
    specs = {
        entry["step"]["id"]: entry["step"]
        for entry in expanded
        if entry["program_id"] == PROGRAM_ID
    }
    if len(records) != 4 or set(specs) != {record["step_id"] for record in records}:
        raise StripeEngineeringProofError(
            "reviewed Stripe proof program is not the four-step slice"
        )

    provider_customer_id: str | None = None
    steps: list[ReferenceStep] = []
    projections: dict[str, dict[str, Any]] = {}
    for record in records:
        step_id = record["step_id"]
        spec = specs[step_id]
        response_body = _decode_json_body(record["response"]["body_base64"])
        if provider_customer_id is None and isinstance(response_body, dict):
            candidate = response_body.get("id")
            if isinstance(candidate, str) and candidate.startswith("cus_"):
                provider_customer_id = candidate
        request = record["request"]
        body = _decode_form(request["request_body_base64"])
        headers = {}
        if request.get("idempotency_key") is not None:
            headers["idempotency-key"] = request["idempotency_key"]
        steps.append(
            ReferenceStep(
                step_id=step_id,
                principal_context_id="stripe_test_account",
                call=ReferenceCall(
                    method=request["method"],
                    path=request["path"],
                    query=dict(request["query"]),
                    body=body,
                    headers=headers,
                    operation_id=record["operation_id"],
                ),
                expected_response=ObservedResponse(
                    status_code=record["response"]["status"],
                    body=response_body,
                    headers={},
                ),
            )
        )
        expect = spec["expect"]
        if "error_type" in expect:
            projections[step_id] = {"kind": "error"}
        else:
            projections[step_id] = {
                "kind": "customer",
                "field_paths": tuple(
                    tuple(item["path"]) for item in expect.get("field_equals", [])
                ),
            }
    if provider_customer_id is None:
        raise StripeEngineeringProofError("reviewed capture did not bind a Stripe customer ID")
    trace = ReferenceTrace(
        provider_id="stripe",
        provider_version=manifest["stripe_version"],
        seed=1,
        initial_observations=(),
        steps=tuple(steps),
        evidence_refs=(expected_capture_sha256,),
        metadata={"program_id": PROGRAM_ID, "capture_step_count": len(steps)},
    )
    return (
        trace,
        StripeProjectionProfile(projections),
        {
            "capture_sha256": actual_digest,
            "provider_customer_id": provider_customer_id,
            "step_count": len(steps),
        },
    )


def run_stripe_engineering_proof(
    *,
    repo_root: Path,
    env_dir: Path,
    capture_path: Path,
    expected_capture_sha256: str,
    expected_account_id: str,
    out_dir: Path,
) -> dict[str, Any]:
    trace, profile, compilation = validate_and_compile_capture(
        repo_root=repo_root,
        capture_path=capture_path,
        expected_capture_sha256=expected_capture_sha256,
        expected_account_id=expected_account_id,
    )
    program = reference_trace_program(
        program_id=PROGRAM_ID,
        program_version="1",
        trace=trace,
        profile=profile,
    )
    target_spec = WorldTargetSpec(
        target_id="stripe_billing_ops_world",
        target_version="v1",
        episode_id=EPISODE_ID,
        principal_mappings=(
            PrincipalMapping("stripe_test_account", "stripe-proof", "billing_operator"),
        ),
        path_mappings=(PathPrefixMapping("/v1", "/stripe/v1"),),
        generated_id_bindings=(
            GeneratedIdBinding(
                binding_id="customer_id",
                producer_operation_id="stripe.post_customers",
                response_pointer="/id",
            ),
        ),
    )

    def export(format: str, destination: Path) -> dict[str, Any]:
        return _portable_export_result(
            export_world_interop(
                env_dir=env_dir,
                out_dir=destination,
                format=format,
            )
        )

    try:
        return run_engineering_proof(
            program=program,
            target_spec=target_spec,
            env_dir=env_dir,
            out_dir=out_dir,
            reference_bindings={"customer_id": compilation["provider_customer_id"]},
            exporters=(
                ProofOutputBuilder("harbor", lambda path: export("harbor", path)),
                ProofOutputBuilder("hud", lambda path: export("hud", path)),
            ),
            packagers=(ProofOutputBuilder("oci", lambda path: export("oci", path)),),
        )
    except EngineeringProofContractError as error:
        raise StripeEngineeringProofError(str(error)) from error


def _load_checker(repo_root: Path) -> ModuleType:
    path = repo_root / "scripts" / "providers" / "check-stripe-testmode-transition-evidence.py"
    spec = importlib.util.spec_from_file_location("datalox_stripe_evidence_checker", path)
    if spec is None or spec.loader is None:
        raise StripeEngineeringProofError(f"could not load Stripe evidence checker: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _decode_json_body(encoded: str) -> Any:
    return json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))


def _decode_form(encoded: str) -> dict[str, Any] | None:
    raw = base64.b64decode(encoded, validate=True)
    if not raw:
        return None
    result: dict[str, Any] = {}
    for key, value in parse_qsl(raw.decode("ascii"), keep_blank_values=True, strict_parsing=True):
        match = re.fullmatch(r"([A-Za-z0-9_]+)\[([A-Za-z0-9_]+)\]", key)
        if match is None:
            if key in result:
                raise StripeEngineeringProofError(f"duplicate flat Stripe form field: {key}")
            result[key] = value
            continue
        parent, child = match.groups()
        nested = result.setdefault(parent, {})
        if not isinstance(nested, dict) or child in nested:
            raise StripeEngineeringProofError(f"duplicate nested Stripe form field: {key}")
        nested[child] = value
    return result


def _at(value: Any, path: tuple[str, ...]) -> Any:
    current = value
    for component in path:
        if not isinstance(current, Mapping) or component not in current:
            raise StripeEngineeringProofError(
                f"response is missing projected field: {'.'.join(path)}"
            )
        current = current[component]
    return current


def _assign(target: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    if path == ("id",):
        return
    current = target
    for component in path[:-1]:
        child = current.setdefault(component, {})
        if not isinstance(child, dict):
            raise StripeEngineeringProofError(f"overlapping projection path: {'.'.join(path)}")
        current = child
    current[path[-1]] = value


def _portable_export_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "out_dir"}


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
