"""Executable admission for task-free provider runtime bundles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any, Mapping

from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import CallRequest, GateResponse
from datalox_gated_runtime.provider_runtime.bundle import (
    GateConfigBehaviorSpec,
    WorldV1BehaviorSpec,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.provider_runtime.runtime import ProviderRuntime

OPERATION_CLAIMS_SCHEMA_VERSION = "datalox_provider_operation_claims_v1"
PROVIDER_ADMISSION_SCHEMA_VERSION = "datalox_provider_admission_v1"
PROVIDER_ADMISSION_FILENAME = "provider-admission.json"

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "provider_id",
        "bundle_version",
        "evidence_sources",
        "operations",
        "provider_invariants",
        "receipt_predicates",
        "reset_profiles",
        "behavior_probes",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "evidence_id",
        "artifact_ref",
        "artifact_sha256",
        "grounding_level",
        "observed_at",
        "valid_through",
        "distribution_label",
        "rights_basis",
    }
)
_OPERATION_FIELDS = frozenset(
    {
        "operation_id",
        "native_surface",
        "mutability",
        "behavior_program",
        "state_effects",
        "grounding",
        "rights",
        "covered_behaviors",
    }
)
_SURFACE_FIELDS = frozenset({"type", "scheme", "authority", "method", "path_template"})
_GROUNDING_FIELDS = frozenset({"level", "evidence_refs"})
_RIGHTS_FIELDS = frozenset({"distribution_label", "behavior_distribution_basis"})
_RESET_PROFILE_FIELDS = frozenset({"profile_id", "kind"})
_PROBE_FIELDS = frozenset({"probe_id", "reset_profile", "steps"})
_STEP_REQUIRED_FIELDS = frozenset(
    {
        "step_id",
        "operation_id",
        "request",
        "expected_status_code",
        "covers",
        "receipt_predicate_refs",
    }
)
_STEP_OPTIONAL_FIELDS = frozenset({"expected_decision_kind"})
_REQUEST_FIELDS = frozenset({"scheme", "authority", "method", "path", "query", "headers", "body"})
_COVER_FIELDS = frozenset({"operation_id", "behavior"})
_PREDICATE_COMMON_FIELDS = frozenset({"predicate_id", "source", "operator", "pointer"})
_BEHAVIORS = frozenset({"success", "failure", "duplicate", "readback", "async", "pagination"})
_DECISION_KINDS = frozenset({"replay", "shadow_read", "shadow_write", "deny", "miss"})
_DISTRIBUTION_ORDER = {"public": 0, "restricted": 1, "private": 2}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_GROUNDING_LEVEL = re.compile(r"^G([0-4])(?:_[A-Z0-9]+)*$")
_PATH_PARAMETER = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")


@dataclass(frozen=True)
class ProviderAdmissionResult:
    path: Path
    sha256: str
    payload: dict[str, Any]


def admit_provider_runtime(
    *,
    bundle_dir: Path,
    claims_path: Path,
    output_path: Path,
    admitted_at: datetime | None = None,
) -> ProviderAdmissionResult:
    """Validate claims against one runtime and write a successful derived admission."""

    if output_path.exists() or output_path.is_symlink():
        raise ProviderRuntimeError(
            "provider_admission_output_exists",
            "Provider admission output already exists.",
            {"path": str(output_path)},
        )
    bundle = load_provider_runtime_bundle(bundle_dir)
    claims_file = _resolve_regular_file(claims_path, code="provider_admission_claims_unreadable")
    claims = _load_json_object(claims_file, code="provider_admission_claims_invalid")
    _require_fields(claims, _TOP_LEVEL_FIELDS, name="operation claims")
    if claims["schema_version"] != OPERATION_CLAIMS_SCHEMA_VERSION:
        _fail(
            "provider_admission_claims_schema_unsupported", "Unsupported operation claims schema."
        )
    if claims["provider_id"] != bundle.manifest.provider_id:
        _fail(
            "provider_admission_provider_mismatch", "Claims provider_id does not match the bundle."
        )
    if claims["bundle_version"] != bundle.manifest.bundle_version:
        _fail(
            "provider_admission_version_mismatch",
            "Claims bundle_version does not match the bundle.",
        )

    if admitted_at is not None and admitted_at.tzinfo is None:
        _fail(
            "provider_admission_timestamp_invalid",
            "admitted_at must include an explicit UTC offset.",
        )
    now = (admitted_at or datetime.now(UTC)).astimezone(UTC)
    evidence = _validate_evidence(claims["evidence_sources"], claims_file.parent, now=now)
    predicates = _validate_predicates(
        claims["provider_invariants"],
        name="provider_invariants",
        allow_response=False,
    )
    receipts = _validate_predicates(
        claims["receipt_predicates"],
        name="receipt_predicates",
        allow_response=True,
    )
    operations = _validate_operations(
        claims["operations"],
        authorities=bundle.manifest.authorities,
        evidence=evidence,
    )
    reset_profiles = _validate_reset_profiles(claims["reset_profiles"])
    probes = _validate_probes(
        claims["behavior_probes"],
        operations=operations,
        receipt_predicates=receipts,
    )
    _require_complete_coverage(operations, probes)

    probe_results = _run_functional_reset_checks(
        bundle_dir=bundle.root,
        bundle_behavior=bundle.manifest.behavior,
        probes=probes,
        operations=operations,
        provider_invariants=predicates,
        receipt_predicates=receipts,
    )
    referenced_evidence = {
        evidence_ref
        for operation in operations.values()
        for evidence_ref in operation["grounding"]["evidence_refs"]
    }
    if referenced_evidence != set(evidence):
        _fail(
            "provider_admission_evidence_reference_incomplete",
            "Every declared evidence source must be referenced by an operation.",
            unused=sorted(set(evidence) - referenced_evidence),
        )

    operation_results = []
    for operation in operations.values():
        refs = operation["grounding"]["evidence_refs"]
        labels = [evidence[ref]["distribution_label"] for ref in refs]
        labels.append(operation["rights"]["distribution_label"])
        distribution = max(labels, key=_DISTRIBUTION_ORDER.__getitem__)
        level = operation["grounding"]["level"]
        operation_results.append(
            {
                "operation_id": operation["operation_id"],
                "native_surface": deepcopy(operation["native_surface"]),
                "mutability": operation["mutability"],
                "behavior_program": operation["behavior_program"],
                "state_effects": list(operation["state_effects"]),
                "grounding": {
                    "level": level,
                    "evidence_refs": list(refs),
                    "grounded": _grounding_rank(level) >= 2,
                },
                "rights": {
                    "distribution_label": distribution,
                    "behavior_distribution_basis": operation["rights"][
                        "behavior_distribution_basis"
                    ],
                },
                "covered_behaviors": {
                    behavior: True for behavior in sorted(operation["covered_behaviors"])
                },
            }
        )

    payload = {
        "schema_version": PROVIDER_ADMISSION_SCHEMA_VERSION,
        "provider_id": bundle.manifest.provider_id,
        "bundle_version": bundle.manifest.bundle_version,
        "provider_runtime_sha256": _sha256_file(bundle.root / "provider-runtime.json"),
        "operation_claims_sha256": _sha256_file(claims_file),
        "admitted": True,
        "task_free": True,
        "evidence_sources": [deepcopy(source) for source in evidence.values()],
        "operations": operation_results,
        "provider_invariants": [
            {**deepcopy(predicate), "passed": True} for predicate in predicates.values()
        ],
        "receipt_predicates": [
            {**deepcopy(predicate), "passed": True} for predicate in receipts.values()
        ],
        "reset_profiles": [
            {
                "profile_id": profile["profile_id"],
                "kind": profile["kind"],
                "functional_equivalence_passed": True,
            }
            for profile in reset_profiles
        ],
        "behavior_probes": probe_results,
    }
    _write_json_atomic(output_path, payload)
    return ProviderAdmissionResult(
        path=output_path.resolve(strict=True),
        sha256=_sha256_file(output_path),
        payload=payload,
    )


def load_provider_admission(path: Path) -> dict[str, Any]:
    """Strictly load a successful admission artifact."""

    raw = _load_json_object(
        _resolve_regular_file(path, code="provider_admission_unreadable"),
        code="provider_admission_invalid",
    )
    expected = {
        "schema_version",
        "provider_id",
        "bundle_version",
        "provider_runtime_sha256",
        "operation_claims_sha256",
        "admitted",
        "task_free",
        "evidence_sources",
        "operations",
        "provider_invariants",
        "receipt_predicates",
        "reset_profiles",
        "behavior_probes",
    }
    _require_fields(raw, frozenset(expected), name="provider admission")
    if raw["schema_version"] != PROVIDER_ADMISSION_SCHEMA_VERSION:
        _fail("provider_admission_schema_unsupported", "Unsupported provider admission schema.")
    if raw["admitted"] is not True or raw["task_free"] is not True:
        _fail("provider_admission_invalid", "Provider admission must be successful and task-free.")
    for field in ("provider_runtime_sha256", "operation_claims_sha256"):
        _sha256_value(raw[field], field=field)
    _identifier(raw["provider_id"], field="provider_id")
    if not isinstance(raw["bundle_version"], str) or not raw["bundle_version"].strip():
        _fail("provider_admission_invalid", "Provider admission bundle_version is invalid.")
    evidence = _validate_admitted_evidence_metadata(raw["evidence_sources"])
    _validate_admitted_operations(raw["operations"], evidence=evidence)
    referenced_evidence = {
        evidence_ref
        for operation in raw["operations"]
        for evidence_ref in operation["grounding"]["evidence_refs"]
    }
    if referenced_evidence != set(evidence):
        _fail("provider_admission_invalid", "Provider admission evidence is not fully referenced.")
    _validate_admitted_predicates(
        raw["provider_invariants"], field="provider_invariants", allow_response=False
    )
    _validate_admitted_predicates(
        raw["receipt_predicates"], field="receipt_predicates", allow_response=True
    )
    _validate_admitted_reset_profiles(raw["reset_profiles"])
    _validate_admitted_probe_results(raw["behavior_probes"])
    return raw


def _validate_admitted_evidence_metadata(raw: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, list):
        _fail("provider_admission_invalid", "Provider admission evidence_sources is invalid.")
    result: dict[str, dict[str, Any]] = {}
    for index, source in enumerate(raw):
        _require_fields(source, _EVIDENCE_FIELDS, name=f"admission evidence_sources[{index}]")
        evidence_id = _identifier(source["evidence_id"], field="evidence_id")
        if evidence_id in result:
            _fail("provider_admission_invalid", "Provider admission evidence ids must be unique.")
        _relative_path(source["artifact_ref"], field="artifact_ref")
        _sha256_value(source["artifact_sha256"], field="artifact_sha256")
        _grounding(source["grounding_level"])
        observed = _timestamp(source["observed_at"], field="observed_at")
        valid_through = _timestamp(source["valid_through"], field="valid_through")
        if observed > valid_through:
            _fail("provider_admission_invalid", "Provider admission evidence dates are invalid.")
        if source["distribution_label"] not in _DISTRIBUTION_ORDER:
            _fail("provider_admission_invalid", "Provider admission evidence rights are invalid.")
        if not isinstance(source["rights_basis"], str) or not source["rights_basis"].strip():
            _fail("provider_admission_invalid", "Provider admission rights_basis is invalid.")
        result[evidence_id] = source
    return result


def _validate_admitted_operations(raw: Any, *, evidence: Mapping[str, Mapping[str, Any]]) -> None:
    fields = frozenset(
        {
            "operation_id",
            "native_surface",
            "mutability",
            "behavior_program",
            "state_effects",
            "grounding",
            "rights",
            "covered_behaviors",
        }
    )
    if not isinstance(raw, list) or not raw:
        _fail("provider_admission_invalid", "Provider admission operations must be non-empty.")
    operation_ids: set[str] = set()
    surfaces: list[tuple[str, Mapping[str, Any]]] = []
    for index, operation in enumerate(raw):
        _require_fields(operation, fields, name=f"admission operations[{index}]")
        operation_id = _identifier(operation["operation_id"], field="operation_id")
        if operation_id in operation_ids:
            _fail("provider_admission_invalid", "Provider admission operation ids must be unique.")
        operation_ids.add(operation_id)
        surface = operation["native_surface"]
        _require_fields(surface, _SURFACE_FIELDS, name=f"admission operations[{index}].surface")
        if surface["type"] != "http" or surface["scheme"] != "https":
            _fail("provider_admission_invalid", "Provider admission surface is invalid.")
        if not isinstance(surface["authority"], str) or not surface["authority"]:
            _fail("provider_admission_invalid", "Provider admission authority is invalid.")
        _http_method(surface["method"])
        _path_template(surface["path_template"])
        surfaces.append((operation_id, surface))
        if operation["mutability"] not in {"read", "write"}:
            _fail("provider_admission_invalid", "Provider admission mutability is invalid.")
        _identifier(operation["behavior_program"], field="behavior_program")
        _unique_identifiers(operation["state_effects"], field="state_effects")
        grounding = operation["grounding"]
        _require_fields(
            grounding,
            frozenset({"level", "evidence_refs", "grounded"}),
            name=f"admission operations[{index}].grounding",
        )
        level = _grounding(grounding["level"])
        refs = _unique_identifiers(grounding["evidence_refs"], field="evidence_refs")
        if set(refs) - set(evidence):
            _fail("provider_admission_invalid", "Provider admission cites unknown evidence.")
        if grounding["grounded"] is not (_grounding_rank(level) >= 2):
            _fail("provider_admission_invalid", "Derived grounding result is inconsistent.")
        if refs and max(
            _grounding_rank(evidence[ref]["grounding_level"]) for ref in refs
        ) < _grounding_rank(level):
            _fail("provider_admission_invalid", "Provider admission grounding is overstated.")
        rights = operation["rights"]
        _require_fields(rights, _RIGHTS_FIELDS, name=f"admission operations[{index}].rights")
        if (
            rights["distribution_label"] not in _DISTRIBUTION_ORDER
            or not isinstance(rights["behavior_distribution_basis"], str)
            or not rights["behavior_distribution_basis"].strip()
        ):
            _fail("provider_admission_invalid", "Provider admission rights are invalid.")
        labels = [evidence[ref]["distribution_label"] for ref in refs]
        if labels and _DISTRIBUTION_ORDER[rights["distribution_label"]] < max(
            _DISTRIBUTION_ORDER[label] for label in labels
        ):
            _fail("provider_admission_invalid", "Provider admission distribution is overstated.")
        covered = operation["covered_behaviors"]
        if (
            not isinstance(covered, dict)
            or not covered
            or set(covered) - _BEHAVIORS
            or any(value is not True for value in covered.values())
        ):
            _fail("provider_admission_invalid", "Derived behavior coverage is invalid.")
    _reject_ambiguous_operation_surfaces(surfaces, code="provider_admission_surface_ambiguous")


def _validate_admitted_predicates(raw: Any, *, field: str, allow_response: bool) -> None:
    if not isinstance(raw, list) or not raw:
        _fail("provider_admission_invalid", f"{field} must be a non-empty predicate list.")
    definitions = []
    for index, predicate in enumerate(raw):
        if not isinstance(predicate, dict) or predicate.get("passed") is not True:
            _fail("provider_admission_invalid", f"{field}[{index}] did not pass.")
        definition = {key: deepcopy(value) for key, value in predicate.items() if key != "passed"}
        definitions.append(definition)
    _validate_predicates(definitions, name=field, allow_response=allow_response)


def _validate_admitted_reset_profiles(raw: Any) -> None:
    expected = {
        "profile_id": "default",
        "kind": "compiled_seed",
        "functional_equivalence_passed": True,
    }
    if raw != [expected]:
        _fail("provider_admission_invalid", "Provider admission reset profile is invalid.")


def _validate_admitted_probe_results(raw: Any) -> None:
    fields = frozenset({"probe_id", "step_count", "first_run_sha256", "second_run_sha256"})
    if not isinstance(raw, list) or not raw:
        _fail("provider_admission_invalid", "Provider admission probes must be non-empty.")
    probe_ids: set[str] = set()
    for index, probe in enumerate(raw):
        _require_fields(probe, fields, name=f"admission behavior_probes[{index}]")
        probe_id = _identifier(probe["probe_id"], field="probe_id")
        if probe_id in probe_ids:
            _fail("provider_admission_invalid", "Provider admission probe ids must be unique.")
        probe_ids.add(probe_id)
        if (
            not isinstance(probe["step_count"], int)
            or isinstance(probe["step_count"], bool)
            or probe["step_count"] < 1
        ):
            _fail("provider_admission_invalid", "Provider admission step_count is invalid.")
        first = _sha256_value(probe["first_run_sha256"], field="first_run_sha256")
        second = _sha256_value(probe["second_run_sha256"], field="second_run_sha256")
        if first != second:
            _fail("provider_admission_invalid", "Provider admission reset digests differ.")


def _validate_evidence(raw: Any, root: Path, *, now: datetime) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, list):
        _fail("provider_admission_evidence_invalid", "evidence_sources must be a list.")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw):
        _require_fields(item, _EVIDENCE_FIELDS, name=f"evidence_sources[{index}]")
        evidence_id = _identifier(item["evidence_id"], field="evidence_id")
        if evidence_id in result:
            _fail("provider_admission_evidence_duplicate", "Evidence ids must be unique.")
        level = _grounding(item["grounding_level"])
        observed = _timestamp(item["observed_at"], field="observed_at")
        valid_through = _timestamp(item["valid_through"], field="valid_through")
        if observed > valid_through:
            _fail("provider_admission_evidence_dates_invalid", "observed_at follows valid_through.")
        if now > valid_through:
            _fail(
                "provider_admission_evidence_stale",
                f"Evidence {evidence_id!r} is past its declared validity boundary.",
            )
        label = item["distribution_label"]
        if label not in _DISTRIBUTION_ORDER:
            _fail("provider_admission_evidence_invalid", "Unknown distribution label.")
        if not isinstance(item["rights_basis"], str) or not item["rights_basis"].strip():
            _fail("provider_admission_evidence_invalid", "rights_basis must be non-empty.")
        relative = _relative_path(item["artifact_ref"], field="artifact_ref")
        artifact = _resolve_descendant_file(root, relative)
        expected_digest = _sha256_value(item["artifact_sha256"], field="artifact_sha256")
        actual_digest = _sha256_file(artifact)
        if actual_digest != expected_digest:
            _fail(
                "provider_admission_evidence_digest_mismatch",
                f"Evidence digest does not match for {evidence_id!r}.",
                expected=expected_digest,
                actual=actual_digest,
            )
        result[evidence_id] = {**deepcopy(item), "grounding_level": level}
    return result


def _validate_operations(
    raw: Any,
    *,
    authorities: tuple[str, ...],
    evidence: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        _fail("provider_admission_operations_invalid", "operations must be a non-empty list.")
    operations: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw):
        _require_fields(item, _OPERATION_FIELDS, name=f"operations[{index}]")
        operation_id = _identifier(item["operation_id"], field="operation_id")
        if operation_id in operations:
            _fail("provider_admission_operation_duplicate", "Operation ids must be unique.")
        surface = item["native_surface"]
        _require_fields(surface, _SURFACE_FIELDS, name=f"operations[{index}].native_surface")
        if surface["type"] != "http" or surface["scheme"] != "https":
            _fail("provider_admission_surface_invalid", "Only native HTTPS surfaces are supported.")
        if surface["authority"] not in authorities:
            _fail(
                "provider_admission_authority_unknown",
                f"Operation {operation_id!r} uses an undeclared provider authority.",
            )
        _http_method(surface["method"])
        _path_template(surface["path_template"])
        if item["mutability"] not in {"read", "write"}:
            _fail("provider_admission_mutability_invalid", "mutability must be read or write.")
        _identifier(item["behavior_program"], field="behavior_program")
        state_effects = _unique_identifiers(item["state_effects"], field="state_effects")
        if item["mutability"] == "write" and not state_effects:
            _fail(
                "provider_admission_state_effects_missing",
                f"Write operation {operation_id!r} must declare observable state effects.",
            )
        grounding = item["grounding"]
        _require_fields(grounding, _GROUNDING_FIELDS, name=f"operations[{index}].grounding")
        level = _grounding(grounding["level"])
        refs = _unique_identifiers(grounding["evidence_refs"], field="evidence_refs")
        unknown_refs = set(refs) - set(evidence)
        if unknown_refs:
            _fail(
                "provider_admission_evidence_unknown",
                f"Operation {operation_id!r} references unknown evidence.",
                evidence_refs=sorted(unknown_refs),
            )
        rank = _grounding_rank(level)
        if rank == 0 and refs:
            _fail("provider_admission_grounding_invalid", "G0 operations may not cite evidence.")
        if rank > 0 and not refs:
            _fail("provider_admission_grounding_invalid", "Grounded operations require evidence.")
        if refs and max(_grounding_rank(evidence[ref]["grounding_level"]) for ref in refs) < rank:
            _fail(
                "provider_admission_grounding_overstated",
                f"Evidence does not support operation {operation_id!r} at {level}.",
            )
        rights = item["rights"]
        _require_fields(rights, _RIGHTS_FIELDS, name=f"operations[{index}].rights")
        if rights["distribution_label"] not in _DISTRIBUTION_ORDER:
            _fail("provider_admission_rights_invalid", "Operation distribution label is invalid.")
        if (
            not isinstance(rights["behavior_distribution_basis"], str)
            or not rights["behavior_distribution_basis"].strip()
        ):
            _fail(
                "provider_admission_rights_invalid",
                "behavior_distribution_basis must be non-empty.",
            )
        behaviors = _behaviors(item["covered_behaviors"])
        required = {"success", "failure"}
        if item["mutability"] == "write":
            required |= {"duplicate", "readback"}
        if not required.issubset(behaviors):
            _fail(
                "provider_admission_core_behavior_missing",
                f"Operation {operation_id!r} omits required core behavior coverage.",
                missing=sorted(required - set(behaviors)),
            )
        operations[operation_id] = {
            **deepcopy(item),
            "state_effects": state_effects,
            "grounding": {"level": level, "evidence_refs": refs},
            "rights": deepcopy(rights),
            "covered_behaviors": behaviors,
        }
    _reject_ambiguous_operation_surfaces(
        [
            (operation_id, operation["native_surface"])
            for operation_id, operation in operations.items()
        ],
        code="provider_admission_surface_ambiguous",
    )
    return operations


def _validate_reset_profiles(raw: Any) -> tuple[dict[str, str], ...]:
    if not isinstance(raw, list) or len(raw) != 1:
        _fail(
            "provider_admission_reset_profiles_invalid",
            "provider-runtime-v2 admits exactly one compiled default reset profile.",
        )
    profile = raw[0]
    _require_fields(profile, _RESET_PROFILE_FIELDS, name="reset_profiles[0]")
    if profile != {"profile_id": "default", "kind": "compiled_seed"}:
        _fail(
            "provider_admission_reset_profiles_invalid",
            "The only v1 reset profile is default/compiled_seed.",
        )
    return (deepcopy(profile),)


def _validate_predicates(
    raw: Any,
    *,
    name: str,
    allow_response: bool,
) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        _fail("provider_admission_predicates_invalid", f"{name} must be a non-empty list.")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            _fail("provider_admission_predicates_invalid", f"{name}[{index}] must be an object.")
        operator = item.get("operator")
        expected_fields = set(_PREDICATE_COMMON_FIELDS)
        if operator == "equals":
            expected_fields.add("expected")
        elif operator == "type":
            expected_fields.add("expected_type")
        elif operator != "exists":
            _fail("provider_admission_predicates_invalid", "Unknown predicate operator.")
        _require_fields(item, frozenset(expected_fields), name=f"{name}[{index}]")
        predicate_id = _identifier(item["predicate_id"], field="predicate_id")
        if predicate_id in result:
            _fail("provider_admission_predicate_duplicate", f"{name} ids must be unique.")
        sources = {"provider_state", "call_evidence"}
        if allow_response:
            sources.add("response_body")
        if item["source"] not in sources:
            _fail("provider_admission_predicates_invalid", "Predicate source is not allowed here.")
        _json_pointer(item["pointer"])
        if operator == "type" and item["expected_type"] not in {
            "object",
            "array",
            "string",
            "number",
            "integer",
            "boolean",
            "null",
        }:
            _fail("provider_admission_predicates_invalid", "Unknown expected_type.")
        result[predicate_id] = deepcopy(item)
    return result


def _validate_probes(
    raw: Any,
    *,
    operations: Mapping[str, Mapping[str, Any]],
    receipt_predicates: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    if not isinstance(raw, list) or not raw:
        _fail("provider_admission_probes_invalid", "behavior_probes must be non-empty.")
    probes: list[dict[str, Any]] = []
    probe_ids: set[str] = set()
    step_ids: set[str] = set()
    used_receipts: set[str] = set()
    for probe_index, probe in enumerate(raw):
        _require_fields(probe, _PROBE_FIELDS, name=f"behavior_probes[{probe_index}]")
        probe_id = _identifier(probe["probe_id"], field="probe_id")
        if probe_id in probe_ids:
            _fail("provider_admission_probe_duplicate", "Probe ids must be unique.")
        probe_ids.add(probe_id)
        if probe["reset_profile"] != "default":
            _fail("provider_admission_reset_profile_unknown", "Probe reset profile is unknown.")
        raw_steps = probe["steps"]
        if not isinstance(raw_steps, list) or not raw_steps:
            _fail("provider_admission_probe_steps_invalid", "Probe steps must be non-empty.")
        steps: list[dict[str, Any]] = []
        for step_index, step in enumerate(raw_steps):
            fields = set(step) if isinstance(step, dict) else set()
            if (
                not isinstance(step, dict)
                or not _STEP_REQUIRED_FIELDS.issubset(fields)
                or not fields.issubset(_STEP_REQUIRED_FIELDS | _STEP_OPTIONAL_FIELDS)
            ):
                _fail(
                    "provider_admission_probe_step_invalid",
                    f"Probe step fields do not match at index {step_index}.",
                )
            step_id = _identifier(step["step_id"], field="step_id")
            if step_id in step_ids:
                _fail(
                    "provider_admission_probe_step_duplicate", "Step ids must be globally unique."
                )
            step_ids.add(step_id)
            operation_id = step["operation_id"]
            operation = operations.get(operation_id)
            if operation is None:
                _fail("provider_admission_operation_unknown", "Probe references unknown operation.")
            request = _validate_request(step["request"])
            _request_matches_surface(request, operation["native_surface"])
            status = step["expected_status_code"]
            if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
                _fail("provider_admission_probe_step_invalid", "expected_status_code is invalid.")
            decision = step.get("expected_decision_kind")
            if decision is not None and decision not in _DECISION_KINDS:
                _fail("provider_admission_probe_step_invalid", "expected_decision_kind is invalid.")
            covers = step["covers"]
            if not isinstance(covers, list) or not covers:
                _fail("provider_admission_probe_step_invalid", "covers must be non-empty.")
            normalized_covers: list[dict[str, str]] = []
            for cover in covers:
                _require_fields(cover, _COVER_FIELDS, name=f"step {step_id} cover")
                covered_operation = cover["operation_id"]
                behavior = cover["behavior"]
                if covered_operation not in operations or behavior not in _BEHAVIORS:
                    _fail("provider_admission_probe_coverage_invalid", "Probe coverage is invalid.")
                if behavior not in operations[covered_operation]["covered_behaviors"]:
                    _fail(
                        "provider_admission_probe_coverage_invalid",
                        "Probe covers behavior absent from the operation claim.",
                    )
                normalized_covers.append({"operation_id": covered_operation, "behavior": behavior})
            refs = _unique_identifiers(
                step["receipt_predicate_refs"], field="receipt_predicate_refs"
            )
            if not refs:
                _fail(
                    "provider_admission_receipt_missing",
                    "Every probe step needs a receipt predicate.",
                )
            unknown = set(refs) - set(receipt_predicates)
            if unknown:
                _fail(
                    "provider_admission_receipt_unknown",
                    "Probe step references unknown receipt predicates.",
                )
            used_receipts.update(refs)
            steps.append(
                {
                    **deepcopy(step),
                    "request": request,
                    "covers": normalized_covers,
                    "receipt_predicate_refs": refs,
                }
            )
        probes.append({"probe_id": probe_id, "reset_profile": "default", "steps": steps})
    if used_receipts != set(receipt_predicates):
        _fail(
            "provider_admission_receipt_reference_incomplete",
            "Every declared receipt predicate must be exercised.",
            unused=sorted(set(receipt_predicates) - used_receipts),
        )
    _validate_behavior_semantics(tuple(probes), operations=operations)
    return tuple(probes)


def _validate_behavior_semantics(
    probes: tuple[Mapping[str, Any], ...],
    *,
    operations: Mapping[str, Mapping[str, Any]],
) -> None:
    for probe in probes:
        successful_requests: dict[str, list[dict[str, Any]]] = {}
        successful_writes: set[str] = set()
        for step in probe["steps"]:
            executing_operation = step["operation_id"]
            for cover in step["covers"]:
                covered_operation = cover["operation_id"]
                behavior = cover["behavior"]
                if behavior in {"success", "failure", "duplicate", "async", "pagination"}:
                    if executing_operation != covered_operation:
                        _fail(
                            "provider_admission_probe_coverage_invalid",
                            f"{behavior} must execute the operation it covers.",
                        )
                if (
                    behavior == "readback"
                    and operations[executing_operation]["mutability"] != "read"
                ):
                    _fail(
                        "provider_admission_probe_coverage_invalid",
                        "readback coverage must execute a declared read operation.",
                    )
                if behavior == "success":
                    successful_requests.setdefault(covered_operation, []).append(step["request"])
                    if operations[covered_operation]["mutability"] == "write":
                        successful_writes.add(covered_operation)
                elif behavior == "duplicate":
                    if step["request"] not in successful_requests.get(covered_operation, []):
                        _fail(
                            "provider_admission_duplicate_probe_invalid",
                            f"Duplicate coverage for {covered_operation!r} must repeat a preceding success request in the same behavior program.",
                        )
                elif behavior == "readback" and covered_operation not in successful_writes:
                    _fail(
                        "provider_admission_readback_probe_invalid",
                        f"Readback for {covered_operation!r} must follow its successful write in the same behavior program.",
                    )


def _require_complete_coverage(
    operations: Mapping[str, Mapping[str, Any]],
    probes: tuple[Mapping[str, Any], ...],
) -> None:
    observed: dict[str, set[str]] = {operation_id: set() for operation_id in operations}
    for probe in probes:
        for step in probe["steps"]:
            for cover in step["covers"]:
                observed[cover["operation_id"]].add(cover["behavior"])
    for operation_id, operation in operations.items():
        expected = set(operation["covered_behaviors"])
        if observed[operation_id] != expected:
            _fail(
                "provider_admission_probe_coverage_incomplete",
                f"Executable probes do not exactly cover operation {operation_id!r}.",
                missing=sorted(expected - observed[operation_id]),
                undeclared=sorted(observed[operation_id] - expected),
            )


def _run_functional_reset_checks(
    *,
    bundle_dir: Path,
    bundle_behavior: WorldV1BehaviorSpec | GateConfigBehaviorSpec,
    probes: tuple[dict[str, Any], ...],
    operations: Mapping[str, Mapping[str, Any]],
    provider_invariants: Mapping[str, Mapping[str, Any]],
    receipt_predicates: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    results = []
    for probe in probes:
        with TemporaryDirectory(prefix="datalox-provider-admission-") as temporary:
            runtime = ProviderRuntime(bundle_dir=bundle_dir, run_dir=Path(temporary) / "run")
            try:
                initial = runtime.export()
                _evaluate_invariants(provider_invariants, initial)
                first = _run_probe(
                    runtime,
                    probe,
                    bundle_behavior=bundle_behavior,
                    operations=operations,
                    provider_invariants=provider_invariants,
                    receipt_predicates=receipt_predicates,
                )
                reset = runtime.reset()
                if _behavior_state(reset["provider_state"]) != _behavior_state(
                    initial["provider_state"]
                ):
                    _fail(
                        "provider_admission_reset_state_mismatch",
                        f"Reset did not restore initial provider state for {probe['probe_id']!r}.",
                    )
                _evaluate_invariants(provider_invariants, reset)
                second = _run_probe(
                    runtime,
                    probe,
                    bundle_behavior=bundle_behavior,
                    operations=operations,
                    provider_invariants=provider_invariants,
                    receipt_predicates=receipt_predicates,
                )
            finally:
                runtime.close()
        first_digest = canonical_json_sha256(first)
        second_digest = canonical_json_sha256(second)
        if first_digest != second_digest:
            _fail(
                "provider_admission_reset_behavior_mismatch",
                f"Behavior after reset differs for {probe['probe_id']!r}.",
                first=first_digest,
                second=second_digest,
            )
        results.append(
            {
                "probe_id": probe["probe_id"],
                "step_count": len(probe["steps"]),
                "first_run_sha256": first_digest,
                "second_run_sha256": second_digest,
            }
        )
    return results


def _run_probe(
    runtime: ProviderRuntime,
    probe: Mapping[str, Any],
    *,
    bundle_behavior: WorldV1BehaviorSpec | GateConfigBehaviorSpec,
    operations: Mapping[str, Mapping[str, Any]],
    provider_invariants: Mapping[str, Mapping[str, Any]],
    receipt_predicates: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    steps = []
    changed_successful_writes: set[str] = set()
    for step in probe["steps"]:
        before = runtime.export()
        request = step["request"]
        response = runtime.handle(
            CallRequest(
                scheme=request["scheme"],
                authority=request["authority"],
                method=request["method"],
                path=request["path"],
                query=deepcopy(request["query"]),
                headers=deepcopy(request["headers"]),
                body=deepcopy(request["body"]),
            )
        )
        if response.status_code != step["expected_status_code"]:
            _fail(
                "provider_admission_probe_status_mismatch",
                f"Probe step {step['step_id']!r} returned an unexpected status.",
                expected=step["expected_status_code"],
                actual=response.status_code,
            )
        expected_decision = step.get("expected_decision_kind")
        if expected_decision is not None and response.decision.kind != expected_decision:
            _fail(
                "provider_admission_probe_decision_mismatch",
                f"Probe step {step['step_id']!r} returned an unexpected decision.",
            )
        after = runtime.export()
        operation = operations[step["operation_id"]]
        if isinstance(bundle_behavior, WorldV1BehaviorSpec) and response.decision.kind != "deny":
            _verify_world_operation_mapping(after, declared_operation=step["operation_id"])
        for predicate_ref in step["receipt_predicate_refs"]:
            _evaluate_predicate(receipt_predicates[predicate_ref], response=response, export=after)
        _evaluate_invariants(provider_invariants, after)
        before_state = _behavior_state(before["provider_state"])
        after_state = _behavior_state(after["provider_state"])
        if operation["mutability"] == "write" and any(
            cover["operation_id"] == step["operation_id"] and cover["behavior"] == "success"
            for cover in step["covers"]
        ):
            if response.decision.kind != "shadow_write" or before_state == after_state:
                _fail(
                    "provider_admission_write_transition_missing",
                    f"Successful write {step['operation_id']!r} did not change provider state.",
                )
            changed_successful_writes.add(step["operation_id"])
        steps.append(_stable_step_result(step, response, after_state))
    claimed_writes = {
        operation_id
        for operation_id, operation in operations.items()
        if operation["mutability"] == "write"
        and any(
            cover["operation_id"] == operation_id
            for step in probe["steps"]
            for cover in step["covers"]
        )
    }
    missing = claimed_writes - changed_successful_writes
    if missing:
        _fail(
            "provider_admission_write_transition_missing",
            "Probe did not execute a state-changing success for every covered write.",
            operation_ids=sorted(missing),
        )
    return {"probe_id": probe["probe_id"], "steps": steps}


def _stable_step_result(
    step: Mapping[str, Any], response: GateResponse, behavior_state: Any
) -> dict[str, Any]:
    return {
        "step_id": step["step_id"],
        "status_code": response.status_code,
        "body": deepcopy(response.body),
        "headers": {key: response.headers[key] for key in sorted(response.headers)},
        "decision": {
            "kind": response.decision.kind,
            "reason_code": response.decision.reason_code,
            "message": response.decision.message,
            "rule_id": response.decision.rule_id,
        },
        "response_case_id": response.response_case_id,
        "provider_state_sha256": canonical_json_sha256(behavior_state),
    }


def _verify_world_operation_mapping(export: Mapping[str, Any], *, declared_operation: str) -> None:
    events = export.get("provider_state", {}).get("verifier_events", [])
    if not isinstance(events, list) or not events:
        _fail("provider_admission_operation_unmapped", "Provider operation evidence is missing.")
    started = [
        event
        for event in events
        if isinstance(event, dict) and event.get("event_type") == "provider_operation_started"
    ]
    actual = started[-1].get("operation_id") if started else None
    if actual != declared_operation:
        _fail(
            "provider_admission_operation_unmapped",
            "The native request did not route to the declared provider operation.",
            declared=declared_operation,
            actual=actual,
        )


def _evaluate_invariants(
    predicates: Mapping[str, Mapping[str, Any]], export: Mapping[str, Any]
) -> None:
    for predicate in predicates.values():
        _evaluate_predicate(predicate, response=None, export=export)


def _evaluate_predicate(
    predicate: Mapping[str, Any],
    *,
    response: GateResponse | None,
    export: Mapping[str, Any],
) -> None:
    source_name = predicate["source"]
    if source_name == "response_body":
        if response is None:
            _fail("provider_admission_predicate_failed", "Response predicate has no response.")
        source = response.body
    else:
        source = export[source_name]
    exists, value = _resolve_pointer(source, predicate["pointer"])
    operator = predicate["operator"]
    passed = exists
    if operator == "equals":
        expected = predicate["expected"]
        passed = exists and type(value) is type(expected) and value == expected
    elif operator == "type":
        passed = exists and _json_type(value) == predicate["expected_type"]
    if not passed:
        _fail(
            "provider_admission_predicate_failed",
            f"Predicate {predicate['predicate_id']!r} failed.",
        )


def _behavior_state(provider_state: Any) -> Any:
    if not isinstance(provider_state, dict):
        return deepcopy(provider_state)
    if provider_state.get("protocol") == "gate_config_v1":
        return deepcopy(provider_state.get("shadow_state"))
    return {
        key: deepcopy(value)
        for key, value in provider_state.items()
        if key not in {"events", "verifier_events"}
    }


def _validate_request(raw: Any) -> dict[str, Any]:
    _require_fields(raw, _REQUEST_FIELDS, name="probe request")
    if raw["scheme"] != "https":
        _fail("provider_admission_request_invalid", "Probe request scheme must be https.")
    if not isinstance(raw["authority"], str) or not raw["authority"]:
        _fail("provider_admission_request_invalid", "Probe authority is invalid.")
    method = _http_method(raw["method"])
    path = raw["path"]
    if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path:
        _fail("provider_admission_request_invalid", "Probe path is invalid.")
    query = raw["query"]
    if not isinstance(query, dict) or any(
        not isinstance(key, str)
        or not isinstance(value, (str, list))
        or isinstance(value, list)
        and any(not isinstance(item, str) for item in value)
        for key, value in query.items()
    ):
        _fail("provider_admission_request_invalid", "Probe query is invalid.")
    headers = raw["headers"]
    if not isinstance(headers, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in headers.items()
    ):
        _fail("provider_admission_request_invalid", "Probe headers are invalid.")
    return {**deepcopy(raw), "method": method}


def _request_matches_surface(request: Mapping[str, Any], surface: Mapping[str, Any]) -> None:
    for field in ("scheme", "authority", "method"):
        if request[field] != surface[field]:
            _fail(
                "provider_admission_request_surface_mismatch",
                f"Probe request {field} does not match its native operation surface.",
            )
    template_segments = _path_segments(surface["path_template"])
    try:
        request_segments = _path_segments(request["path"], allow_parameters=False)
    except ProviderRuntimeError:
        request_segments = None
    if (
        request_segments is None
        or len(request_segments) != len(template_segments)
        or any(
            _PATH_PARAMETER.fullmatch(template) is None and actual != template
            for actual, template in zip(request_segments, template_segments)
        )
    ):
        _fail(
            "provider_admission_request_surface_mismatch",
            "Probe request path does not match its native path template.",
        )


def _path_template(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "?" in value or "#" in value:
        _fail("provider_admission_surface_invalid", "path_template is invalid.")
    _path_segments(value)
    return value


def _path_segments(value: str, *, allow_parameters: bool = True) -> tuple[str, ...]:
    if value == "/":
        return ()
    if not value.startswith("/") or value.endswith("/"):
        _fail("provider_admission_surface_invalid", "Provider paths may not have a trailing slash.")
    segments = tuple(value[1:].split("/"))
    for segment in segments:
        parameter = _PATH_PARAMETER.fullmatch(segment) is not None
        if (not segment or segment in {".", ".."} or "{" in segment or "}" in segment) and not (
            allow_parameters and parameter
        ):
            _fail(
                "provider_admission_surface_invalid",
                "Path parameters must occupy one complete non-empty path segment.",
            )
        if parameter and not allow_parameters:
            _fail(
                "provider_admission_surface_invalid",
                "Concrete request paths cannot contain parameters.",
            )
    return segments


def _reject_ambiguous_operation_surfaces(
    surfaces: list[tuple[str, Mapping[str, Any]]], *, code: str
) -> None:
    for index, (left_id, left) in enumerate(surfaces):
        left_segments = _path_segments(left["path_template"])
        for right_id, right in surfaces[index + 1 :]:
            if left["authority"] != right["authority"] or left["method"] != right["method"]:
                continue
            right_segments = _path_segments(right["path_template"])
            overlaps = len(left_segments) == len(right_segments) and all(
                _PATH_PARAMETER.fullmatch(left_segment) is not None
                or _PATH_PARAMETER.fullmatch(right_segment) is not None
                or left_segment == right_segment
                for left_segment, right_segment in zip(left_segments, right_segments)
            )
            if overlaps:
                _fail(
                    code,
                    "Native provider operation surfaces must not overlap.",
                    operation_ids=sorted((left_id, right_id)),
                )


def _resolve_pointer(value: Any, pointer: str) -> tuple[bool, Any]:
    _json_pointer(pointer)
    current = value
    if pointer == "":
        return True, current
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return False, None
    return True, current


def _json_pointer(value: Any) -> str:
    if not isinstance(value, str) or (value and not value.startswith("/")):
        _fail("provider_admission_predicates_invalid", "Predicate pointer is invalid.")
    for token in re.findall(r"~.", value):
        if token not in {"~0", "~1"}:
            _fail("provider_admission_predicates_invalid", "Predicate pointer escape is invalid.")
    return value


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "invalid"


def _behaviors(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw or any(item not in _BEHAVIORS for item in raw):
        _fail("provider_admission_behaviors_invalid", "covered_behaviors is invalid.")
    if len(set(raw)) != len(raw):
        _fail("provider_admission_behaviors_invalid", "covered_behaviors has duplicates.")
    return tuple(raw)


def _unique_identifiers(raw: Any, *, field: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        _fail("provider_admission_claims_invalid", f"{field} must be a list.")
    values = tuple(_identifier(value, field=field) for value in raw)
    if len(set(values)) != len(values):
        _fail("provider_admission_claims_invalid", f"{field} must not contain duplicates.")
    return values


def _identifier(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _fail("provider_admission_claims_invalid", f"{field} is not a valid identifier.")
    return value


def _grounding(value: Any) -> str:
    if not isinstance(value, str) or _GROUNDING_LEVEL.fullmatch(value) is None:
        _fail("provider_admission_grounding_invalid", "Grounding level is invalid.")
    return value


def _grounding_rank(value: str) -> int:
    matched = _GROUNDING_LEVEL.fullmatch(value)
    if matched is None:
        _fail("provider_admission_grounding_invalid", "Grounding level is invalid.")
    return int(matched.group(1))


def _http_method(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.upper() or not value.isalpha():
        _fail("provider_admission_surface_invalid", "HTTP method must be uppercase letters.")
    return value


def _timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        _fail("provider_admission_evidence_invalid", f"{field} must be an RFC 3339 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("provider_admission_evidence_invalid", f"{field} must be an RFC 3339 timestamp.")
    if parsed.tzinfo is None:
        _fail("provider_admission_evidence_invalid", f"{field} must include a UTC offset.")
    return parsed.astimezone(UTC)


def _relative_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        _fail("provider_admission_path_invalid", f"{field} is invalid.")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or parsed.as_posix() != value or ".." in parsed.parts:
        _fail("provider_admission_path_invalid", f"{field} is invalid.")
    return value


def _resolve_descendant_file(root: Path, relative: str) -> Path:
    candidate = root
    for part in PurePosixPath(relative).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            _fail("provider_admission_symlink_forbidden", "Evidence paths may not use symlinks.")
    resolved = _resolve_regular_file(candidate, code="provider_admission_evidence_unreadable")
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError:
        _fail("provider_admission_path_escape", "Evidence path escapes the claims directory.")
    return resolved


def _resolve_regular_file(path: Path, *, code: str) -> Path:
    if path.is_symlink():
        _fail("provider_admission_symlink_forbidden", "Symbolic links are not allowed.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail(code, f"Could not resolve {path}: {exc}.")
    if not resolved.is_file():
        _fail(code, f"Expected a regular file: {resolved}.")
    return resolved


def _sha256_value(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        _fail("provider_admission_digest_invalid", f"{field} is not a SHA-256 digest.")
    return value


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json_object(path: Path, *, code: str) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(code, f"Could not load JSON from {path}: {exc}.")
    if not isinstance(raw, dict):
        _fail(code, f"Expected a JSON object in {path}.")
    return raw


def _require_fields(raw: Any, fields: frozenset[str], *, name: str) -> None:
    if not isinstance(raw, dict) or set(raw) != fields:
        actual = set(raw) if isinstance(raw, dict) else set()
        _fail(
            "provider_admission_claims_invalid",
            f"{name} fields do not match the contract.",
            missing=sorted(fields - actual),
            unknown=sorted(actual - fields),
        )


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderRuntimeError(code, message, details)
