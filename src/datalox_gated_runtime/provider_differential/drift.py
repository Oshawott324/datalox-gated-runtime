"""Provider-source drift comparison and release assessment derivation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from datalox_gated_runtime.provider_differential.compiled_program import (
    CompiledBehaviorProgram,
    CompiledBehaviorStep,
    compiled_behavior_program_sha256,
)
from datalox_gated_runtime.json_digest import canonical_json_bytes, canonical_json_sha256
from datalox_gated_runtime.provider_differential.contracts import (
    GroundingMeasurement,
    ProviderDifferentialAttestation,
)
from datalox_gated_runtime.provider_differential.errors import ProviderDifferentialError
from datalox_gated_runtime.provider_runtime.assessment_registry import (
    validate_provider_drift_assessment,
)

PROVIDER_DRIFT_REPORT_SCHEMA_VERSION = "datalox_provider_drift_report_v1"
PROVIDER_DRIFT_COMPARISON_PROFILE = "portable_behavior_structural_v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?Z$"
)
_DIFFERENCE_KINDS = (
    "provider_version_changed",
    "response_status_changed",
    "response_headers_changed",
    "response_body_changed",
    "state_relation_changed",
    "duplicate_semantics_changed",
    "native_failure_semantics_changed",
    "pagination_changed",
    "async_sequence_changed",
)
_STEP_ROLES = frozenset(
    {"before", "success", "duplicate", "native_failure", "resulting_state", "supporting"}
)
_MISSING = {"$datalox_missing": True}


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderDifferentialError(code, message, details)


@dataclass(frozen=True)
class DriftClassificationScope:
    """Explicit semantic declarations unavailable from V3 response structure."""

    pagination_step_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        values = tuple(
            _identifier(item, field="pagination_step_ids") for item in self.pagination_step_ids
        )
        if len(values) != len(set(values)):
            _fail(
                "provider_drift_classification_scope_invalid",
                "pagination_step_ids must be unique.",
            )
        object.__setattr__(self, "pagination_step_ids", tuple(sorted(values)))

    def to_dict(self) -> dict[str, Any]:
        return {"pagination_step_ids": list(self.pagination_step_ids)}

    @classmethod
    def from_dict(cls, value: Any) -> DriftClassificationScope:
        raw = _shape(
            value,
            required={"pagination_step_ids"},
            field="classification_scope",
        )
        if type(raw["pagination_step_ids"]) is not list:
            _fail(
                "provider_drift_classification_scope_invalid",
                "pagination_step_ids must be an array.",
            )
        return cls(tuple(raw["pagination_step_ids"]))


@dataclass(frozen=True)
class ProviderDriftDifference:
    kind: str
    path: str
    step_id: str | None
    attempt_number: int | None
    role: str | None
    baseline_sha256: str
    candidate_sha256: str

    def __post_init__(self) -> None:
        if self.kind not in _DIFFERENCE_KINDS:
            _fail("provider_drift_difference_invalid", "Drift difference kind is invalid.")
        _json_pointer(self.path)
        if self.step_id is not None:
            _identifier(self.step_id, field="difference.step_id")
        if self.attempt_number is not None and (
            type(self.attempt_number) is not int or self.attempt_number < 1
        ):
            _fail(
                "provider_drift_difference_invalid",
                "Difference attempt_number must be a positive integer or null.",
            )
        if self.role is not None and self.role not in _STEP_ROLES:
            _fail("provider_drift_difference_invalid", "Difference role is invalid.")
        _digest(self.baseline_sha256, field="difference.baseline_sha256")
        _digest(self.candidate_sha256, field="difference.candidate_sha256")
        if self.baseline_sha256 == self.candidate_sha256:
            _fail(
                "provider_drift_difference_invalid",
                "A drift difference must bind distinct values.",
            )

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.path,
            self.kind,
            self.step_id or "",
            self.attempt_number or 0,
            self.baseline_sha256,
            self.candidate_sha256,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "step_id": self.step_id,
            "attempt_number": self.attempt_number,
            "role": self.role,
            "baseline_sha256": self.baseline_sha256,
            "candidate_sha256": self.candidate_sha256,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ProviderDriftDifference:
        return cls(
            **_shape(
                value,
                required={
                    "kind",
                    "path",
                    "step_id",
                    "attempt_number",
                    "role",
                    "baseline_sha256",
                    "candidate_sha256",
                },
                field="difference",
            )
        )


@dataclass(frozen=True)
class ProviderDriftReport:
    report_id: str
    observed_at: str
    provider_id: str
    program_id: str
    comparison_status: str
    baseline: Mapping[str, Any]
    candidate: Mapping[str, Any]
    comparison_binding: Mapping[str, Any]
    classification_scope: DriftClassificationScope
    differences: tuple[ProviderDriftDifference, ...]
    summary: Mapping[str, int]
    comparison_profile: str = PROVIDER_DRIFT_COMPARISON_PROFILE
    schema_version: str = PROVIDER_DRIFT_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != PROVIDER_DRIFT_REPORT_SCHEMA_VERSION:
            _fail("provider_drift_report_schema_unsupported", "Drift report schema is unsupported.")
        for field in ("report_id", "provider_id", "program_id", "comparison_profile"):
            _identifier(getattr(self, field), field=field)
        if self.comparison_profile != PROVIDER_DRIFT_COMPARISON_PROFILE:
            _fail(
                "provider_drift_comparison_profile_unsupported",
                "Drift comparison profile is unsupported.",
            )
        _timestamp(self.observed_at, field="observed_at")
        if self.comparison_status not in {"equal", "changed", "reacquisition_blocked"}:
            _fail("provider_drift_report_invalid", "Drift comparison status is invalid.")
        baseline = _measurement_binding(self.baseline, field="baseline", allow_incomplete=False)
        candidate = _measurement_binding(self.candidate, field="candidate", allow_incomplete=True)
        binding = _comparison_binding(self.comparison_binding)
        if not isinstance(self.classification_scope, DriftClassificationScope):
            _fail(
                "provider_drift_classification_scope_invalid",
                "classification_scope must be a DriftClassificationScope.",
            )
        differences = tuple(self.differences)
        if not all(isinstance(item, ProviderDriftDifference) for item in differences):
            _fail("provider_drift_report_invalid", "Drift differences are invalid.")
        if differences != tuple(sorted(differences, key=lambda item: item.sort_key)):
            _fail("provider_drift_report_invalid", "Drift differences must be sorted.")
        serialized = [canonical_json_bytes(item.to_dict()) for item in differences]
        if len(serialized) != len(set(serialized)):
            _fail("provider_drift_report_invalid", "Drift differences must be unique.")
        summary = dict(self.summary)
        expected_summary = {kind: 0 for kind in _DIFFERENCE_KINDS}
        for difference in differences:
            expected_summary[difference.kind] += 1
        if summary != expected_summary:
            _fail("provider_drift_report_invalid", "Drift summary does not match differences.")
        if self.comparison_status == "reacquisition_blocked":
            if candidate["completion"] != "incomplete" or differences:
                _fail(
                    "provider_drift_report_invalid",
                    "Blocked reacquisition requires an incomplete candidate and no drift claims.",
                )
        elif candidate["completion"] != "complete":
            _fail(
                "provider_drift_report_invalid",
                "A behavior comparison requires a complete candidate measurement.",
            )
        if (self.comparison_status == "equal") is not (not differences):
            if self.comparison_status != "reacquisition_blocked":
                _fail(
                    "provider_drift_report_invalid",
                    "Equal/changed status must exactly match difference presence.",
                )
        object.__setattr__(self, "baseline", MappingProxyType(baseline))
        object.__setattr__(self, "candidate", MappingProxyType(candidate))
        object.__setattr__(self, "comparison_binding", MappingProxyType(binding))
        object.__setattr__(self, "differences", differences)
        object.__setattr__(self, "summary", MappingProxyType(summary))

    @property
    def sha256(self) -> str:
        return canonical_json_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "report_id": self.report_id,
            "observed_at": self.observed_at,
            "provider_id": self.provider_id,
            "program_id": self.program_id,
            "comparison_profile": self.comparison_profile,
            "comparison_status": self.comparison_status,
            "baseline": dict(self.baseline),
            "candidate": dict(self.candidate),
            "comparison_binding": dict(self.comparison_binding),
            "classification_scope": self.classification_scope.to_dict(),
            "differences": [item.to_dict() for item in self.differences],
            "summary": dict(self.summary),
        }

    @classmethod
    def from_dict(cls, value: Any) -> ProviderDriftReport:
        raw = _shape(
            value,
            required={
                "schema_version",
                "report_id",
                "observed_at",
                "provider_id",
                "program_id",
                "comparison_profile",
                "comparison_status",
                "baseline",
                "candidate",
                "comparison_binding",
                "classification_scope",
                "differences",
                "summary",
            },
            field="report",
        )
        if type(raw["differences"]) is not list:
            _fail("provider_drift_report_invalid", "differences must be an array.")
        return cls(
            **{
                **raw,
                "classification_scope": DriftClassificationScope.from_dict(
                    raw["classification_scope"]
                ),
                "differences": tuple(
                    ProviderDriftDifference.from_dict(item) for item in raw["differences"]
                ),
            }
        )


def compare_provider_drift(
    *,
    report_id: str,
    baseline_measurement: GroundingMeasurement,
    candidate_measurement: GroundingMeasurement,
    baseline_program: CompiledBehaviorProgram,
    candidate_program: CompiledBehaviorProgram | None,
    classification_scope: DriftClassificationScope = DriftClassificationScope(),
) -> ProviderDriftReport:
    """Compare two source observations without inferring provider semantics."""

    _identifier(report_id, field="report_id")
    if not isinstance(baseline_measurement, GroundingMeasurement) or not isinstance(
        candidate_measurement, GroundingMeasurement
    ):
        _fail(
            "provider_drift_measurement_invalid",
            "Drift inputs must be GroundingMeasurement values.",
        )
    _require_measurements_comparable(baseline_measurement, candidate_measurement)
    _bind_complete_program(baseline_measurement, baseline_program, label="baseline")
    _validate_scope(classification_scope, baseline_program)

    baseline_binding = _report_measurement_binding(
        baseline_measurement,
    )
    binding = {
        "connector_sha256": baseline_measurement.connector_sha256,
        "recipe_sha256": baseline_measurement.recipe_sha256,
        "harvest_engine_sha256": baseline_measurement.harvest_engine_sha256,
        "seed": baseline_program.seed,
    }
    if candidate_measurement.completion == "incomplete":
        if candidate_program is not None:
            _fail(
                "provider_drift_incomplete_program_forbidden",
                "An incomplete candidate measurement cannot supply a comparison program.",
            )
        return ProviderDriftReport(
            report_id=report_id,
            observed_at=candidate_measurement.observed_at,
            provider_id=baseline_measurement.provider_id,
            program_id=baseline_measurement.program_id,
            comparison_status="reacquisition_blocked",
            baseline=baseline_binding,
            candidate=_report_measurement_binding(candidate_measurement),
            comparison_binding=binding,
            classification_scope=classification_scope,
            differences=(),
            summary={kind: 0 for kind in _DIFFERENCE_KINDS},
        )
    if candidate_program is None:
        _fail(
            "provider_drift_candidate_program_required",
            "A complete candidate measurement requires its compiled behavior program.",
        )
    _bind_complete_program(candidate_measurement, candidate_program, label="candidate")
    if baseline_program.seed != candidate_program.seed:
        _incomparable("seed", baseline_program.seed, candidate_program.seed)
    if baseline_program.recipe.to_dict() != candidate_program.recipe.to_dict():
        _incomparable(
            "embedded_recipe",
            canonical_json_sha256(baseline_program.recipe.to_dict()),
            canonical_json_sha256(candidate_program.recipe.to_dict()),
        )
    _validate_scope(classification_scope, candidate_program)

    differences = _compare_behavior(
        baseline_program,
        candidate_program,
        classification_scope=classification_scope,
    )
    summary = {kind: 0 for kind in _DIFFERENCE_KINDS}
    for difference in differences:
        summary[difference.kind] += 1
    return ProviderDriftReport(
        report_id=report_id,
        observed_at=candidate_measurement.observed_at,
        provider_id=baseline_measurement.provider_id,
        program_id=baseline_measurement.program_id,
        comparison_status="changed" if differences else "equal",
        baseline=baseline_binding,
        candidate=_report_measurement_binding(
            candidate_measurement,
        ),
        comparison_binding=binding,
        classification_scope=classification_scope,
        differences=differences,
        summary=summary,
    )


def derive_provider_drift_assessment(
    *,
    assessment_id: str,
    report: ProviderDriftReport,
    release_manifest_sha256: str,
    profile_id: str,
    freshness_window_days: int,
    differential_attestation: ProviderDifferentialAttestation | None = None,
) -> dict[str, Any]:
    """Derive one registry assessment from source drift and replica evidence."""

    if not isinstance(report, ProviderDriftReport):
        _fail("provider_drift_report_invalid", "report must be a ProviderDriftReport.")
    release_digest = _digest(release_manifest_sha256, field="release_manifest_sha256")
    safe_profile = _identifier(profile_id, field="profile_id")
    if type(freshness_window_days) is not int or freshness_window_days <= 0:
        _fail(
            "provider_drift_freshness_invalid",
            "freshness_window_days must be a positive integer.",
        )
    replica_status = "not_run"
    replica_report_sha256: str | None = None
    replica_difference_count = 0
    if differential_attestation is not None:
        _bind_attestation(
            report=report,
            attestation=differential_attestation,
            release_manifest_sha256=release_digest,
            profile_id=safe_profile,
        )
        replica_status = "passed" if differential_attestation.passed else "failed"
        replica_report_sha256 = differential_attestation.sha256
        replica_difference_count = _attestation_difference_count(differential_attestation)

    if report.comparison_status == "reacquisition_blocked":
        if differential_attestation is not None:
            _fail(
                "provider_drift_attestation_for_incomplete_source",
                "An incomplete source reacquisition cannot bind a replica attestation.",
            )
        status = "reacquisition_blocked"
        source_status = "incomplete"
    elif report.comparison_status == "changed":
        status = "provider_drift_detected"
        source_status = "changed"
    else:
        source_status = "equal"
        if differential_attestation is None:
            _fail(
                "provider_drift_attestation_required",
                "An equal source comparison requires replica evidence for an assessment.",
            )
        status = "current" if differential_attestation.passed else "replica_mismatch"

    observed_at = _normalized_timestamp(report.observed_at)
    observed = _parse_timestamp(observed_at)
    expires_at = _format_timestamp(observed + timedelta(days=freshness_window_days))
    assessment = {
        "schema_version": "datalox_provider_drift_assessment_v1",
        "assessment_id": _identifier(assessment_id, field="assessment_id"),
        "provider_id": report.provider_id,
        "program_id": report.program_id,
        "observed_at": observed_at,
        "baseline_measurement_sha256": report.baseline["measurement_sha256"],
        "candidate_measurement_sha256": report.candidate["measurement_sha256"],
        "release_manifest_sha256": release_digest,
        "profile_id": safe_profile,
        "source_comparison": {
            "status": source_status,
            "report_sha256": report.sha256,
            "difference_count": len(report.differences),
        },
        "replica_comparison": {
            "status": replica_status,
            "report_sha256": replica_report_sha256,
            "difference_count": replica_difference_count,
        },
        "status": status,
        "freshness_window_days": freshness_window_days,
        "expires_at": expires_at,
    }
    return validate_provider_drift_assessment(assessment)


def load_provider_drift_report(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> ProviderDriftReport:
    if path.is_symlink() or not path.is_file():
        _fail(
            "provider_drift_report_unreadable",
            "Provider drift report must be a regular file.",
        )
    body = path.read_bytes()
    if len(body) > 8 * 1024 * 1024:
        _fail("provider_drift_report_too_large", "Provider drift report exceeds 8 MiB.")
    try:
        value = json.loads(body, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProviderDifferentialError(
            "provider_drift_report_json_invalid",
            "Provider drift report is not valid UTF-8 JSON.",
        ) from error
    report = ProviderDriftReport.from_dict(value)
    if expected_sha256 is not None and report.sha256 != _digest(
        expected_sha256, field="expected_sha256"
    ):
        _fail(
            "provider_drift_report_digest_mismatch",
            "Provider drift report does not match its expected digest.",
        )
    return report


def _compare_behavior(
    baseline: CompiledBehaviorProgram,
    candidate: CompiledBehaviorProgram,
    *,
    classification_scope: DriftClassificationScope,
) -> tuple[ProviderDriftDifference, ...]:
    differences: list[ProviderDriftDifference] = []
    if baseline.provider_version != candidate.provider_version:
        differences.append(
            _difference(
                kind="provider_version_changed",
                path="/provider_version",
                baseline=baseline.provider_version,
                candidate=candidate.provider_version,
            )
        )
    baseline_steps = {step.step_id: step for step in baseline.steps}
    candidate_steps = {step.step_id: step for step in candidate.steps}
    if baseline_steps.keys() != candidate_steps.keys():
        _incomparable("step_ids", sorted(baseline_steps), sorted(candidate_steps))
    pagination_steps = set(classification_scope.pagination_step_ids)
    for step_id in sorted(baseline_steps):
        left = baseline_steps[step_id]
        right = candidate_steps[step_id]
        step_differences = _compare_step(left, right)
        differences.extend(step_differences)
        if not step_differences:
            continue
        step_path = f"/steps/{_pointer_component(step_id)}"
        left_projection = left.to_dict()
        right_projection = right.to_dict()
        if left.role == "duplicate":
            differences.append(
                _difference(
                    kind="duplicate_semantics_changed",
                    path=step_path,
                    baseline=left_projection,
                    candidate=right_projection,
                    step=left,
                )
            )
        if left.role == "native_failure":
            differences.append(
                _difference(
                    kind="native_failure_semantics_changed",
                    path=step_path,
                    baseline=left_projection,
                    candidate=right_projection,
                    step=left,
                )
            )
        if step_id in pagination_steps:
            differences.append(
                _difference(
                    kind="pagination_changed",
                    path=step_path,
                    baseline=left_projection,
                    candidate=right_projection,
                    step=left,
                )
            )
        if left.poll is not None:
            differences.append(
                _difference(
                    kind="async_sequence_changed",
                    path=step_path,
                    baseline=left_projection,
                    candidate=right_projection,
                    step=left,
                )
            )
    for path, left, right in _json_differences(
        dict(baseline.observed_relations),
        dict(candidate.observed_relations),
        path="/observed_relations",
    ):
        differences.append(
            _difference(
                kind="state_relation_changed",
                path=path,
                baseline=left,
                candidate=right,
            )
        )
    return tuple(sorted(differences, key=lambda item: item.sort_key))


def _compare_step(
    baseline: CompiledBehaviorStep,
    candidate: CompiledBehaviorStep,
) -> list[ProviderDriftDifference]:
    if _step_contract(baseline) != _step_contract(candidate):
        _incomparable(
            f"step_contract:{baseline.step_id}",
            canonical_json_sha256(_step_contract(baseline)),
            canonical_json_sha256(_step_contract(candidate)),
        )
    path = f"/steps/{_pointer_component(baseline.step_id)}/attempts"
    left_attempts = baseline.expected_attempts
    right_attempts = candidate.expected_attempts
    differences: list[ProviderDriftDifference] = []
    if len(left_attempts) != len(right_attempts):
        differences.append(
            _difference(
                kind="response_body_changed",
                path=path,
                baseline=[item.to_dict() for item in left_attempts],
                candidate=[item.to_dict() for item in right_attempts],
                step=baseline,
            )
        )
    for index in range(min(len(left_attempts), len(right_attempts))):
        left = left_attempts[index]
        right = right_attempts[index]
        attempt_path = f"{path}/{left.attempt_number}"
        if left.attempt_number != right.attempt_number:
            differences.append(
                _difference(
                    kind="response_body_changed",
                    path=f"{attempt_path}/attempt_number",
                    baseline=left.attempt_number,
                    candidate=right.attempt_number,
                    step=baseline,
                    attempt_number=left.attempt_number,
                )
            )
        if left.expected_status_code != right.expected_status_code:
            differences.append(
                _difference(
                    kind="response_status_changed",
                    path=f"{attempt_path}/response/status_code",
                    baseline=left.expected_status_code,
                    candidate=right.expected_status_code,
                    step=baseline,
                    attempt_number=left.attempt_number,
                )
            )
        for child_path, left_value, right_value in _json_differences(
            dict(left.expected_headers),
            dict(right.expected_headers),
            path=f"{attempt_path}/response/headers",
        ):
            differences.append(
                _difference(
                    kind="response_headers_changed",
                    path=child_path,
                    baseline=left_value,
                    candidate=right_value,
                    step=baseline,
                    attempt_number=left.attempt_number,
                )
            )
        for child_path, left_value, right_value in _json_differences(
            left.to_dict()["expected_response"]["body"],
            right.to_dict()["expected_response"]["body"],
            path=f"{attempt_path}/response/body",
        ):
            differences.append(
                _difference(
                    kind="response_body_changed",
                    path=child_path,
                    baseline=left_value,
                    candidate=right_value,
                    step=baseline,
                    attempt_number=left.attempt_number,
                )
            )
        for field in ("template_bindings", "introduced_bindings"):
            left_value = left.to_dict()[field]
            right_value = right.to_dict()[field]
            for child_path, old, new in _json_differences(
                left_value,
                right_value,
                path=f"{attempt_path}/{field}",
            ):
                differences.append(
                    _difference(
                        kind="response_body_changed",
                        path=child_path,
                        baseline=old,
                        candidate=new,
                        step=baseline,
                        attempt_number=left.attempt_number,
                    )
                )
    return differences


def _step_contract(step: CompiledBehaviorStep) -> dict[str, Any]:
    value = step.to_dict()
    value.pop("expected_attempts")
    return value


def _json_differences(
    baseline: Any,
    candidate: Any,
    *,
    path: str,
) -> list[tuple[str, Any, Any]]:
    if type(baseline) is not type(candidate):
        return [(path, baseline, candidate)]
    if type(baseline) is dict:
        result: list[tuple[str, Any, Any]] = []
        for key in sorted(set(baseline) | set(candidate)):
            child_path = f"{path}/{_pointer_component(key)}"
            if key not in baseline:
                result.append((child_path, _MISSING, candidate[key]))
            elif key not in candidate:
                result.append((child_path, baseline[key], _MISSING))
            else:
                result.extend(_json_differences(baseline[key], candidate[key], path=child_path))
        return result
    if type(baseline) is list:
        result = []
        for index in range(max(len(baseline), len(candidate))):
            child_path = f"{path}/{index}"
            if index >= len(baseline):
                result.append((child_path, _MISSING, candidate[index]))
            elif index >= len(candidate):
                result.append((child_path, baseline[index], _MISSING))
            else:
                result.extend(_json_differences(baseline[index], candidate[index], path=child_path))
        return result
    return [] if baseline == candidate else [(path, baseline, candidate)]


def _difference(
    *,
    kind: str,
    path: str,
    baseline: Any,
    candidate: Any,
    step: CompiledBehaviorStep | None = None,
    attempt_number: int | None = None,
) -> ProviderDriftDifference:
    return ProviderDriftDifference(
        kind=kind,
        path=path,
        step_id=None if step is None else step.step_id,
        attempt_number=attempt_number,
        role=None if step is None else step.role,
        baseline_sha256=canonical_json_sha256(baseline),
        candidate_sha256=canonical_json_sha256(candidate),
    )


def _require_measurements_comparable(
    baseline: GroundingMeasurement,
    candidate: GroundingMeasurement,
) -> None:
    if baseline.completion != "complete":
        _fail(
            "provider_drift_baseline_incomplete",
            "The baseline measurement must be complete.",
        )
    for field in (
        "provider_id",
        "program_id",
        "connector_sha256",
        "recipe_sha256",
        "harvest_engine_sha256",
    ):
        if getattr(baseline, field) != getattr(candidate, field):
            _incomparable(field, getattr(baseline, field), getattr(candidate, field))


def _bind_complete_program(
    measurement: GroundingMeasurement,
    program: CompiledBehaviorProgram,
    *,
    label: str,
) -> None:
    if not isinstance(program, CompiledBehaviorProgram) or program.complete is not True:
        _fail(
            "provider_drift_program_invalid",
            f"The {label} compiled behavior program must be complete.",
        )
    expected = {
        "provider_id": measurement.provider_id,
        "provider_version": measurement.provider_version,
        "program_id": measurement.program_id,
        "capture_sha256": measurement.capture_sha256,
        "connector_sha256": measurement.connector_sha256,
        "recipe_sha256": measurement.recipe_sha256,
        "harvest_engine_sha256": measurement.harvest_engine_sha256,
        "compiled_program_sha256": measurement.compiled_program_sha256,
    }
    actual = {
        "provider_id": program.provider_id,
        "provider_version": program.provider_version,
        "program_id": program.recipe.program_id,
        "capture_sha256": program.capture_sha256,
        "connector_sha256": program.connector_sha256,
        "recipe_sha256": program.recipe_sha256,
        "harvest_engine_sha256": program.harvest_engine_sha256,
        "compiled_program_sha256": compiled_behavior_program_sha256(program),
    }
    for field, expected_value in expected.items():
        if actual[field] != expected_value:
            _fail(
                "provider_drift_program_binding_mismatch",
                f"The {label} program does not match its measurement.",
                field=field,
                expected=expected_value,
                actual=actual[field],
            )


def _validate_scope(
    scope: DriftClassificationScope,
    program: CompiledBehaviorProgram,
) -> None:
    if not isinstance(scope, DriftClassificationScope):
        _fail(
            "provider_drift_classification_scope_invalid",
            "classification_scope must be a DriftClassificationScope.",
        )
    unknown = sorted(set(scope.pagination_step_ids) - {step.step_id for step in program.steps})
    if unknown:
        _fail(
            "provider_drift_classification_scope_invalid",
            "Pagination classification references unknown program steps.",
            unknown_step_ids=unknown,
        )


def _report_measurement_binding(
    measurement: GroundingMeasurement,
) -> dict[str, Any]:
    return {
        "measurement_sha256": measurement.sha256,
        "capture_sha256": measurement.capture_sha256,
        "compiled_program_sha256": measurement.compiled_program_sha256,
        "provider_version": measurement.provider_version,
        "observed_at": measurement.observed_at,
        "completion": measurement.completion,
    }


def _measurement_binding(
    value: Mapping[str, Any],
    *,
    field: str,
    allow_incomplete: bool,
) -> dict[str, Any]:
    raw = _shape(
        value,
        required={
            "measurement_sha256",
            "capture_sha256",
            "compiled_program_sha256",
            "provider_version",
            "observed_at",
            "completion",
        },
        field=field,
    )
    for name in ("measurement_sha256", "capture_sha256"):
        _digest(raw[name], field=f"{field}.{name}")
    if raw["compiled_program_sha256"] is not None:
        _digest(raw["compiled_program_sha256"], field=f"{field}.compiled_program_sha256")
    if type(raw["provider_version"]) is not str or not raw["provider_version"]:
        _fail("provider_drift_report_invalid", f"{field}.provider_version is invalid.")
    _timestamp(raw["observed_at"], field=f"{field}.observed_at")
    allowed = {"complete", "incomplete"} if allow_incomplete else {"complete"}
    if raw["completion"] not in allowed:
        _fail("provider_drift_report_invalid", f"{field}.completion is invalid.")
    if (raw["completion"] == "complete") is not (raw["compiled_program_sha256"] is not None):
        _fail(
            "provider_drift_report_invalid",
            f"{field} completion and compiled program digest are inconsistent.",
        )
    return dict(raw)


def _comparison_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    raw = _shape(
        value,
        required={"connector_sha256", "recipe_sha256", "harvest_engine_sha256", "seed"},
        field="comparison_binding",
    )
    _digest(raw["connector_sha256"], field="comparison_binding.connector_sha256")
    _digest(raw["recipe_sha256"], field="comparison_binding.recipe_sha256")
    _digest(
        raw["harvest_engine_sha256"],
        field="comparison_binding.harvest_engine_sha256",
    )
    if type(raw["seed"]) is not int:
        _fail("provider_drift_report_invalid", "comparison_binding.seed must be an integer.")
    return dict(raw)


def _bind_attestation(
    *,
    report: ProviderDriftReport,
    attestation: ProviderDifferentialAttestation,
    release_manifest_sha256: str,
    profile_id: str,
) -> None:
    if not isinstance(attestation, ProviderDifferentialAttestation):
        _fail(
            "provider_drift_attestation_invalid",
            "differential_attestation must be a ProviderDifferentialAttestation.",
        )
    expected = {
        "provider_id": report.provider_id,
        "provider_version": report.candidate["provider_version"],
        "program_id": report.program_id,
        "observed_at": report.candidate["observed_at"],
        "measurement_sha256": report.candidate["measurement_sha256"],
        "capture_sha256": report.candidate["capture_sha256"],
        "connector_sha256": report.comparison_binding["connector_sha256"],
        "recipe_sha256": report.comparison_binding["recipe_sha256"],
        "harvest_engine_sha256": report.comparison_binding["harvest_engine_sha256"],
        "compiled_program_sha256": report.candidate["compiled_program_sha256"],
        "seed": report.comparison_binding["seed"],
        "release_manifest_sha256": release_manifest_sha256,
        "profile_id": profile_id,
    }
    actual = {
        "provider_id": attestation.provider_id,
        "provider_version": attestation.provider_version,
        "program_id": attestation.program_id,
        "observed_at": attestation.observed_at,
        "measurement_sha256": attestation.measurement_sha256,
        "capture_sha256": attestation.source["capture_sha256"],
        "connector_sha256": attestation.source["connector_sha256"],
        "recipe_sha256": attestation.source["recipe_sha256"],
        "harvest_engine_sha256": attestation.source["harvest_engine_sha256"],
        "compiled_program_sha256": attestation.source["compiled_program_sha256"],
        "seed": attestation.program["seed"],
        "release_manifest_sha256": attestation.replica["release_manifest_sha256"],
        "profile_id": attestation.replica["profile_id"],
    }
    for field, expected_value in expected.items():
        if actual[field] != expected_value:
            _fail(
                "provider_drift_attestation_binding_mismatch",
                "Differential attestation does not bind the drift candidate and release.",
                field=field,
            )


def _attestation_difference_count(attestation: ProviderDifferentialAttestation) -> int:
    count = 0
    for run in attestation.runs.values():
        if run.status == "failed":
            count += 1
        elif run.report is not None:
            mismatches = run.report.get("mismatches")
            if isinstance(mismatches, tuple):
                count += len(mismatches)
            elif isinstance(mismatches, list):
                count += len(mismatches)
    if not attestation.functional_reset["within_instance_equivalent"]:
        count += 1
    if not attestation.functional_reset["fresh_instance_equivalent"]:
        count += 1
    return count


def _incomparable(field: str, baseline: Any, candidate: Any) -> None:
    _fail(
        "provider_drift_inputs_incomparable",
        "Grounding measurements do not describe the same comparison program.",
        field=field,
        baseline_sha256=canonical_json_sha256(baseline),
        candidate_sha256=canonical_json_sha256(candidate),
    )


def _shape(value: Any, *, required: set[str], field: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != required:
        _fail("provider_drift_report_invalid", f"{field} has an invalid field set.")
    return dict(value)


def _identifier(value: Any, *, field: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _fail("provider_drift_identifier_invalid", f"{field} is not a valid identifier.")
    return value


def _digest(value: Any, *, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail("provider_drift_digest_invalid", f"{field} is not a valid SHA-256 digest.")
    return value


def _timestamp(value: Any, *, field: str) -> str:
    if type(value) is not str or _UTC_TIMESTAMP.fullmatch(value) is None:
        _fail("provider_drift_timestamp_invalid", f"{field} must be RFC 3339 UTC.")
    _parse_timestamp(value)
    return value


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ProviderDifferentialError(
            "provider_drift_timestamp_invalid",
            "Timestamp is not a valid RFC 3339 UTC value.",
        ) from error
    return parsed.astimezone(UTC)


def _normalized_timestamp(value: str) -> str:
    return _format_timestamp(_parse_timestamp(_timestamp(value, field="observed_at")))


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json_pointer(value: Any) -> str:
    if type(value) is not str or (value and not value.startswith("/")):
        _fail("provider_drift_difference_invalid", "Difference path must be a JSON pointer.")
    for raw in value.split("/")[1:] if value else ():
        if "~" in raw.replace("~0", "").replace("~1", ""):
            _fail("provider_drift_difference_invalid", "Difference path escaping is invalid.")
    return value


def _pointer_component(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("provider_drift_report_json_invalid", "Drift report has duplicate keys.")
        result[key] = value
    return result
