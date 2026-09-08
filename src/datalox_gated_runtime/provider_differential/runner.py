"""Differential admission evidence for an immutable Provider Release profile."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from datalox_gated_runtime.provider_differential.contracts import (
    DIFFERENTIAL_ATTESTATION_SCHEMA_VERSION,
    DIFFERENTIAL_COMPARISON_PROFILE,
    DifferentialProgramBinding,
    DifferentialRunEvidence,
    GroundingMeasurement,
    ProviderDifferentialAttestation,
)
from datalox_gated_runtime.provider_differential.errors import ProviderDifferentialError
from datalox_gated_runtime.provider_differential.target import ProviderReleaseTarget
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.reference import ConformanceReport


def run_provider_release_differential(
    *,
    registry: FilesystemProviderReleaseRegistry,
    release_reference: str,
    profile_id: str,
    authority: str,
    principal_bindings: Mapping[str, str],
    measurement: GroundingMeasurement,
    program: DifferentialProgramBinding,
    observed_at: str,
) -> ProviderDifferentialAttestation:
    """Run one program twice in one release instance and once in a fresh instance."""

    _validate_input_bindings(measurement=measurement, program=program)
    measurement_time = _timestamp(measurement.observed_at)
    attestation_time = _timestamp(observed_at)
    if attestation_time < measurement_time:
        _fail(
            "provider_differential_attestation_time_invalid",
            "Attestation observed_at must not precede the grounding measurement.",
        )

    target_arguments = {
        "registry": registry,
        "release_reference": release_reference,
        "profile_id": profile_id,
        "authority": authority,
        "principal_bindings": principal_bindings,
    }
    first_target = ProviderReleaseTarget(**target_arguments)
    try:
        if first_target.provider_id != program.provider_id:
            _fail(
                "provider_differential_release_provider_mismatch",
                "Provider Release provider does not match the grounding measurement.",
                release_provider_id=first_target.provider_id,
                measurement_provider_id=program.provider_id,
            )
        first = _execute_program(
            phase="within_instance_initial",
            target=first_target,
            program=program,
        )
        second = _execute_program(
            phase="within_instance_after_reset",
            target=first_target,
            program=program,
        )
        replica = _replica_binding(first_target)
        provider_id = first_target.provider_id
    finally:
        first_target.close()

    fresh_target = ProviderReleaseTarget(**target_arguments)
    try:
        fresh = _execute_program(
            phase="fresh_instance",
            target=fresh_target,
            program=program,
        )
        if _replica_binding(fresh_target) != replica:
            _fail(
                "provider_differential_fresh_release_binding_mismatch",
                "Fresh target did not materialize the same immutable Provider Release profile.",
            )
    finally:
        fresh_target.close()

    within_equivalent = _equivalent(first, second)
    fresh_equivalent = _equivalent(first, fresh)
    functional_reset = {
        "within_instance_equivalent": within_equivalent,
        "fresh_instance_equivalent": fresh_equivalent,
        "passed": within_equivalent and fresh_equivalent,
    }
    runs = {
        first.phase: first,
        second.phase: second,
        fresh.phase: fresh,
    }
    passed = functional_reset["passed"] and all(run.passed for run in runs.values())
    measurement_sha256 = measurement.sha256
    attestation_id = _attestation_id(
        measurement_sha256=measurement_sha256,
        release_manifest_sha256=replica["release_manifest_sha256"],
        profile_id=profile_id,
        observed_at=observed_at,
    )
    return ProviderDifferentialAttestation(
        schema_version=DIFFERENTIAL_ATTESTATION_SCHEMA_VERSION,
        attestation_id=attestation_id,
        observed_at=observed_at,
        provider_id=provider_id,
        provider_version=program.provider_version,
        program_id=program.program_id,
        measurement_sha256=measurement_sha256,
        source={
            "capture_sha256": measurement.capture_sha256,
            "connector_sha256": measurement.connector_sha256,
            "recipe_sha256": measurement.recipe_sha256,
            "harvest_engine_sha256": measurement.harvest_engine_sha256,
            "compiled_program_sha256": measurement.compiled_program_sha256,
        },
        replica=replica,
        comparison_profile=DIFFERENTIAL_COMPARISON_PROFILE,
        program={
            "trace_schema_id": program.trace_schema_id,
            "trace_digest": program.trace_digest,
            "compiled_program_sha256": program.compiled_program_sha256,
            "seed": program.seed,
        },
        runs=runs,
        functional_reset=functional_reset,
        passed=passed,
    )


def _validate_input_bindings(
    *,
    measurement: GroundingMeasurement,
    program: DifferentialProgramBinding,
) -> None:
    if not isinstance(measurement, GroundingMeasurement):
        _fail(
            "provider_differential_measurement_invalid",
            "measurement must be a GroundingMeasurement.",
        )
    if not isinstance(program, DifferentialProgramBinding):
        _fail(
            "provider_differential_program_invalid",
            "program must be a DifferentialProgramBinding.",
        )
    if measurement.completion != "complete":
        _fail(
            "provider_differential_measurement_incomplete",
            "Only a complete grounding measurement can support a differential attestation.",
        )
    mismatches = {
        name: {"measurement": getattr(measurement, name), "program": getattr(program, name)}
        for name in ("provider_id", "provider_version", "program_id")
        if getattr(measurement, name) != getattr(program, name)
    }
    if measurement.capture_sha256 != program.trace_digest:
        mismatches["capture_sha256"] = {
            "measurement": measurement.capture_sha256,
            "program": program.trace_digest,
        }
    for name in (
        "connector_sha256",
        "recipe_sha256",
        "harvest_engine_sha256",
        "compiled_program_sha256",
    ):
        if getattr(measurement, name) != getattr(program, name):
            mismatches[name] = {
                "measurement": getattr(measurement, name),
                "program": getattr(program, name),
            }
    if mismatches:
        _fail(
            "provider_differential_input_binding_mismatch",
            "Grounding measurement and differential program identities differ.",
            mismatches=mismatches,
        )
    if program.profile_id != DIFFERENTIAL_COMPARISON_PROFILE:
        _fail(
            "provider_differential_comparison_profile_unsupported",
            "Provider Release differential requires behavior_binding_exact_v1.",
            profile_id=program.profile_id,
        )


def _execute_program(
    *,
    phase: str,
    target: ProviderReleaseTarget,
    program: DifferentialProgramBinding,
) -> DifferentialRunEvidence:
    previous_generation = target.reset_generation
    try:
        report = program.runner(target)
        if not isinstance(report, ConformanceReport):
            _fail(
                "provider_differential_report_invalid",
                "Program runner must return ConformanceReport.",
            )
        if target.reset_generation != previous_generation + 1:
            _fail(
                "provider_differential_fresh_reset_required",
                "Each differential run must reset the target exactly once.",
            )
        expected = {
            "trace_schema_id": program.trace_schema_id,
            "trace_digest": program.trace_digest,
            "provider_id": program.provider_id,
            "provider_version": program.provider_version,
            "target_id": target.target_id,
            "target_version": target.target_version,
            "profile_id": program.profile_id,
            "seed": program.seed,
        }
        mismatches = {
            name: {"expected": value, "actual": getattr(report, name)}
            for name, value in expected.items()
            if getattr(report, name) != value
        }
        if mismatches:
            _fail(
                "provider_differential_report_binding_mismatch",
                "Conformance report does not bind the requested inputs and target.",
                mismatches=mismatches,
            )
        initial_state = target.last_reset_state_sha256
        if initial_state is None:
            _fail(
                "provider_differential_reset_evidence_missing",
                "Program runner did not leave reset-state evidence.",
            )
        return DifferentialRunEvidence(
            phase=phase,
            status="completed",
            passed=report.passed,
            reset_generation=target.reset_generation,
            initial_state_sha256=initial_state,
            final_state_sha256=target.behavior_state_sha256(),
            behavioral_fingerprint=target.behavioral_fingerprint(),
            report=report.to_dict(),
            error=None,
        )
    except Exception as error:
        code = (
            error.code
            if isinstance(error, ProviderDifferentialError)
            else "provider_differential_execution_failed"
        )
        return DifferentialRunEvidence(
            phase=phase,
            status="failed",
            passed=False,
            reset_generation=target.reset_generation,
            initial_state_sha256=None,
            final_state_sha256=None,
            behavioral_fingerprint=None,
            report=None,
            error={"code": code, "type": type(error).__name__},
        )


def _equivalent(first: DifferentialRunEvidence, second: DifferentialRunEvidence) -> bool:
    return (
        first.status == "completed"
        and second.status == "completed"
        and first.initial_state_sha256 == second.initial_state_sha256
        and first.final_state_sha256 == second.final_state_sha256
        and first.behavioral_fingerprint == second.behavioral_fingerprint
    )


def _replica_binding(target: ProviderReleaseTarget) -> dict[str, str]:
    return {
        "release_reference": target.release_reference,
        "release_manifest_sha256": target.manifest_sha256,
        "profile_id": target.profile_id,
        "provider_runtime_sha256": target.provider_runtime_sha256,
        "provider_admission_sha256": target.provider_admission_sha256,
    }


def _attestation_id(
    *,
    measurement_sha256: str,
    release_manifest_sha256: str,
    profile_id: str,
    observed_at: str,
) -> str:
    payload = "\0".join(
        (measurement_sha256, release_manifest_sha256, profile_id, observed_at)
    ).encode("utf-8")
    return "att_" + hashlib.sha256(payload).hexdigest()[:32]


def _timestamp(value: str) -> datetime:
    if (
        type(value) is not str
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z",
            value,
        )
        is None
    ):
        _fail(
            "provider_differential_timestamp_invalid",
            "observed_at must be an RFC 3339 UTC timestamp ending in Z.",
        )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ProviderDifferentialError(
            "provider_differential_timestamp_invalid",
            "observed_at must be an RFC 3339 UTC timestamp ending in Z.",
        ) from error


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderDifferentialError(code, message, details)
