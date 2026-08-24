from __future__ import annotations

from dataclasses import replace
from typing import Protocol

from datalox_gated_runtime.reference.comparison import compare_json
from datalox_gated_runtime.reference.contracts import (
    ConformanceMismatch,
    ConformanceReport,
    ExpectedObservation,
    JsonValue,
    ObservationRequest,
    ObservedResponse,
    ReferenceCall,
    ReferenceContractError,
    ReferenceStep,
    ReferenceTrace,
    compute_reference_trace_digest,
    freeze_json,
)


class SequenceTarget(Protocol):
    target_id: str
    target_version: str

    def reset(self, seed: int) -> None: ...

    def execute(self, call: ReferenceCall) -> ObservedResponse: ...

    def observe(self, request: ObservationRequest) -> JsonValue: ...


class ConformanceProfile(Protocol):
    profile_id: str

    def normalize_response(
        self,
        *,
        step: ReferenceStep,
        response: ObservedResponse,
    ) -> ObservedResponse: ...

    def normalize_observation(
        self,
        *,
        request: ObservationRequest,
        value: JsonValue,
    ) -> JsonValue: ...


class IdentityConformanceProfile:
    profile_id = "identity_exact_v1"

    def normalize_response(
        self,
        *,
        step: ReferenceStep,
        response: ObservedResponse,
    ) -> ObservedResponse:
        return response

    def normalize_observation(
        self,
        *,
        request: ObservationRequest,
        value: JsonValue,
    ) -> JsonValue:
        return value


def run_conformance(
    trace: ReferenceTrace,
    target: SequenceTarget,
    *,
    profile: ConformanceProfile | None = None,
) -> ConformanceReport:
    active_profile = profile or IdentityConformanceProfile()
    base_report = ConformanceReport(
        trace_schema_id=trace.schema_id,
        trace_digest=compute_reference_trace_digest(trace),
        provider_id=trace.provider_id,
        provider_version=trace.provider_version,
        target_id=target.target_id,
        target_version=target.target_version,
        profile_id=active_profile.profile_id,
        seed=trace.seed,
    )
    mismatches: list[ConformanceMismatch] = []
    try:
        target.reset(trace.seed)
    except Exception as error:
        mismatches.append(_target_error("target_reset_error", error))
        return _report(base_report, mismatches)

    for observation in trace.initial_observations:
        _compare_observation(
            observation,
            target=target,
            profile=active_profile,
            mismatches=mismatches,
            step_id=None,
        )

    for step in trace.steps:
        try:
            actual_response = target.execute(step.call)
        except Exception as error:
            mismatches.append(_target_error("target_execution_error", error, step_id=step.step_id))
            break
        if not isinstance(actual_response, ObservedResponse):
            mismatches.append(
                ConformanceMismatch(
                    code="target_response_contract_error",
                    path="",
                    expected={"type": "ObservedResponse"},
                    actual={"type": type(actual_response).__name__},
                    step_id=step.step_id,
                )
            )
            break
        _compare_response(
            step,
            actual_response=actual_response,
            profile=active_profile,
            mismatches=mismatches,
        )
        for observation in step.post_observations:
            _compare_observation(
                observation,
                target=target,
                profile=active_profile,
                mismatches=mismatches,
                step_id=step.step_id,
            )

    return _report(base_report, mismatches)


def _compare_response(
    step: ReferenceStep,
    *,
    actual_response: ObservedResponse,
    profile: ConformanceProfile,
    mismatches: list[ConformanceMismatch],
) -> None:
    try:
        expected = profile.normalize_response(
            step=step,
            response=step.expected_response,
        )
        actual = profile.normalize_response(step=step, response=actual_response)
        if not isinstance(expected, ObservedResponse) or not isinstance(
            actual,
            ObservedResponse,
        ):
            raise ReferenceContractError("response normalizer must return ObservedResponse")
    except Exception as error:
        mismatches.append(
            _target_error(
                "profile_response_normalization_error",
                error,
                step_id=step.step_id,
            )
        )
        return
    expected_value = freeze_json(expected.to_dict())
    actual_value = freeze_json(actual.to_dict())
    for difference in compare_json(expected_value, actual_value):
        mismatches.append(
            ConformanceMismatch(
                code=f"response_{difference.kind}",
                path=difference.path,
                expected=difference.expected,
                actual=difference.actual,
                step_id=step.step_id,
            )
        )


def _compare_observation(
    observation: ExpectedObservation,
    *,
    target: SequenceTarget,
    profile: ConformanceProfile,
    mismatches: list[ConformanceMismatch],
    step_id: str | None,
) -> None:
    request = observation.request
    try:
        actual_value = freeze_json(
            target.observe(request),
            path=f"target.observation.{request.observation_id}",
        )
    except ReferenceContractError as error:
        mismatches.append(
            _target_error(
                "target_observation_contract_error",
                error,
                step_id=step_id,
                observation_id=request.observation_id,
            )
        )
        return
    except Exception as error:
        mismatches.append(
            _target_error(
                "target_observation_error",
                error,
                step_id=step_id,
                observation_id=request.observation_id,
            )
        )
        return
    try:
        expected = freeze_json(
            profile.normalize_observation(
                request=request,
                value=observation.expected,
            )
        )
        actual = freeze_json(profile.normalize_observation(request=request, value=actual_value))
    except Exception as error:
        mismatches.append(
            _target_error(
                "profile_observation_normalization_error",
                error,
                step_id=step_id,
                observation_id=request.observation_id,
            )
        )
        return
    for difference in compare_json(expected, actual):
        mismatches.append(
            ConformanceMismatch(
                code=f"observation_{difference.kind}",
                path=difference.path,
                expected=difference.expected,
                actual=difference.actual,
                step_id=step_id,
                observation_id=request.observation_id,
            )
        )


def _target_error(
    code: str,
    error: Exception,
    *,
    step_id: str | None = None,
    observation_id: str | None = None,
) -> ConformanceMismatch:
    return ConformanceMismatch(
        code=code,
        path="",
        expected=None,
        actual={"error_type": type(error).__name__},
        step_id=step_id,
        observation_id=observation_id,
    )


def _report(
    base_report: ConformanceReport,
    mismatches: list[ConformanceMismatch],
) -> ConformanceReport:
    return replace(base_report, mismatches=tuple(mismatches))
