from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from datalox_gated_runtime.behavior_harvest.contracts import (
    BehaviorCapture,
    BehaviorContractError,
    BehaviorRecipe,
    BindingSpec,
    EngineIdentity,
    JsonValue,
    RequestTemplate,
    freeze_json,
    load_capture,
    render_path_template,
    thaw_json,
)
from datalox_gated_runtime.reference import (
    REFERENCE_TRACE_SCHEMA_ID,
    ConformanceMismatch,
    ConformanceReport,
    ObservedResponse,
    ReferenceCall,
)
from datalox_gated_runtime.reference.comparison import compare_json


class BehaviorTraceTarget(Protocol):
    target_id: str
    target_version: str

    def reset(self, seed: int) -> None: ...

    def execute(self, call: ReferenceCall) -> ObservedResponse: ...


@dataclass(frozen=True)
class CompiledBehaviorStep:
    step_id: str
    operation_id: str
    request: RequestTemplate
    expected_status_code: int
    expected_body_template: JsonValue
    expected_headers: Mapping[str, str]
    bindings: tuple[BindingSpec, ...]


@dataclass(frozen=True)
class CompiledBehaviorTrace:
    provider_id: str
    provider_version: str
    seed: int
    capture_sha256: str
    steps: tuple[CompiledBehaviorStep, ...]
    observed_relations: Mapping[str, str]
    recipe: BehaviorRecipe


def compile_reference_trace(
    *,
    capture_path: os.PathLike[str] | str,
    expected_capture_sha256: str,
    connector_path: os.PathLike[str] | str,
    expected_connector_sha256: str,
    recipe_path: os.PathLike[str] | str,
    expected_recipe_sha256: str,
    expected_engine: EngineIdentity,
    sensitive_values: Mapping[str, bytes],
    static_input_paths: Mapping[str, os.PathLike[str] | str],
    expected_static_input_sha256: Mapping[str, str],
) -> CompiledBehaviorTrace:
    """Self-load and compile an exact capture into a binding-aware trace."""
    loaded = load_capture(
        capture_path,
        expected_sha256=expected_capture_sha256,
        connector_path=connector_path,
        expected_connector_sha256=expected_connector_sha256,
        recipe_path=recipe_path,
        expected_recipe_sha256=expected_recipe_sha256,
        expected_engine=expected_engine,
        sensitive_values=sensitive_values,
        static_input_paths=static_input_paths,
        expected_static_input_sha256=expected_static_input_sha256,
    )
    return _compile_capture(loaded.value, capture_sha256=loaded.exact_sha256)


def run_compiled_behavior_trace(
    *,
    target: BehaviorTraceTarget,
    capture_path: os.PathLike[str] | str,
    expected_capture_sha256: str,
    connector_path: os.PathLike[str] | str,
    expected_connector_sha256: str,
    recipe_path: os.PathLike[str] | str,
    expected_recipe_sha256: str,
    expected_engine: EngineIdentity,
    sensitive_values: Mapping[str, bytes],
    static_input_paths: Mapping[str, os.PathLike[str] | str],
    expected_static_input_sha256: Mapping[str, str],
) -> ConformanceReport:
    """Self-load, compile, and execute one binding-aware differential trace."""
    trace = compile_reference_trace(
        capture_path=capture_path,
        expected_capture_sha256=expected_capture_sha256,
        connector_path=connector_path,
        expected_connector_sha256=expected_connector_sha256,
        recipe_path=recipe_path,
        expected_recipe_sha256=expected_recipe_sha256,
        expected_engine=expected_engine,
        sensitive_values=sensitive_values,
        static_input_paths=static_input_paths,
        expected_static_input_sha256=expected_static_input_sha256,
    )
    report = ConformanceReport(
        trace_schema_id=REFERENCE_TRACE_SCHEMA_ID,
        trace_digest=trace.capture_sha256,
        provider_id=trace.provider_id,
        provider_version=trace.provider_version,
        target_id=target.target_id,
        target_version=target.target_version,
        profile_id="behavior_binding_exact_v1",
        seed=trace.seed,
    )
    mismatches: list[ConformanceMismatch] = []
    try:
        target.reset(trace.seed)
    except Exception as error:
        mismatches.append(_target_error("target_reset_error", error))
        return _with_mismatches(report, mismatches)

    bindings: dict[str, JsonValue] = {}
    actual_bodies: dict[str, JsonValue] = {}
    for step in trace.steps:
        try:
            call = _resolve_call(step, bindings)
        except Exception as error:
            mismatches.append(
                _target_error(
                    "compiled_trace_resolution_error",
                    error,
                    step_id=step.step_id,
                )
            )
            break
        try:
            actual = target.execute(call)
        except Exception as error:
            mismatches.append(_target_error("target_execution_error", error, step_id=step.step_id))
            break
        if not isinstance(actual, ObservedResponse):
            mismatches.append(
                ConformanceMismatch(
                    code="target_response_contract_error",
                    path="",
                    expected={"type": "ObservedResponse"},
                    actual={"type": type(actual).__name__},
                    step_id=step.step_id,
                )
            )
            break
        try:
            for binding in step.bindings:
                observed = _pointer_value(actual.body, binding.pointer)
                if type(observed) is not str:
                    raise BehaviorContractError(
                        f"target binding {binding.binding_id!r} must be a string"
                    )
                bindings[binding.binding_id] = observed
            expected = ObservedResponse(
                status_code=step.expected_status_code,
                body=_resolve_bindings(step.expected_body_template, bindings),
                headers=step.expected_headers,
            )
        except Exception as error:
            mismatches.append(
                _target_error(
                    "compiled_trace_resolution_error",
                    error,
                    step_id=step.step_id,
                )
            )
            break
        actual_bodies[step.step_id] = actual.body
        for difference in compare_json(
            freeze_json(expected.to_dict()),
            freeze_json(actual.to_dict()),
        ):
            mismatches.append(
                ConformanceMismatch(
                    code=f"behavior_response_{difference.kind}",
                    path=difference.path,
                    expected=difference.expected,
                    actual=difference.actual,
                    step_id=step.step_id,
                )
            )

    if len(actual_bodies) == len(trace.steps):
        actual_relations = _compute_target_relations(trace, actual_bodies)
        for difference in compare_json(
            freeze_json(dict(trace.observed_relations)),
            freeze_json(dict(actual_relations)),
        ):
            mismatches.append(
                ConformanceMismatch(
                    code=f"behavior_state_relation_{difference.kind}",
                    path=difference.path,
                    expected=difference.expected,
                    actual=difference.actual,
                )
            )
    return _with_mismatches(report, mismatches)


def _compile_capture(
    capture: BehaviorCapture,
    *,
    capture_sha256: str,
) -> CompiledBehaviorTrace:
    if not isinstance(capture, BehaviorCapture):
        raise BehaviorContractError("compiled behavior input must be a validated capture")
    value_to_binding: dict[str, str] = {}
    for binding_id, value in capture.bindings.items():
        if type(value) is not str:
            raise BehaviorContractError("compiled behavior bindings must be strings")
        if value in value_to_binding:
            raise BehaviorContractError("compiled behavior binding values must be unambiguous")
        value_to_binding[value] = binding_id
    by_step = {item.step_id: item for item in capture.recipe.steps}
    steps = tuple(
        CompiledBehaviorStep(
            step_id=exchange.step_id,
            operation_id=exchange.operation_id,
            request=by_step[exchange.step_id].request,
            expected_status_code=exchange.status_code,
            expected_body_template=freeze_json(_binding_template(exchange.body, value_to_binding)),
            expected_headers=exchange.headers,
            bindings=by_step[exchange.step_id].bindings,
        )
        for exchange in capture.exchanges
    )
    return CompiledBehaviorTrace(
        provider_id=capture.connector.provider_id,
        provider_version=capture.connector.provider_version,
        seed=capture.recipe.seed,
        capture_sha256=capture_sha256,
        steps=steps,
        observed_relations=capture.observed_relations,
        recipe=capture.recipe,
    )


def _resolve_call(
    step: CompiledBehaviorStep,
    bindings: Mapping[str, JsonValue],
) -> ReferenceCall:
    resolved = _resolve_bindings(step.request.to_dict(), bindings)
    return ReferenceCall(
        method=step.request.method,
        path=render_path_template(step.request.path, bindings),
        query=resolved["query"],
        body=resolved["body"],
        headers=resolved["headers"],
        operation_id=step.operation_id,
    )


def _resolve_bindings(value: Any, bindings: Mapping[str, JsonValue]) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"$binding"}:
            binding_id = value["$binding"]
            if binding_id not in bindings:
                raise BehaviorContractError(f"binding {binding_id!r} is unavailable")
            return thaw_json(bindings[binding_id])
        return {key: _resolve_bindings(item, bindings) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_resolve_bindings(item, bindings) for item in value]
    return thaw_json(freeze_json(value))


def _binding_template(
    value: JsonValue,
    value_to_binding: Mapping[str, str],
) -> Any:
    if type(value) is str and value in value_to_binding:
        return {"$binding": value_to_binding[value]}
    if isinstance(value, Mapping):
        return {key: _binding_template(item, value_to_binding) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_binding_template(item, value_to_binding) for item in value]
    return thaw_json(value)


def _compute_target_relations(
    trace: CompiledBehaviorTrace,
    actual_bodies: Mapping[str, JsonValue],
) -> Mapping[str, str]:
    relations: dict[str, str] = {}
    for step in trace.recipe.steps:
        for assertion in step.assertions:
            if assertion.kind != "state_observe_step":
                continue
            assert assertion.pointer is not None
            assert assertion.prior_pointer is not None
            assert assertion.prior_step_id is not None
            current = _pointer_value(actual_bodies[step.step_id], assertion.pointer)
            prior = _pointer_value(
                actual_bodies[assertion.prior_step_id],
                assertion.prior_pointer,
            )
            relations[f"{step.step_id}.{assertion.assertion_id}"] = (
                "equal" if current == prior else "changed"
            )
    return relations


def _pointer_value(value: JsonValue, pointer: str) -> JsonValue:
    current = value
    if pointer == "":
        return current
    for raw_component in pointer.split("/")[1:]:
        component = raw_component.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if component not in current:
                raise BehaviorContractError(f"JSON pointer {pointer!r} does not exist")
            current = current[component]
        elif type(current) is tuple:
            if not component.isascii() or not component.isdigit():
                raise BehaviorContractError(f"JSON pointer {pointer!r} has a non-index component")
            index = int(component)
            if index >= len(current):
                raise BehaviorContractError(f"JSON pointer {pointer!r} does not exist")
            current = current[index]
        else:
            raise BehaviorContractError(f"JSON pointer {pointer!r} traverses a scalar")
    return current


def _target_error(
    code: str,
    error: Exception,
    *,
    step_id: str | None = None,
) -> ConformanceMismatch:
    return ConformanceMismatch(
        code=code,
        path="",
        expected={"completed": True},
        actual={"error_type": type(error).__name__},
        step_id=step_id,
    )


def _with_mismatches(
    report: ConformanceReport,
    mismatches: list[ConformanceMismatch],
) -> ConformanceReport:
    return ConformanceReport(
        trace_schema_id=report.trace_schema_id,
        trace_digest=report.trace_digest,
        provider_id=report.provider_id,
        provider_version=report.provider_version,
        target_id=report.target_id,
        target_version=report.target_version,
        profile_id=report.profile_id,
        seed=report.seed,
        mismatches=tuple(mismatches),
    )
