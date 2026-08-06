from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (
    BehaviorCapture,
    BehaviorContractError,
    BehaviorRecipe,
    BindingSpec,
    ComposedStringBindingOccurrence,
    EngineIdentity,
    JsonValue,
    RequestTemplate,
    _logical_exchange_groups,
    freeze_json,
    generated_binding_value_matches,
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
class _BindingReference:
    binding_id: str


@dataclass(frozen=True)
class _ComposedBindingReference:
    prefix: str
    binding_id: str
    suffix: str


@dataclass(frozen=True)
class CompiledBehaviorStep:
    step_id: str
    operation_id: str
    request: RequestTemplate
    expected_status_code: int
    expected_body_template: Any
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
    static_artifact_paths: Mapping[str, os.PathLike[str] | str] | None = None,
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
        static_artifact_paths=static_artifact_paths,
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
    static_artifact_paths: Mapping[str, os.PathLike[str] | str] | None = None,
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
        static_artifact_paths=static_artifact_paths,
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
                if not generated_binding_value_matches(observed, binding.value_type):
                    raise BehaviorContractError(
                        f"target binding {binding.binding_id!r} has the wrong type",
                        code="binding_coercion_invalid",
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
    by_step = {item.step_id: item for item in capture.recipe.steps}
    terminal_exchanges = tuple(
        group[-1]
        for group in _logical_exchange_groups(
            capture.recipe.steps,
            capture.exchanges,
        )
    )
    exchange_by_step = {item.step_id: item for item in terminal_exchanges}
    legacy_string_bindings: dict[str, str] = {}
    explicit_occurrences: dict[str, dict[str, str]] = {}
    composed_occurrences: dict[str, dict[str, ComposedStringBindingOccurrence]] = {}
    for step in capture.recipe.steps:
        for binding in step.bindings:
            value = capture.bindings[binding.binding_id]
            if not generated_binding_value_matches(value, binding.value_type):
                raise BehaviorContractError(
                    "compiled behavior binding has an invalid generated ID value",
                    code="binding_coercion_invalid",
                )
            if not binding.response_occurrences:
                if type(value) is not str:
                    raise BehaviorContractError(
                        "integer bindings require explicit response occurrences",
                        code="binding_occurrence_invalid",
                    )
                if value in legacy_string_bindings:
                    raise BehaviorContractError(
                        "legacy string binding values must be unambiguous",
                        code="binding_occurrence_invalid",
                    )
                legacy_string_bindings[value] = binding.binding_id
                continue
            for occurrence in binding.response_occurrences:
                exchange = exchange_by_step[occurrence.step_id]
                observed = _pointer_value(exchange.body, occurrence.pointer)
                if type(observed) is not type(value) or observed != value:
                    raise BehaviorContractError(
                        f"binding {binding.binding_id!r} response occurrence does not "
                        "match its captured value",
                        code="binding_occurrence_invalid",
                    )
                explicit_occurrences.setdefault(occurrence.step_id, {})[occurrence.pointer] = (
                    binding.binding_id
                )
            for occurrence in binding.composed_string_occurrences:
                exchange = exchange_by_step[occurrence.step_id]
                observed = _pointer_value(exchange.body, occurrence.pointer)
                expected = f"{occurrence.prefix}{value}{occurrence.suffix}"
                if type(observed) is not str or observed != expected:
                    raise BehaviorContractError(
                        f"binding {binding.binding_id!r} composed occurrence does "
                        "not match its exact captured pattern",
                        code="binding_occurrence_invalid",
                    )
                composed_occurrences.setdefault(occurrence.step_id, {})[occurrence.pointer] = (
                    occurrence
                )
    steps = tuple(
        CompiledBehaviorStep(
            step_id=exchange.step_id,
            operation_id=exchange.operation_id,
            request=by_step[exchange.step_id].request,
            expected_status_code=exchange.status_code,
            expected_body_template=_binding_template(
                exchange.body,
                legacy_string_bindings=legacy_string_bindings,
                explicit_occurrences=explicit_occurrences.get(exchange.step_id, {}),
                composed_occurrences=composed_occurrences.get(exchange.step_id, {}),
            ),
            expected_headers=exchange.headers,
            bindings=by_step[exchange.step_id].bindings,
        )
        for exchange in terminal_exchanges
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
    resolved = _resolve_request_bindings(step.request.to_dict(), bindings)
    return ReferenceCall(
        method=step.request.method,
        path=render_path_template(step.request.path, bindings),
        query=resolved["query"],
        body=resolved["body"],
        headers=resolved["headers"],
        operation_id=step.operation_id,
    )


def _resolve_bindings(value: Any, bindings: Mapping[str, JsonValue]) -> Any:
    if isinstance(value, _ComposedBindingReference):
        if value.binding_id not in bindings:
            raise BehaviorContractError(f"binding {value.binding_id!r} is unavailable")
        bound = bindings[value.binding_id]
        if type(bound) is not str:
            raise BehaviorContractError(
                "composed binding value must be a string",
                code="binding_occurrence_invalid",
            )
        return f"{value.prefix}{bound}{value.suffix}"
    if isinstance(value, _BindingReference):
        if value.binding_id not in bindings:
            raise BehaviorContractError(f"binding {value.binding_id!r} is unavailable")
        return thaw_json(bindings[value.binding_id])
    if isinstance(value, Mapping):
        return {key: _resolve_bindings(item, bindings) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_resolve_bindings(item, bindings) for item in value]
    return thaw_json(freeze_json(value))


def _resolve_request_bindings(
    value: Any,
    bindings: Mapping[str, JsonValue],
) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"$binding"}:
            binding_id = value["$binding"]
            if binding_id not in bindings:
                raise BehaviorContractError(f"binding {binding_id!r} is unavailable")
            return thaw_json(bindings[binding_id])
        return {key: _resolve_request_bindings(item, bindings) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_resolve_request_bindings(item, bindings) for item in value]
    return thaw_json(freeze_json(value))


def _binding_template(
    value: JsonValue,
    *,
    legacy_string_bindings: Mapping[str, str],
    explicit_occurrences: Mapping[str, str],
    composed_occurrences: Mapping[str, ComposedStringBindingOccurrence],
    pointer: str = "",
) -> Any:
    binding_id = explicit_occurrences.get(pointer)
    if binding_id is not None:
        return _BindingReference(binding_id)
    composed = composed_occurrences.get(pointer)
    if composed is not None:
        return _ComposedBindingReference(
            prefix=composed.prefix,
            binding_id=composed.binding_id,
            suffix=composed.suffix,
        )
    if type(value) is str:
        legacy_binding_id = legacy_string_bindings.get(value)
        if legacy_binding_id is not None:
            return _BindingReference(legacy_binding_id)
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                key: _binding_template(
                    item,
                    legacy_string_bindings=legacy_string_bindings,
                    explicit_occurrences=explicit_occurrences,
                    composed_occurrences=composed_occurrences,
                    pointer=_pointer_child(pointer, key),
                )
                for key, item in value.items()
            }
        )
    if isinstance(value, tuple):
        return tuple(
            _binding_template(
                item,
                legacy_string_bindings=legacy_string_bindings,
                explicit_occurrences=explicit_occurrences,
                composed_occurrences=composed_occurrences,
                pointer=_pointer_child(pointer, str(index)),
            )
            for index, item in enumerate(value)
        )
    return thaw_json(value)


def _pointer_child(pointer: str, component: str) -> str:
    escaped = component.replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{escaped}"


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
    if (
        code == "compiled_trace_resolution_error"
        and getattr(error, "code", None) == "binding_coercion_invalid"
    ):
        code = "binding_coercion_invalid"
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
