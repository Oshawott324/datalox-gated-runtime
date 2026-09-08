from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (
    BehaviorCapture,
    BehaviorContractError,
    BehaviorRecipe,
    BehaviorStep,
    BindingSpec,
    CapturedExchange,
    ComposedStringBindingOccurrence,
    EngineIdentity,
    JsonValue,
    LoadedCapture,
    PollSpec,
    RequestTemplate,
    _logical_exchange_groups,
    canonical_contract_digest,
    canonical_json_bytes,
    freeze_json,
    generated_binding_value_matches,
    load_capture,
    render_path_template,
    sha256_digest,
    thaw_json,
)
from datalox_gated_runtime.provider_differential.contracts import (
    DIFFERENTIAL_COMPARISON_PROFILE,
)
from datalox_gated_runtime.reference import (
    REFERENCE_TRACE_SCHEMA_ID,
    ConformanceMismatch,
    ConformanceReport,
    ObservedResponse,
    ReferenceCall,
)
from datalox_gated_runtime.reference.comparison import compare_json


COMPILED_BEHAVIOR_PROGRAM_SCHEMA_ID = "datalox_compiled_behavior_program_v1"
_DEFAULT_MAX_PROGRAM_BYTES = 16 * 1024 * 1024


class BehaviorProgramTarget(Protocol):
    target_id: str
    target_version: str

    def reset(self, seed: int) -> None: ...

    def execute(
        self,
        call: ReferenceCall,
        *,
        principal_context_id: str,
    ) -> ObservedResponse: ...


@dataclass(frozen=True)
class TemplateBinding:
    pointer: str
    binding_id: str
    kind: str
    prefix: str = ""
    suffix: str = ""

    def __post_init__(self) -> None:
        _pointer_components(self.pointer)
        _nonempty_string(self.binding_id, path="template_binding.binding_id")
        if self.kind not in {"whole", "composed"}:
            raise BehaviorContractError("template binding kind is unsupported")
        if type(self.prefix) is not str or type(self.suffix) is not str:
            raise BehaviorContractError("template binding affixes must be strings")
        if self.kind == "whole" and (self.prefix or self.suffix):
            raise BehaviorContractError("whole template binding cannot declare affixes")
        if self.kind == "composed" and not (self.prefix or self.suffix):
            raise BehaviorContractError("composed template binding requires an affix")

    def marker(self) -> JsonValue:
        if self.kind == "whole":
            return MappingProxyType({"$binding": self.binding_id})
        return MappingProxyType(
            {
                "$composed_binding": MappingProxyType(
                    {
                        "prefix": self.prefix,
                        "binding_id": self.binding_id,
                        "suffix": self.suffix,
                    }
                )
            }
        )

    def to_dict(self) -> dict[str, str]:
        result = {
            "pointer": self.pointer,
            "binding_id": self.binding_id,
            "kind": self.kind,
        }
        if self.kind == "composed":
            result["prefix"] = self.prefix
            result["suffix"] = self.suffix
        return result

    @classmethod
    def from_dict(cls, value: Any) -> TemplateBinding:
        raw = _shape(
            value,
            path="template_binding",
            required={"pointer", "binding_id", "kind"},
            optional={"prefix", "suffix"},
        )
        return cls(
            pointer=raw["pointer"],
            binding_id=raw["binding_id"],
            kind=raw["kind"],
            prefix=raw.get("prefix", ""),
            suffix=raw.get("suffix", ""),
        )


@dataclass(frozen=True)
class CompiledBehaviorAttempt:
    attempt_number: int
    expected_status_code: int
    expected_body_template: JsonValue
    expected_headers: Mapping[str, str]
    template_bindings: tuple[TemplateBinding, ...] = ()
    introduced_bindings: tuple[BindingSpec, ...] = ()

    def __post_init__(self) -> None:
        if type(self.attempt_number) is not int or self.attempt_number < 1:
            raise BehaviorContractError("compiled attempt number must be positive")
        response = ObservedResponse(
            status_code=self.expected_status_code,
            body=self.expected_body_template,
            headers=self.expected_headers,
        )
        object.__setattr__(self, "expected_body_template", response.body)
        object.__setattr__(self, "expected_headers", response.headers)
        template_bindings = tuple(self.template_bindings)
        if not all(isinstance(item, TemplateBinding) for item in template_bindings):
            raise BehaviorContractError("compiled attempt has an invalid template binding")
        pointers = [item.pointer for item in template_bindings]
        if len(pointers) != len(set(pointers)) or _pointers_overlap(pointers):
            raise BehaviorContractError("compiled attempt template binding pointers overlap")
        for binding in template_bindings:
            if _pointer_value(response.body, binding.pointer) != binding.marker():
                raise BehaviorContractError(
                    "compiled attempt template marker does not match its declaration"
                )
        object.__setattr__(self, "template_bindings", template_bindings)
        introduced = tuple(self.introduced_bindings)
        if not all(isinstance(item, BindingSpec) for item in introduced):
            raise BehaviorContractError("compiled attempt has an invalid introduced binding")
        object.__setattr__(self, "introduced_bindings", introduced)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "expected_response": {
                "status_code": self.expected_status_code,
                "body": thaw_json(self.expected_body_template),
                "headers": dict(self.expected_headers),
            },
            "template_bindings": [item.to_dict() for item in self.template_bindings],
            "introduced_bindings": [item.to_dict() for item in self.introduced_bindings],
        }

    @classmethod
    def from_dict(cls, value: Any) -> CompiledBehaviorAttempt:
        raw = _shape(
            value,
            path="compiled_attempt",
            required={
                "attempt_number",
                "expected_response",
                "template_bindings",
                "introduced_bindings",
            },
        )
        response = ObservedResponse.from_dict(raw["expected_response"])
        return cls(
            attempt_number=raw["attempt_number"],
            expected_status_code=response.status_code,
            expected_body_template=response.body,
            expected_headers=response.headers,
            template_bindings=tuple(
                TemplateBinding.from_dict(item)
                for item in _array(raw["template_bindings"], path="template_bindings")
            ),
            introduced_bindings=tuple(
                BindingSpec.from_dict(item)
                for item in _array(raw["introduced_bindings"], path="introduced_bindings")
            ),
        )


@dataclass(frozen=True)
class CompiledBehaviorStep:
    step_id: str
    operation_id: str
    kind: str
    role: str
    expected_outcome: str
    subject_id: str
    auth_context_id: str
    request: RequestTemplate
    poll: PollSpec | None
    expected_attempts: tuple[CompiledBehaviorAttempt, ...]
    bindings: tuple[BindingSpec, ...]

    def __post_init__(self) -> None:
        _nonempty_string(self.step_id, path="compiled_step.step_id")
        _nonempty_string(self.operation_id, path="compiled_step.operation_id")
        for name in ("kind", "role", "expected_outcome", "subject_id", "auth_context_id"):
            _nonempty_string(getattr(self, name), path=f"compiled_step.{name}")
        if not isinstance(self.request, RequestTemplate):
            raise BehaviorContractError("compiled step request is invalid")
        if self.poll is not None and not isinstance(self.poll, PollSpec):
            raise BehaviorContractError("compiled step poll contract is invalid")
        attempts = tuple(self.expected_attempts)
        if not attempts or not all(isinstance(item, CompiledBehaviorAttempt) for item in attempts):
            raise BehaviorContractError("compiled step must contain attempts")
        if tuple(item.attempt_number for item in attempts) != tuple(range(1, len(attempts) + 1)):
            raise BehaviorContractError("compiled attempt numbers must be contiguous")
        object.__setattr__(self, "expected_attempts", attempts)
        bindings = tuple(self.bindings)
        if not all(isinstance(item, BindingSpec) for item in bindings):
            raise BehaviorContractError("compiled step bindings are invalid")
        object.__setattr__(self, "bindings", bindings)

    @property
    def expected_status_code(self) -> int:
        return self.expected_attempts[-1].expected_status_code

    @property
    def expected_body_template(self) -> JsonValue:
        return self.expected_attempts[-1].expected_body_template

    @property
    def expected_headers(self) -> Mapping[str, str]:
        return self.expected_attempts[-1].expected_headers

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "operation_id": self.operation_id,
            "kind": self.kind,
            "role": self.role,
            "expected_outcome": self.expected_outcome,
            "subject_id": self.subject_id,
            "auth_context_id": self.auth_context_id,
            "request": self.request.to_dict(),
            "poll": None if self.poll is None else self.poll.to_dict(),
            "expected_attempts": [item.to_dict() for item in self.expected_attempts],
            "bindings": [item.to_dict() for item in self.bindings],
        }

    @classmethod
    def from_dict(cls, value: Any) -> CompiledBehaviorStep:
        raw = _shape(
            value,
            path="compiled_step",
            required={
                "step_id",
                "operation_id",
                "kind",
                "role",
                "expected_outcome",
                "subject_id",
                "auth_context_id",
                "request",
                "poll",
                "expected_attempts",
                "bindings",
            },
        )
        return cls(
            step_id=raw["step_id"],
            operation_id=raw["operation_id"],
            kind=raw["kind"],
            role=raw["role"],
            expected_outcome=raw["expected_outcome"],
            subject_id=raw["subject_id"],
            auth_context_id=raw["auth_context_id"],
            request=RequestTemplate.from_dict(raw["request"]),
            poll=None if raw["poll"] is None else PollSpec.from_dict(raw["poll"]),
            expected_attempts=tuple(
                CompiledBehaviorAttempt.from_dict(item)
                for item in _array(raw["expected_attempts"], path="expected_attempts")
            ),
            bindings=tuple(
                BindingSpec.from_dict(item) for item in _array(raw["bindings"], path="bindings")
            ),
        )


@dataclass(frozen=True)
class CompiledBehaviorProgram:
    provider_id: str
    provider_version: str
    seed: int
    capture_sha256: str
    connector_sha256: str
    connector_canonical_sha256: str
    recipe_sha256: str
    recipe_canonical_sha256: str
    harvest_engine_id: str
    harvest_engine_version: str
    harvest_engine_sha256: str
    static_input_sha256: Mapping[str, str]
    static_artifact_sha256: Mapping[str, str]
    steps: tuple[CompiledBehaviorStep, ...]
    observed_relations: Mapping[str, str]
    recipe: BehaviorRecipe
    complete: bool = True
    schema_id: str = COMPILED_BEHAVIOR_PROGRAM_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != COMPILED_BEHAVIOR_PROGRAM_SCHEMA_ID:
            raise BehaviorContractError("compiled behavior program schema is unsupported")
        if self.complete is not True:
            raise BehaviorContractError("compiled behavior program must be complete")
        _nonempty_string(self.provider_id, path="compiled_program.provider_id")
        _nonempty_string(self.provider_version, path="compiled_program.provider_version")
        if type(self.seed) is not int:
            raise BehaviorContractError("compiled program seed must be an integer")
        for name in (
            "capture_sha256",
            "connector_sha256",
            "connector_canonical_sha256",
            "recipe_sha256",
            "recipe_canonical_sha256",
            "harvest_engine_sha256",
        ):
            _sha256(getattr(self, name), path=f"compiled_program.{name}")
        _nonempty_string(
            self.harvest_engine_id,
            path="compiled_program.harvest_engine_id",
        )
        _nonempty_string(
            self.harvest_engine_version,
            path="compiled_program.harvest_engine_version",
        )
        object.__setattr__(
            self,
            "static_input_sha256",
            _digest_mapping(
                self.static_input_sha256,
                path="compiled_program.static_input_sha256",
            ),
        )
        object.__setattr__(
            self,
            "static_artifact_sha256",
            _digest_mapping(
                self.static_artifact_sha256,
                path="compiled_program.static_artifact_sha256",
            ),
        )
        if not isinstance(self.recipe, BehaviorRecipe) or self.recipe.seed != self.seed:
            raise BehaviorContractError("compiled program recipe or seed is invalid")
        if canonical_contract_digest(self.recipe) != self.recipe_canonical_sha256:
            raise BehaviorContractError("compiled recipe does not match recipe_canonical_sha256")
        steps = tuple(self.steps)
        if len(steps) != len(self.recipe.steps):
            raise BehaviorContractError("compiled program does not exactly cover its recipe")
        available: set[str] = set()
        for compiled, declared in zip(steps, self.recipe.steps, strict=True):
            if (
                compiled.step_id != declared.step_id
                or compiled.operation_id != declared.operation_id
                or compiled.kind != declared.kind
                or compiled.role != declared.role
                or compiled.expected_outcome != declared.expected_outcome
                or compiled.subject_id != declared.subject_id
                or compiled.auth_context_id != declared.auth_context_id
                or compiled.request != declared.request
                or compiled.poll != declared.poll
                or compiled.bindings != declared.bindings
            ):
                raise BehaviorContractError("compiled step does not match its recipe")
            introduced = tuple(
                binding
                for attempt in compiled.expected_attempts
                for binding in attempt.introduced_bindings
            )
            if introduced != declared.bindings:
                raise BehaviorContractError(
                    "compiled binding introductions do not match the recipe"
                )
            for attempt in compiled.expected_attempts:
                available.update(item.binding_id for item in attempt.introduced_bindings)
                if {item.binding_id for item in attempt.template_bindings} - available:
                    raise BehaviorContractError(
                        "compiled template references a binding before it is available"
                    )
        object.__setattr__(self, "steps", steps)
        relations = dict(self.observed_relations)
        if any(
            type(key) is not str or value not in {"changed", "equal"}
            for key, value in relations.items()
        ):
            raise BehaviorContractError("compiled observed relations are invalid")
        object.__setattr__(self, "observed_relations", MappingProxyType(relations))

    def behavior_to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "seed": self.seed,
            "program_id": self.recipe.program_id,
            "complete": self.complete,
            "steps": [item.to_dict() for item in self.steps],
            "observed_relations": dict(self.observed_relations),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "capture_sha256": self.capture_sha256,
            "connector_sha256": self.connector_sha256,
            "connector_canonical_sha256": self.connector_canonical_sha256,
            "recipe_sha256": self.recipe_sha256,
            "recipe_canonical_sha256": self.recipe_canonical_sha256,
            "harvest_engine": {
                "engine_id": self.harvest_engine_id,
                "engine_version": self.harvest_engine_version,
                "source_sha256": self.harvest_engine_sha256,
            },
            "static_input_sha256": dict(self.static_input_sha256),
            "static_artifact_sha256": dict(self.static_artifact_sha256),
            **self.behavior_to_dict(),
            "recipe": self.recipe.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> CompiledBehaviorProgram:
        raw = _shape(
            value,
            path="compiled_program",
            required={
                "schema_id",
                "provider_id",
                "provider_version",
                "seed",
                "program_id",
                "complete",
                "capture_sha256",
                "connector_sha256",
                "connector_canonical_sha256",
                "recipe_sha256",
                "recipe_canonical_sha256",
                "harvest_engine",
                "static_input_sha256",
                "static_artifact_sha256",
                "steps",
                "observed_relations",
                "recipe",
            },
        )
        recipe = BehaviorRecipe.from_dict(raw["recipe"])
        engine = EngineIdentity.from_dict(raw["harvest_engine"])
        if raw["program_id"] != recipe.program_id:
            raise BehaviorContractError("compiled program_id does not match its recipe")
        if not isinstance(raw["observed_relations"], Mapping):
            raise BehaviorContractError("compiled observed_relations must be an object")
        return cls(
            schema_id=raw["schema_id"],
            provider_id=raw["provider_id"],
            provider_version=raw["provider_version"],
            seed=raw["seed"],
            capture_sha256=raw["capture_sha256"],
            connector_sha256=raw["connector_sha256"],
            connector_canonical_sha256=raw["connector_canonical_sha256"],
            recipe_sha256=raw["recipe_sha256"],
            recipe_canonical_sha256=raw["recipe_canonical_sha256"],
            harvest_engine_id=engine.engine_id,
            harvest_engine_version=engine.engine_version,
            harvest_engine_sha256=engine.source_sha256,
            static_input_sha256=raw["static_input_sha256"],
            static_artifact_sha256=raw["static_artifact_sha256"],
            steps=tuple(
                CompiledBehaviorStep.from_dict(item) for item in _array(raw["steps"], path="steps")
            ),
            observed_relations=raw["observed_relations"],
            recipe=recipe,
            complete=raw["complete"],
        )


def compile_loaded_v3_capture(loaded: LoadedCapture) -> CompiledBehaviorProgram:
    if not isinstance(loaded, LoadedCapture):
        raise BehaviorContractError("compiled behavior input must come from load_capture()")
    return _compile_v3_capture(loaded.value, capture_sha256=loaded.exact_sha256)


def _compile_v3_capture(
    capture: BehaviorCapture,
    *,
    capture_sha256: str,
) -> CompiledBehaviorProgram:
    if not isinstance(capture, BehaviorCapture):
        raise BehaviorContractError("compiled behavior input must be a validated V3 capture")
    _sha256(capture_sha256, path="capture_sha256")
    groups = _logical_exchange_groups(capture.recipe.steps, capture.exchanges)
    occurrence_map = _occurrence_map(capture.recipe)
    compiled_steps: list[CompiledBehaviorStep] = []
    for step, group in zip(capture.recipe.steps, groups, strict=True):
        introduced = _introduced_bindings_by_attempt(
            step=step,
            exchanges=group,
            captured_bindings=capture.bindings,
        )
        attempts: list[CompiledBehaviorAttempt] = []
        for index, exchange in enumerate(group):
            template_bindings = _matching_template_bindings(
                exchange.body,
                occurrence_map.get(step.step_id, ()),
                captured_bindings=capture.bindings,
            )
            attempts.append(
                CompiledBehaviorAttempt(
                    attempt_number=exchange.attempt_number or 1,
                    expected_status_code=exchange.status_code,
                    expected_body_template=_project_body(exchange.body, template_bindings),
                    expected_headers=exchange.headers,
                    template_bindings=template_bindings,
                    introduced_bindings=introduced[index],
                )
            )
        compiled_steps.append(
            CompiledBehaviorStep(
                step_id=step.step_id,
                operation_id=step.operation_id,
                kind=step.kind,
                role=step.role,
                expected_outcome=step.expected_outcome,
                subject_id=step.subject_id,
                auth_context_id=step.auth_context_id,
                request=step.request,
                poll=step.poll,
                expected_attempts=tuple(attempts),
                bindings=step.bindings,
            )
        )
    return CompiledBehaviorProgram(
        provider_id=capture.connector.provider_id,
        provider_version=capture.connector.provider_version,
        seed=capture.recipe.seed,
        capture_sha256=capture_sha256,
        connector_sha256=capture.connector_sha256,
        connector_canonical_sha256=capture.connector_canonical_sha256,
        recipe_sha256=capture.recipe_sha256,
        recipe_canonical_sha256=capture.recipe_canonical_sha256,
        harvest_engine_id=capture.engine.engine_id,
        harvest_engine_version=capture.engine.engine_version,
        harvest_engine_sha256=capture.engine.source_sha256,
        static_input_sha256={
            item.input_id: item.body_sha256 for item in capture.static_input_receipts
        },
        static_artifact_sha256={
            item.artifact_id: item.body_sha256 for item in capture.static_artifact_receipts
        },
        steps=tuple(compiled_steps),
        observed_relations=capture.observed_relations,
        recipe=capture.recipe,
    )


def compile_v3_reference_program(
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
) -> CompiledBehaviorProgram:
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
    return compile_loaded_v3_capture(loaded)


def run_compiled_behavior_program(
    *,
    target: BehaviorProgramTarget,
    program: CompiledBehaviorProgram,
) -> ConformanceReport:
    report = ConformanceReport(
        trace_schema_id=REFERENCE_TRACE_SCHEMA_ID,
        trace_digest=program.capture_sha256,
        provider_id=program.provider_id,
        provider_version=program.provider_version,
        target_id=target.target_id,
        target_version=target.target_version,
        profile_id=DIFFERENTIAL_COMPARISON_PROFILE,
        seed=program.seed,
    )
    mismatches: list[ConformanceMismatch] = []
    try:
        target.reset(program.seed)
    except Exception as error:
        return _report_with(report, [_target_error("target_reset_error", error)])
    bindings: dict[str, JsonValue] = {}
    actual_terminal_bodies: dict[str, JsonValue] = {}
    for step in program.steps:
        try:
            call = _resolve_call(step, bindings)
        except Exception as error:
            mismatches.append(
                _target_error("compiled_program_resolution_error", error, step_id=step.step_id)
            )
            break
        completed = True
        for attempt in step.expected_attempts:
            attempt_id = (
                step.step_id
                if len(step.expected_attempts) == 1
                else f"{step.step_id}:attempt:{attempt.attempt_number}"
            )
            try:
                actual = target.execute(
                    call,
                    principal_context_id=step.auth_context_id,
                )
            except Exception as error:
                mismatches.append(
                    _target_error("target_execution_error", error, step_id=attempt_id)
                )
                completed = False
                break
            if not isinstance(actual, ObservedResponse):
                mismatches.append(
                    ConformanceMismatch(
                        code="target_response_contract_error",
                        path="",
                        expected={"type": "ObservedResponse"},
                        actual={"type": type(actual).__name__},
                        step_id=attempt_id,
                    )
                )
                completed = False
                break
            try:
                for binding in attempt.introduced_bindings:
                    observed = _pointer_value(actual.body, binding.pointer)
                    if not generated_binding_value_matches(observed, binding.value_type):
                        raise BehaviorContractError(
                            f"target binding {binding.binding_id!r} has the wrong type",
                            code="binding_coercion_invalid",
                        )
                    bindings[binding.binding_id] = observed
                expected = ObservedResponse(
                    status_code=attempt.expected_status_code,
                    body=_resolve_expected_body(attempt, bindings),
                    headers=attempt.expected_headers,
                )
            except Exception as error:
                mismatches.append(
                    _target_error("compiled_program_resolution_error", error, step_id=attempt_id)
                )
                completed = False
                break
            actual_terminal_bodies[step.step_id] = actual.body
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
                        step_id=attempt_id,
                    )
                )
        if not completed:
            break
    if len(actual_terminal_bodies) == len(program.steps):
        actual_relations = _compute_relations(program, actual_terminal_bodies)
        for difference in compare_json(
            freeze_json(dict(program.observed_relations)),
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
    return _report_with(report, mismatches)


def write_compiled_behavior_program(
    path: os.PathLike[str] | str,
    program: CompiledBehaviorProgram,
) -> str:
    target = Path(path)
    if not target.parent.is_dir():
        raise BehaviorContractError("compiled behavior output directory does not exist")
    payload = _compiled_behavior_program_bytes(program)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise BehaviorContractError("compiled behavior output already exists") from error
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    return compiled_behavior_program_sha256(program)


def compiled_behavior_program_sha256(program: CompiledBehaviorProgram) -> str:
    """Digest the exact canonical bytes emitted by the portable-program writer."""

    return sha256_digest(_compiled_behavior_program_bytes(program))


def load_compiled_behavior_program(
    path: os.PathLike[str] | str,
    *,
    expected_sha256: str,
    max_bytes: int = _DEFAULT_MAX_PROGRAM_BYTES,
) -> CompiledBehaviorProgram:
    _sha256(expected_sha256, path="expected_sha256")
    if type(max_bytes) is not int or max_bytes < 1:
        raise BehaviorContractError("compiled program max_bytes must be positive")
    flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(Path(path), flags)
    except OSError as error:
        raise BehaviorContractError("compiled program cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BehaviorContractError("compiled program must be a regular file")
        if metadata.st_size > max_bytes:
            raise BehaviorContractError("compiled program exceeds max_bytes")
        with os.fdopen(descriptor, "rb") as input_file:
            descriptor = -1
            payload = input_file.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > max_bytes:
        raise BehaviorContractError("compiled program exceeds max_bytes")
    if sha256_digest(payload) != expected_sha256:
        raise BehaviorContractError("compiled program digest does not match expected_sha256")
    try:
        raw = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except BehaviorContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
        raise BehaviorContractError(
            "compiled program must contain exactly one UTF-8 JSON value"
        ) from error
    return CompiledBehaviorProgram.from_dict(raw)


def _occurrence_map(recipe: BehaviorRecipe) -> Mapping[str, tuple[TemplateBinding, ...]]:
    result: dict[str, list[TemplateBinding]] = {}
    for step in recipe.steps:
        for binding in step.bindings:
            for occurrence in binding.response_occurrences:
                result.setdefault(occurrence.step_id, []).append(
                    TemplateBinding(
                        pointer=occurrence.pointer,
                        binding_id=binding.binding_id,
                        kind="whole",
                    )
                )
            for occurrence in binding.composed_string_occurrences:
                result.setdefault(occurrence.step_id, []).append(
                    _composed_template_binding(occurrence)
                )
    return MappingProxyType(
        {
            step_id: tuple(sorted(items, key=lambda item: item.pointer))
            for step_id, items in result.items()
        }
    )


def _composed_template_binding(
    occurrence: ComposedStringBindingOccurrence,
) -> TemplateBinding:
    return TemplateBinding(
        pointer=occurrence.pointer,
        binding_id=occurrence.binding_id,
        kind="composed",
        prefix=occurrence.prefix,
        suffix=occurrence.suffix,
    )


def _matching_template_bindings(
    body: JsonValue,
    declarations: tuple[TemplateBinding, ...],
    *,
    captured_bindings: Mapping[str, JsonValue],
) -> tuple[TemplateBinding, ...]:
    result: list[TemplateBinding] = []
    for declaration in declarations:
        try:
            observed = _pointer_value(body, declaration.pointer)
        except BehaviorContractError:
            continue
        captured = captured_bindings[declaration.binding_id]
        expected = (
            captured
            if declaration.kind == "whole"
            else f"{declaration.prefix}{captured}{declaration.suffix}"
        )
        if type(observed) is type(expected) and observed == expected:
            result.append(declaration)
    return tuple(result)


def _introduced_bindings_by_attempt(
    *,
    step: BehaviorStep,
    exchanges: tuple[CapturedExchange, ...],
    captured_bindings: Mapping[str, JsonValue],
) -> tuple[tuple[BindingSpec, ...], ...]:
    result: list[list[BindingSpec]] = [[] for _ in exchanges]
    for binding in step.bindings:
        captured = captured_bindings[binding.binding_id]
        for index, exchange in enumerate(exchanges):
            try:
                observed = _pointer_value(exchange.body, binding.pointer)
            except BehaviorContractError:
                continue
            if type(observed) is type(captured) and observed == captured:
                result[index].append(binding)
                break
        else:
            raise BehaviorContractError(
                f"binding {binding.binding_id!r} was not observed in its defining step",
                code="binding_occurrence_invalid",
            )
    return tuple(tuple(items) for items in result)


def _project_body(
    body: JsonValue,
    bindings: tuple[TemplateBinding, ...],
) -> JsonValue:
    by_pointer = {item.pointer: item for item in bindings}

    def project(value: JsonValue, pointer: str) -> JsonValue:
        binding = by_pointer.get(pointer)
        if binding is not None:
            return binding.marker()
        if isinstance(value, Mapping):
            return MappingProxyType(
                {key: project(item, _pointer_child(pointer, key)) for key, item in value.items()}
            )
        if isinstance(value, tuple):
            return tuple(
                project(item, _pointer_child(pointer, str(index)))
                for index, item in enumerate(value)
            )
        return value

    return project(body, "")


def _resolve_expected_body(
    attempt: CompiledBehaviorAttempt,
    bindings: Mapping[str, JsonValue],
) -> JsonValue:
    by_pointer = {item.pointer: item for item in attempt.template_bindings}

    def resolve(value: JsonValue, pointer: str) -> JsonValue:
        declaration = by_pointer.get(pointer)
        if declaration is not None:
            if declaration.binding_id not in bindings:
                raise BehaviorContractError(f"binding {declaration.binding_id!r} is unavailable")
            bound = bindings[declaration.binding_id]
            if declaration.kind == "whole":
                return bound
            if type(bound) is not str:
                raise BehaviorContractError("composed binding value must be a string")
            return f"{declaration.prefix}{bound}{declaration.suffix}"
        if isinstance(value, Mapping):
            return MappingProxyType(
                {key: resolve(item, _pointer_child(pointer, key)) for key, item in value.items()}
            )
        if isinstance(value, tuple):
            return tuple(
                resolve(item, _pointer_child(pointer, str(index)))
                for index, item in enumerate(value)
            )
        return value

    return resolve(attempt.expected_body_template, "")


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


def _resolve_request_bindings(value: Any, bindings: Mapping[str, JsonValue]) -> Any:
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


def _compute_relations(
    program: CompiledBehaviorProgram,
    bodies: Mapping[str, JsonValue],
) -> Mapping[str, str]:
    result: dict[str, str] = {}
    for step in program.recipe.steps:
        for assertion in step.assertions:
            if assertion.kind != "state_observe_step":
                continue
            assert assertion.pointer is not None
            assert assertion.prior_pointer is not None
            assert assertion.prior_step_id is not None
            current = _pointer_value(bodies[step.step_id], assertion.pointer)
            prior = _pointer_value(bodies[assertion.prior_step_id], assertion.prior_pointer)
            result[f"{step.step_id}.{assertion.assertion_id}"] = (
                "equal" if current == prior else "changed"
            )
    return MappingProxyType(result)


def _pointer_value(value: JsonValue, pointer: str) -> JsonValue:
    current = value
    for component in _pointer_components(pointer):
        if isinstance(current, Mapping):
            if component not in current:
                raise BehaviorContractError(f"JSON pointer {pointer!r} does not exist")
            current = current[component]
        elif isinstance(current, tuple):
            if not component.isascii() or not component.isdigit():
                raise BehaviorContractError(f"JSON pointer {pointer!r} has a non-index")
            index = int(component)
            if index >= len(current):
                raise BehaviorContractError(f"JSON pointer {pointer!r} does not exist")
            current = current[index]
        else:
            raise BehaviorContractError(f"JSON pointer {pointer!r} traverses a scalar")
    return current


def _pointer_components(pointer: str) -> tuple[str, ...]:
    if type(pointer) is not str or (pointer and not pointer.startswith("/")):
        raise BehaviorContractError("JSON pointer is invalid")
    result: list[str] = []
    for raw in pointer.split("/")[1:] if pointer else ():
        if "~" in raw.replace("~0", "").replace("~1", ""):
            raise BehaviorContractError("JSON pointer escaping is invalid")
        result.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(result)


def _pointer_child(pointer: str, component: str) -> str:
    escaped = component.replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{escaped}"


def _pointers_overlap(pointers: list[str]) -> bool:
    components = [_pointer_components(item) for item in pointers]
    return any(
        left[: len(right)] == right or right[: len(left)] == left
        for index, left in enumerate(components)
        for right in components[index + 1 :]
    )


def _target_error(
    code: str,
    error: Exception,
    *,
    step_id: str | None = None,
) -> ConformanceMismatch:
    if getattr(error, "code", None) == "binding_coercion_invalid":
        code = "binding_coercion_invalid"
    return ConformanceMismatch(
        code=code,
        path="",
        expected={"completed": True},
        actual={"error_type": type(error).__name__},
        step_id=step_id,
    )


def _report_with(
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


def _shape(
    value: Any,
    *,
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise BehaviorContractError(f"{path} must be an object")
    allowed = required | (set() if optional is None else optional)
    if missing := sorted(required - value.keys()):
        raise BehaviorContractError(f"{path} is missing fields: {', '.join(missing)}")
    if unknown := sorted(value.keys() - allowed):
        raise BehaviorContractError(f"{path} has unknown fields: {', '.join(unknown)}")
    return value


def _array(value: Any, *, path: str) -> list[Any]:
    if type(value) is not list:
        raise BehaviorContractError(f"{path} must be an array")
    return value


def _nonempty_string(value: Any, *, path: str) -> str:
    if type(value) is not str or not value:
        raise BehaviorContractError(f"{path} must be a non-empty string")
    return value


def _sha256(value: Any, *, path: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise BehaviorContractError(f"{path} must be an exact sha256 digest")
    return value


def _digest_mapping(value: Any, *, path: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise BehaviorContractError(f"{path} must be an object")
    result: dict[str, str] = {}
    for key, digest in value.items():
        if type(key) is not str or not key or key.strip() != key:
            raise BehaviorContractError(f"{path} keys must be canonical non-empty strings")
        result[key] = _sha256(digest, path=f"{path}.{key}")
    return MappingProxyType(dict(sorted(result.items())))


def _compiled_behavior_program_bytes(program: CompiledBehaviorProgram) -> bytes:
    if not isinstance(program, CompiledBehaviorProgram):
        raise BehaviorContractError("compiled behavior program is invalid")
    return canonical_json_bytes(program.to_dict()) + b"\n"


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BehaviorContractError(f"compiled program contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise BehaviorContractError(f"compiled program contains non-finite number {value}")
