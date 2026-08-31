from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from datalox_gated_runtime.engineering_proof.contracts import (
    EngineeringProofContractError,
)
from datalox_gated_runtime.reference import ObservedResponse, ReferenceCall, SequenceTarget


@dataclass(frozen=True)
class PrincipalStepBinding:
    """Bind one immutable captured step to one explicit principal context."""

    step_id: str
    operation_id: str
    principal_context_id: str

    def __post_init__(self) -> None:
        for field_name in ("step_id", "operation_id", "principal_context_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value or value.strip() != value:
                raise EngineeringProofContractError(
                    f"principal step binding {field_name} must be a non-empty canonical string"
                )


class LegacyTraceTarget(Protocol):
    """Execution shape used by content-addressed harvest engines v1-v3."""

    target_id: str
    target_version: str

    def reset(self, seed: int) -> None: ...

    def execute(self, call: ReferenceCall) -> ObservedResponse: ...


class PrincipalBoundTraceTarget:
    """Adapt explicit per-step principals to immutable legacy differential engines."""

    def __init__(
        self,
        *,
        target: SequenceTarget,
        bindings: tuple[PrincipalStepBinding, ...],
    ) -> None:
        if not bindings:
            raise EngineeringProofContractError("principal step bindings must not be empty")
        step_ids = [item.step_id for item in bindings]
        if len(step_ids) != len(set(step_ids)):
            raise EngineeringProofContractError(
                "principal step bindings contain duplicate step ids"
            )
        self._target = target
        self._bindings = bindings
        self._index = 0
        self.target_id = target.target_id
        self.target_version = target.target_version

    def reset(self, seed: int) -> None:
        self._target.reset(seed)
        self._index = 0

    def execute(self, call: ReferenceCall) -> ObservedResponse:
        if self._index >= len(self._bindings):
            raise EngineeringProofContractError(
                "legacy trace executed more calls than its principal bindings declare"
            )
        binding = self._bindings[self._index]
        if call.operation_id != binding.operation_id:
            raise EngineeringProofContractError(
                "legacy trace operation does not match its ordered principal binding: "
                f"step={binding.step_id} expected={binding.operation_id} "
                f"actual={call.operation_id}"
            )
        self._index += 1
        return self._target.execute(
            call,
            principal_context_id=binding.principal_context_id,
        )


def principal_bindings_from_recipe_steps(
    steps: object,
) -> tuple[PrincipalStepBinding, ...]:
    """Compile declared recipe steps without coupling to a harvest engine version."""

    if not isinstance(steps, tuple) or not steps:
        raise EngineeringProofContractError("recipe steps must be a non-empty tuple")
    try:
        return tuple(
            PrincipalStepBinding(
                step_id=step.step_id,
                operation_id=step.operation_id,
                principal_context_id=step.auth_context_id,
            )
            for step in steps
        )
    except AttributeError as error:
        raise EngineeringProofContractError(
            "recipe step does not declare step, operation, and auth-context identity"
        ) from error
