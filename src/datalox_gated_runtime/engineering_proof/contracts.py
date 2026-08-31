from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from datalox_gated_runtime.reference import ConformanceReport, SequenceTarget
from datalox_gated_runtime.reference.contracts import JsonValue, freeze_json, thaw_json

WORLD_TARGET_SPEC_SCHEMA = "datalox_world_target_spec_v2"
DIFFERENTIAL_PROGRAM_SPEC_SCHEMA = "datalox_differential_program_spec_v1"
ENGINEERING_PROOF_SCHEMA = "datalox_engineering_proof_v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class EngineeringProofContractError(ValueError):
    """A provider-neutral proof contract is invalid."""


def _object(value: Any, *, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EngineeringProofContractError(f"{path} must be an object")
    return value


def _shape(
    value: dict[str, Any],
    *,
    required: frozenset[str],
    path: str,
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required)
    if missing:
        raise EngineeringProofContractError(f"{path} is missing fields: {', '.join(missing)}")
    if unknown:
        raise EngineeringProofContractError(f"{path} has unknown fields: {', '.join(unknown)}")


def _string(value: Any, *, path: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise EngineeringProofContractError(f"{path} must be a non-empty canonical string")
    return value


def _identifier(value: Any, *, path: str) -> str:
    result = _string(value, path=path)
    if _IDENTIFIER.fullmatch(result) is None:
        raise EngineeringProofContractError(f"{path} must be a stable identifier")
    return result


def _digest(value: Any, *, path: str) -> str:
    result = _string(value, path=path)
    if _DIGEST.fullmatch(result) is None:
        raise EngineeringProofContractError(
            f"{path} must use sha256:<64 lowercase hexadecimal characters>"
        )
    return result


def _integer(value: Any, *, path: str) -> int:
    if type(value) is not int:
        raise EngineeringProofContractError(f"{path} must be an integer")
    return value


def _path_prefix(value: Any, *, path: str) -> str:
    result = _string(value, path=path)
    invalid_character = any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in result
    )
    if (
        not result.startswith("/")
        or "?" in result
        or "#" in result
        or invalid_character
        or (result != "/" and result.endswith("/"))
        or "//" in result
        or any(component in {".", ".."} for component in result.split("/"))
    ):
        raise EngineeringProofContractError(f"{path} must be a canonical absolute path prefix")
    return result


def _json_pointer(value: Any, *, path: str) -> str:
    pointer = _string(value, path=path)
    if not pointer.startswith("/"):
        raise EngineeringProofContractError(f"{path} must be a non-root JSON pointer")
    for component in pointer.split("/")[1:]:
        index = 0
        while index < len(component):
            if component[index] != "~":
                index += 1
                continue
            if index + 1 >= len(component) or component[index + 1] not in {"0", "1"}:
                raise EngineeringProofContractError(f"{path} contains an invalid escape")
            index += 2
    return pointer


def _array(value: Any, *, path: str) -> list[Any]:
    if type(value) is not list:
        raise EngineeringProofContractError(f"{path} must be an array")
    return value


def _prefixes_overlap(first: str, second: str) -> bool:
    if first == "/" or second == "/":
        return True
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


@dataclass(frozen=True)
class PathPrefixMapping:
    reference_prefix: str
    world_prefix: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reference_prefix",
            _path_prefix(self.reference_prefix, path="path_mapping.reference_prefix"),
        )
        object.__setattr__(
            self,
            "world_prefix",
            _path_prefix(self.world_prefix, path="path_mapping.world_prefix"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "reference_prefix": self.reference_prefix,
            "world_prefix": self.world_prefix,
        }

    @classmethod
    def from_dict(cls, value: Any) -> PathPrefixMapping:
        raw = _object(value, path="path_mapping")
        _shape(
            raw,
            required=frozenset({"reference_prefix", "world_prefix"}),
            path="path_mapping",
        )
        return cls(
            reference_prefix=raw["reference_prefix"],
            world_prefix=raw["world_prefix"],
        )


@dataclass(frozen=True)
class OperationMapping:
    reference_operation_id: str
    world_operation_id: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reference_operation_id",
            _identifier(
                self.reference_operation_id,
                path="operation_mapping.reference_operation_id",
            ),
        )
        object.__setattr__(
            self,
            "world_operation_id",
            _identifier(self.world_operation_id, path="operation_mapping.world_operation_id"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "reference_operation_id": self.reference_operation_id,
            "world_operation_id": self.world_operation_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> OperationMapping:
        raw = _object(value, path="operation_mapping")
        _shape(
            raw,
            required=frozenset({"reference_operation_id", "world_operation_id"}),
            path="operation_mapping",
        )
        return cls(
            reference_operation_id=raw["reference_operation_id"],
            world_operation_id=raw["world_operation_id"],
        )


@dataclass(frozen=True)
class PrincipalMapping:
    principal_context_id: str
    actor_id: str
    actor_role: str

    def __post_init__(self) -> None:
        for field_name in ("principal_context_id", "actor_id", "actor_role"):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), path=f"principal_mapping.{field_name}"),
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "principal_context_id": self.principal_context_id,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
        }

    @classmethod
    def from_dict(cls, value: Any) -> PrincipalMapping:
        raw = _object(value, path="principal_mapping")
        _shape(
            raw,
            required=frozenset({"principal_context_id", "actor_id", "actor_role"}),
            path="principal_mapping",
        )
        return cls(
            principal_context_id=raw["principal_context_id"],
            actor_id=raw["actor_id"],
            actor_role=raw["actor_role"],
        )


@dataclass(frozen=True)
class StaticValueMapping:
    """Declare equivalent fixed fixture identifiers across provider and world state."""

    reference_value: str
    world_value: str

    def __post_init__(self) -> None:
        for field_name in ("reference_value", "world_value"):
            object.__setattr__(
                self,
                field_name,
                _string(getattr(self, field_name), path=f"static_value_mapping.{field_name}"),
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "reference_value": self.reference_value,
            "world_value": self.world_value,
        }

    @classmethod
    def from_dict(cls, value: Any) -> StaticValueMapping:
        raw = _object(value, path="static_value_mapping")
        _shape(
            raw,
            required=frozenset({"reference_value", "world_value"}),
            path="static_value_mapping",
        )
        return cls(
            reference_value=raw["reference_value"],
            world_value=raw["world_value"],
        )


@dataclass(frozen=True)
class StateRecordOverride:
    """Align one target seed record with an observed provider precondition."""

    collection: str
    record_id: str
    value: JsonValue

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "collection",
            _identifier(self.collection, path="state_record_override.collection"),
        )
        object.__setattr__(
            self,
            "record_id",
            _string(self.record_id, path="state_record_override.record_id"),
        )
        object.__setattr__(self, "value", freeze_json(self.value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "collection": self.collection,
            "record_id": self.record_id,
            "value": thaw_json(self.value),
        }

    @classmethod
    def from_dict(cls, value: Any) -> StateRecordOverride:
        raw = _object(value, path="state_record_override")
        _shape(
            raw,
            required=frozenset({"collection", "record_id", "value"}),
            path="state_record_override",
        )
        return cls(
            collection=raw["collection"],
            record_id=raw["record_id"],
            value=raw["value"],
        )


@dataclass(frozen=True)
class GeneratedIdBinding:
    binding_id: str
    producer_operation_id: str
    response_pointer: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "binding_id",
            _identifier(self.binding_id, path="generated_id_binding.binding_id"),
        )
        object.__setattr__(
            self,
            "producer_operation_id",
            _identifier(
                self.producer_operation_id,
                path="generated_id_binding.producer_operation_id",
            ),
        )
        object.__setattr__(
            self,
            "response_pointer",
            _json_pointer(
                self.response_pointer,
                path="generated_id_binding.response_pointer",
            ),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "binding_id": self.binding_id,
            "producer_operation_id": self.producer_operation_id,
            "response_pointer": self.response_pointer,
        }

    @classmethod
    def from_dict(cls, value: Any) -> GeneratedIdBinding:
        raw = _object(value, path="generated_id_binding")
        _shape(
            raw,
            required=frozenset({"binding_id", "producer_operation_id", "response_pointer"}),
            path="generated_id_binding",
        )
        return cls(
            binding_id=raw["binding_id"],
            producer_operation_id=raw["producer_operation_id"],
            response_pointer=raw["response_pointer"],
        )


@dataclass(frozen=True)
class WorldTargetSpec:
    target_id: str
    target_version: str
    episode_id: str
    principal_mappings: tuple[PrincipalMapping, ...]
    path_mappings: tuple[PathPrefixMapping, ...]
    static_value_mappings: tuple[StaticValueMapping, ...] = ()
    state_record_overrides: tuple[StateRecordOverride, ...] = ()
    operation_mappings: tuple[OperationMapping, ...] = ()
    generated_id_bindings: tuple[GeneratedIdBinding, ...] = ()
    schema_version: str = WORLD_TARGET_SPEC_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != WORLD_TARGET_SPEC_SCHEMA:
            raise EngineeringProofContractError(
                f"unsupported world target schema: {self.schema_version}"
            )
        for field_name in ("target_id", "episode_id"):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), path=f"world_target.{field_name}"),
            )
        object.__setattr__(
            self,
            "target_version",
            _string(self.target_version, path="world_target.target_version"),
        )
        path_mappings = tuple(self.path_mappings)
        principal_mappings = tuple(self.principal_mappings)
        operation_mappings = tuple(self.operation_mappings)
        static_value_mappings = tuple(self.static_value_mappings)
        state_record_overrides = tuple(self.state_record_overrides)
        generated_id_bindings = tuple(self.generated_id_bindings)
        if not path_mappings or not all(
            isinstance(item, PathPrefixMapping) for item in path_mappings
        ):
            raise EngineeringProofContractError(
                "world_target.path_mappings must contain path-prefix mappings"
            )
        if not principal_mappings or not all(
            isinstance(item, PrincipalMapping) for item in principal_mappings
        ):
            raise EngineeringProofContractError(
                "world_target.principal_mappings must contain principal mappings"
            )
        if not all(isinstance(item, OperationMapping) for item in operation_mappings):
            raise EngineeringProofContractError(
                "world_target.operation_mappings contains an invalid mapping"
            )
        if not all(isinstance(item, StaticValueMapping) for item in static_value_mappings):
            raise EngineeringProofContractError(
                "world_target.static_value_mappings contains an invalid mapping"
            )
        if not all(isinstance(item, StateRecordOverride) for item in state_record_overrides):
            raise EngineeringProofContractError(
                "world_target.state_record_overrides contains an invalid override"
            )
        if not all(isinstance(item, GeneratedIdBinding) for item in generated_id_bindings):
            raise EngineeringProofContractError(
                "world_target.generated_id_bindings contains an invalid binding"
            )
        for index, first in enumerate(path_mappings):
            for second in path_mappings[index + 1 :]:
                if _prefixes_overlap(first.reference_prefix, second.reference_prefix):
                    raise EngineeringProofContractError(
                        "world_target.path_mappings contains overlapping reference prefixes"
                    )
        reference_operations = [item.reference_operation_id for item in operation_mappings]
        if len(reference_operations) != len(set(reference_operations)):
            raise EngineeringProofContractError(
                "world_target.operation_mappings contains duplicate reference operations"
            )
        binding_ids = [item.binding_id for item in generated_id_bindings]
        if len(binding_ids) != len(set(binding_ids)):
            raise EngineeringProofContractError(
                "world_target.generated_id_bindings contains duplicate binding ids"
            )
        principal_context_ids = [item.principal_context_id for item in principal_mappings]
        if len(principal_context_ids) != len(set(principal_context_ids)):
            raise EngineeringProofContractError(
                "world_target.principal_mappings contains duplicate principal contexts"
            )
        reference_values = [item.reference_value for item in static_value_mappings]
        world_values = [item.world_value for item in static_value_mappings]
        if len(reference_values) != len(set(reference_values)) or len(world_values) != len(
            set(world_values)
        ):
            raise EngineeringProofContractError(
                "world_target.static_value_mappings must be one-to-one"
            )
        state_keys = [(item.collection, item.record_id) for item in state_record_overrides]
        if len(state_keys) != len(set(state_keys)):
            raise EngineeringProofContractError(
                "world_target.state_record_overrides contains duplicate records"
            )
        if operation_mappings:
            missing = sorted(
                {
                    item.producer_operation_id
                    for item in generated_id_bindings
                    if item.producer_operation_id not in set(reference_operations)
                }
            )
            if missing:
                raise EngineeringProofContractError(
                    "generated binding producers are absent from explicit operation mappings: "
                    + ", ".join(missing)
                )
        object.__setattr__(self, "path_mappings", path_mappings)
        object.__setattr__(self, "principal_mappings", principal_mappings)
        object.__setattr__(self, "static_value_mappings", static_value_mappings)
        object.__setattr__(self, "state_record_overrides", state_record_overrides)
        object.__setattr__(self, "operation_mappings", operation_mappings)
        object.__setattr__(self, "generated_id_bindings", generated_id_bindings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_id": self.target_id,
            "target_version": self.target_version,
            "episode_id": self.episode_id,
            "principal_mappings": [item.to_dict() for item in self.principal_mappings],
            "path_mappings": [item.to_dict() for item in self.path_mappings],
            "static_value_mappings": [item.to_dict() for item in self.static_value_mappings],
            "state_record_overrides": [item.to_dict() for item in self.state_record_overrides],
            "operation_mappings": [item.to_dict() for item in self.operation_mappings],
            "generated_id_bindings": [item.to_dict() for item in self.generated_id_bindings],
        }

    @classmethod
    def from_dict(cls, value: Any) -> WorldTargetSpec:
        raw = _object(value, path="world_target")
        _shape(
            raw,
            required=frozenset(
                {
                    "schema_version",
                    "target_id",
                    "target_version",
                    "episode_id",
                    "principal_mappings",
                    "path_mappings",
                    "static_value_mappings",
                    "state_record_overrides",
                    "operation_mappings",
                    "generated_id_bindings",
                }
            ),
            path="world_target",
        )
        return cls(
            schema_version=raw["schema_version"],
            target_id=raw["target_id"],
            target_version=raw["target_version"],
            episode_id=raw["episode_id"],
            principal_mappings=tuple(
                PrincipalMapping.from_dict(item)
                for item in _array(
                    raw["principal_mappings"],
                    path="world_target.principal_mappings",
                )
            ),
            path_mappings=tuple(
                PathPrefixMapping.from_dict(item)
                for item in _array(raw["path_mappings"], path="world_target.path_mappings")
            ),
            static_value_mappings=tuple(
                StaticValueMapping.from_dict(item)
                for item in _array(
                    raw["static_value_mappings"],
                    path="world_target.static_value_mappings",
                )
            ),
            state_record_overrides=tuple(
                StateRecordOverride.from_dict(item)
                for item in _array(
                    raw["state_record_overrides"],
                    path="world_target.state_record_overrides",
                )
            ),
            operation_mappings=tuple(
                OperationMapping.from_dict(item)
                for item in _array(
                    raw["operation_mappings"],
                    path="world_target.operation_mappings",
                )
            ),
            generated_id_bindings=tuple(
                GeneratedIdBinding.from_dict(item)
                for item in _array(
                    raw["generated_id_bindings"],
                    path="world_target.generated_id_bindings",
                )
            ),
        )


@dataclass(frozen=True)
class DifferentialProgramSpec:
    program_id: str
    program_version: str
    provider_id: str
    provider_version: str
    trace_schema_id: str
    trace_digest: str
    seed: int
    schema_version: str = DIFFERENTIAL_PROGRAM_SPEC_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != DIFFERENTIAL_PROGRAM_SPEC_SCHEMA:
            raise EngineeringProofContractError(
                f"unsupported differential program schema: {self.schema_version}"
            )
        for field_name in ("program_id", "provider_id", "trace_schema_id"):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), path=f"program.{field_name}"),
            )
        for field_name in ("program_version", "provider_version"):
            object.__setattr__(
                self,
                field_name,
                _string(getattr(self, field_name), path=f"program.{field_name}"),
            )
        object.__setattr__(
            self,
            "trace_digest",
            _digest(self.trace_digest, path="program.trace_digest"),
        )
        object.__setattr__(self, "seed", _integer(self.seed, path="program.seed"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "program_id": self.program_id,
            "program_version": self.program_version,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "trace_schema_id": self.trace_schema_id,
            "trace_digest": self.trace_digest,
            "seed": self.seed,
        }

    @classmethod
    def from_dict(cls, value: Any) -> DifferentialProgramSpec:
        raw = _object(value, path="program")
        _shape(
            raw,
            required=frozenset(
                {
                    "schema_version",
                    "program_id",
                    "program_version",
                    "provider_id",
                    "provider_version",
                    "trace_schema_id",
                    "trace_digest",
                    "seed",
                }
            ),
            path="program",
        )
        return cls(**raw)


class DifferentialProgram(Protocol):
    spec: DifferentialProgramSpec

    def run(self, target: SequenceTarget) -> ConformanceReport: ...
