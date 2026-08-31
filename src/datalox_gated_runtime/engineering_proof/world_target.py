from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from datalox_gated_runtime.engineering_proof.contracts import (
    EngineeringProofContractError,
    GeneratedIdBinding,
    PathPrefixMapping,
    WorldTargetSpec,
)
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.reference import JsonValue, ObservationRequest, ObservedResponse
from datalox_gated_runtime.reference.contracts import ReferenceCall, thaw_json
from datalox_gated_runtime.world_v1.backend import (
    WorldBundleBackend,
    initialize_world_bundle_session,
)
from datalox_gated_runtime.world_v1.contracts import ActorContext


class WorldBundleTraceTarget:
    """Execute a differential trace against a fresh admitted-world session."""

    def __init__(
        self,
        *,
        env_dir: Path,
        spec: WorldTargetSpec,
        reference_bindings: Mapping[str, str] | None = None,
    ) -> None:
        if not isinstance(spec, WorldTargetSpec):
            raise EngineeringProofContractError("world target spec is invalid")
        self.env_dir = env_dir.resolve()
        self.spec = spec
        self.target_id = spec.target_id
        self.target_version = spec.target_version
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._backend: WorldBundleBackend | None = None
        self._actors = {
            item.principal_context_id: ActorContext(item.actor_id, item.actor_role)
            for item in spec.principal_mappings
        }
        self._static_reference_to_world = {
            item.reference_value: item.world_value for item in spec.static_value_mappings
        }
        self._static_world_to_reference = {
            item.world_value: item.reference_value for item in spec.static_value_mappings
        }
        self._reference_bindings = self._validate_reference_bindings(reference_bindings or {})
        self._local_bindings: dict[str, str] = {}
        self._transcript: list[dict[str, Any]] = []
        self._reset_generation = 0

    def __enter__(self) -> WorldBundleTraceTarget:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _validate_reference_bindings(self, values: Mapping[str, str]) -> dict[str, str]:
        expected = {item.binding_id for item in self.spec.generated_id_bindings}
        if set(values) != expected:
            raise EngineeringProofContractError(
                "reference bindings must exactly match generated binding ids"
            )
        result: dict[str, str] = {}
        for binding_id, value in values.items():
            if type(value) is not str or not value:
                raise EngineeringProofContractError(
                    f"reference binding {binding_id!r} must be a non-empty string"
                )
            if value in result.values():
                raise EngineeringProofContractError("reference binding values must be unambiguous")
            result[binding_id] = value
        return result

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()
            self._backend = None
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None

    def reset(self, seed: int) -> None:
        if type(seed) is not int:
            raise EngineeringProofContractError("target reset seed must be an integer")
        self.close()
        self._temporary = tempfile.TemporaryDirectory(prefix="datalox-world-proof-")
        run_dir = Path(self._temporary.name) / "run"
        initialize_world_bundle_session(
            source_bundle_dir=self.env_dir,
            run_dir=run_dir,
            episode_id=self.spec.episode_id,
        )
        self._backend = WorldBundleBackend(
            run_dir=run_dir,
            configured_actor=None,
        )
        if self.spec.state_record_overrides:
            controller = ActorContext(
                "proof-fixture-controller",
                self.spec.principal_mappings[0].actor_role,
            )
            with self._backend.session.transaction(
                operation_id="engineering_proof.seed_override",
                actor=controller,
                tool_name=None,
                request={"override_count": len(self.spec.state_record_overrides)},
            ):
                for override in self.spec.state_record_overrides:
                    collection = self._backend.session.get_state(override.collection)
                    if not isinstance(collection, dict):
                        raise EngineeringProofContractError(
                            f"state override collection is not an object: {override.collection}"
                        )
                    collection[override.record_id] = thaw_json(override.value)
                    self._backend.session.set_state(override.collection, collection)
        self._local_bindings = {}
        self._transcript = []
        self._reset_generation += 1

    @property
    def reset_generation(self) -> int:
        return self._reset_generation

    def execute(
        self,
        call: ReferenceCall,
        *,
        principal_context_id: str,
    ) -> ObservedResponse:
        if self._backend is None:
            raise EngineeringProofContractError("world target must be reset before execution")
        try:
            actor = self._actors[principal_context_id]
        except KeyError as error:
            raise EngineeringProofContractError(
                "reference step principal is absent from explicit target mappings: "
                f"{principal_context_id}"
            ) from error
        mapped_path = self._map_path(call.path)
        mapped_path = self._replace_path_segments(mapped_path)
        mapped_operation = self._map_operation(call.operation_id)
        request = CallRequest(
            method=call.method,
            path=mapped_path,
            query=self._replace_values(thaw_json(call.query)),
            body=self._replace_values(thaw_json(call.body)),
            headers=dict(call.headers),
            operation_id=mapped_operation,
        )
        response = self._backend.handle_as(request, actor=actor)
        if response is None:
            raise EngineeringProofContractError(
                f"world has no route for {request.normalized_method()} {request.path}"
            )
        self._capture_generated_bindings(call.operation_id, response.body)
        self._transcript.append(
            {
                "request": {
                    "method": request.normalized_method(),
                    "path": self._normalize_path(request.path),
                    "query": self._normalize_values(dict(request.query)),
                    "body": self._normalize_values(request.body),
                    "headers": dict(sorted(request.headers.items())),
                    "operation_id": request.operation_id,
                    "principal_context_id": principal_context_id,
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                },
                "response": {
                    "status_code": response.status_code,
                    "body": self._normalize_values(response.body),
                    "headers": dict(sorted(response.headers.items())),
                    "is_mutation": response.is_mutation,
                    "decision_kind": response.decision_kind,
                    "operation_id": response.operation_id,
                    "reason_code": response.reason_code,
                    "message": response.message,
                },
            }
        )
        return ObservedResponse(
            status_code=response.status_code,
            body=self._restore_reference_values(response.body),
            headers=response.headers,
        )

    def observe(self, request: ObservationRequest) -> JsonValue:
        raise EngineeringProofContractError(
            f"world target has no declarative observation mapping for {request.observation_id!r}"
        )

    def behavioral_fingerprint(self) -> str:
        canonical = json.dumps(
            self._transcript,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def transcript(self) -> tuple[dict[str, Any], ...]:
        return tuple(json.loads(json.dumps(item)) for item in self._transcript)

    def _map_path(self, path: str) -> str:
        matches = [
            item for item in self.spec.path_mappings if _prefix_matches(path, item.reference_prefix)
        ]
        if len(matches) != 1:
            raise EngineeringProofContractError(
                f"reference path must match exactly one declared prefix: {path}"
            )
        mapping = matches[0]
        return _replace_prefix(path, mapping)

    def _map_operation(self, operation_id: str) -> str:
        if not self.spec.operation_mappings:
            return operation_id
        mapped = {
            item.reference_operation_id: item.world_operation_id
            for item in self.spec.operation_mappings
        }
        try:
            return mapped[operation_id]
        except KeyError as error:
            raise EngineeringProofContractError(
                f"reference operation is absent from explicit mappings: {operation_id}"
            ) from error

    def _capture_generated_bindings(
        self,
        reference_operation_id: str,
        body: Any,
    ) -> None:
        for rule in self.spec.generated_id_bindings:
            if (
                rule.producer_operation_id != reference_operation_id
                or rule.binding_id in self._local_bindings
            ):
                continue
            value = _pointer_value(body, rule)
            if type(value) is not str or not value:
                raise EngineeringProofContractError(
                    f"generated binding {rule.binding_id!r} must resolve to a non-empty string"
                )
            if value in self._local_bindings.values():
                raise EngineeringProofContractError(
                    "generated local binding values must be unambiguous"
                )
            self._local_bindings[rule.binding_id] = value

    def _replace_path_segments(self, path: str) -> str:
        replacements = self._replacement_map()
        return "/".join(replacements.get(component, component) for component in path.split("/"))

    def _replace_values(self, value: Any) -> Any:
        replacements = self._replacement_map()
        if isinstance(value, Mapping):
            return {key: self._replace_values(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [self._replace_values(item) for item in value]
        if type(value) is str:
            return replacements.get(value, value)
        return value

    def _replacement_map(self) -> dict[str, str]:
        return {
            **self._static_reference_to_world,
            **{
                self._reference_bindings[binding_id]: local_value
                for binding_id, local_value in self._local_bindings.items()
            },
        }

    def _restore_reference_values(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: self._restore_reference_values(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [self._restore_reference_values(item) for item in value]
        if type(value) is str:
            return self._static_world_to_reference.get(value, value)
        return value

    def _normalize_path(self, path: str) -> str:
        replacements = {
            local_value: f"${{{binding_id}}}"
            for binding_id, local_value in self._local_bindings.items()
        }
        return "/".join(replacements.get(component, component) for component in path.split("/"))

    def _normalize_values(self, value: Any) -> Any:
        replacements = {
            local_value: f"${{{binding_id}}}"
            for binding_id, local_value in self._local_bindings.items()
        }
        if isinstance(value, Mapping):
            return {key: self._normalize_values(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [self._normalize_values(item) for item in value]
        if type(value) is str:
            return replacements.get(value, value)
        return value


def _prefix_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return path.startswith("/")
    return path == prefix or path.startswith(prefix + "/")


def _replace_prefix(path: str, mapping: PathPrefixMapping) -> str:
    if mapping.reference_prefix == "/":
        suffix = path[1:]
    else:
        suffix = path[len(mapping.reference_prefix) :].lstrip("/")
    if mapping.world_prefix == "/":
        return "/" + suffix if suffix else "/"
    return mapping.world_prefix + ("/" + suffix if suffix else "")


def _pointer_value(value: Any, rule: GeneratedIdBinding) -> Any:
    current = value
    for raw_component in rule.response_pointer.split("/")[1:]:
        component = raw_component.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if component not in current:
                raise EngineeringProofContractError(
                    f"generated binding pointer does not exist: {rule.response_pointer}"
                )
            current = current[component]
        elif isinstance(current, (tuple, list)):
            if not component.isascii() or not component.isdigit():
                raise EngineeringProofContractError(
                    f"generated binding pointer has a non-index component: {rule.response_pointer}"
                )
            index = int(component)
            if index >= len(current):
                raise EngineeringProofContractError(
                    f"generated binding pointer does not exist: {rule.response_pointer}"
                )
            current = current[index]
        else:
            raise EngineeringProofContractError(
                f"generated binding pointer traverses a scalar: {rule.response_pointer}"
            )
    return current
