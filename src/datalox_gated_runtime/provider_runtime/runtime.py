"""Stateful execution and trusted reset/export for a provider runtime bundle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import CallRequest, GateResponse
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.provider_runtime.bundle import (
    GateConfigBehaviorSpec,
    LoadedProviderRuntimeBundle,
    WorldV1BehaviorSpec,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.provider_runtime.identity import (
    ANONYMOUS_PRINCIPAL_CONTEXT_ID,
    FIXED_PRINCIPAL_CONTEXT_ID,
    CredentialMapIdentityPolicy,
    FixedIdentityPolicy,
    IdentityResolutionError,
    redact_external_request,
    resolve_external_identity,
    sanitize_external_request,
)
from datalox_gated_runtime.runtime import GatedRuntime
from datalox_gated_runtime.serializer import dataclass_to_dict
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.world_v1.contracts import (
    ActorContext,
    ToolCatalog,
    resolve_actor_context,
)
from datalox_gated_runtime.world_v1.errors import WorldAuthorizationError
from datalox_gated_runtime.world_v1.session import WorldSession

_PATH_PARAMETER = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")
_RUN_METADATA_FILENAME = "provider-run.json"
_RUN_METADATA_SCHEMA_VERSION = "datalox_provider_runtime_run_metadata_v1"
_RUN_METADATA_FIELDS = frozenset(
    {
        "schema_version",
        "provider_id",
        "bundle_version",
        "provider_runtime_sha256",
        "provider_admission_sha256",
        "configured_actor",
        "run_id",
        "created_at",
    }
)
_RUN_BINDING_FIELDS = _RUN_METADATA_FIELDS - {"run_id", "created_at"}
_RUN_LIFECYCLES = frozenset({"create", "resume"})


@dataclass(frozen=True)
class _AdmittedOperation:
    operation_id: str
    authority: str
    method: str
    path_segments: tuple[str, ...]


class ProviderBehaviorBackend:
    def __init__(
        self,
        *,
        bundle: LoadedProviderRuntimeBundle,
        state_path: Path,
        lifecycle: Literal["create", "resume"],
        configured_actor: ActorContext | None = None,
    ) -> None:
        self.bundle = bundle
        if not isinstance(bundle.manifest.behavior, WorldV1BehaviorSpec):
            raise TypeError("ProviderBehaviorBackend requires world_v1_adapter behavior")
        if bundle.implementation is None or bundle.seed is None:
            raise TypeError("world_v1_adapter bundle is incomplete")
        self.behavior = bundle.manifest.behavior
        self.world_id = bundle.manifest.provider_id
        self.configured_actor = configured_actor
        self.catalog = ToolCatalog(roles=bundle.roles, tools=bundle.tools)
        if lifecycle == "resume":
            _require_existing_run_file(
                state_path,
                code="provider_runtime_run_state_missing",
                description="provider state database",
            )
        self.session = WorldSession(state_path)
        try:
            if lifecycle == "create":
                self.reset()
            elif not self.session.is_initialized:
                raise ProviderRuntimeError(
                    "provider_runtime_run_state_invalid",
                    "Provider state database is not an initialized world session.",
                    {"path": str(state_path)},
                )
        except BaseException:
            self.session.close()
            raise

    def close(self) -> None:
        self.session.close()

    def reset(self) -> None:
        self.bundle.implementation.initialize_episode(
            session=self.session,
            episode=deepcopy(self.bundle.seed),
        )

    def request_for_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        actor: ActorContext,
    ) -> CallRequest:
        self.catalog.require_invocation(actor, tool_name)
        request = self.bundle.implementation.request_for_tool(
            tool_name,
            arguments,
            actor=actor,
        )
        operation_id = self.bundle.implementation.operation_for_tool(tool_name)
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower()
            not in {
                "x-datalox-actor-id",
                "x-datalox-actor-role",
                "x-datalox-tool-name",
            }
        }
        return CallRequest(
            scheme=request.scheme,
            authority=request.authority,
            method=request.method,
            path=request.path,
            query=dict(request.query),
            body=request.body,
            headers=headers,
            operation_id=operation_id or request.operation_id,
        )

    def handle(self, request: CallRequest) -> WorldResponse | None:
        tool_id = self.bundle.implementation.tool_for_request(request)
        try:
            actor = resolve_actor_context(
                request,
                declared_roles=self.catalog.role_ids,
                default_role=self.behavior.default_actor_role,
                configured_actor=self.configured_actor,
            )
        except WorldAuthorizationError as exc:
            return WorldResponse(
                status_code=403,
                body={"error": exc.to_dict()},
                is_mutation=False,
                world_id=self.world_id,
                operation_id=request.operation_id or tool_id or "unmapped_operation",
                decision_kind="deny",
                reason_code=exc.code,
                message=exc.message,
            )

        return self._handle_as_actor(request, actor=actor, tool_id=tool_id)

    def handle_as(self, request: CallRequest, *, actor: ActorContext) -> WorldResponse | None:
        """Execute with an identity supplied by a trusted runtime adapter."""

        if not isinstance(actor, ActorContext):
            raise TypeError("actor must be an ActorContext")
        if actor.role not in self.catalog.role_ids:
            raise WorldAuthorizationError(
                "world_actor_role_unknown",
                f"Actor role {actor.role!r} is not declared by this provider bundle.",
                actor_id=actor.actor_id,
                role=actor.role,
                declared_roles=sorted(self.catalog.role_ids),
            )
        tool_id = self.bundle.implementation.tool_for_request(request)
        return self._handle_as_actor(request, actor=actor, tool_id=tool_id)

    def _handle_as_actor(
        self,
        request: CallRequest,
        *,
        actor: ActorContext,
        tool_id: str | None,
    ) -> WorldResponse | None:
        if tool_id is not None:
            try:
                self.catalog.require_invocation(actor, tool_id)
            except WorldAuthorizationError as exc:
                return WorldResponse(
                    status_code=403,
                    body={"error": exc.to_dict()},
                    is_mutation=False,
                    world_id=self.world_id,
                    operation_id=request.operation_id or tool_id,
                    decision_kind="deny",
                    reason_code=exc.code,
                    message=exc.message,
                )
        operation_id = request.operation_id or tool_id or "unmapped_operation"
        with self.session.transaction(
            operation_id=operation_id,
            actor=actor,
            tool_name=tool_id,
            request=self._request_evidence(request),
        ):
            self.session.append_event(
                "provider_operation_started",
                {
                    "operation_id": operation_id,
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                    "tool_id": tool_id,
                    "request": self._request_evidence(request),
                },
            )
            response = self.bundle.implementation.handle(
                request,
                actor=actor,
                session=self.session,
            )
            if response is not None:
                self.session.record_response_digest(
                    actor=actor,
                    operation_id=operation_id,
                    tool_id=tool_id,
                    request=self._request_evidence(request),
                    status_code=response.status_code,
                    body=response.body,
                )
            return response

    @staticmethod
    def _request_evidence(request: CallRequest) -> dict[str, Any]:
        return {
            "scheme": request.scheme,
            "authority": request.authority,
            "method": request.normalized_method(),
            "path": request.path,
            "query": deepcopy(request.query),
            "body": deepcopy(request.body),
            "raw_body_sha256": request.raw_body_sha256,
        }


class ProviderRuntime:
    """One isolated provider state instance; no task, verifier, or provider client."""

    def __init__(
        self,
        *,
        bundle_dir: Path,
        run_dir: Path,
        configured_actor: ActorContext | None = None,
        admission_path: Path | None = None,
        lifecycle: Literal["create", "resume"] = "create",
    ) -> None:
        if lifecycle not in _RUN_LIFECYCLES:
            raise ProviderRuntimeError(
                "provider_runtime_lifecycle_invalid",
                "Provider runtime lifecycle must be either 'create' or 'resume'.",
                {"lifecycle": lifecycle},
            )
        self.bundle = load_provider_runtime_bundle(bundle_dir)
        self._admission_path: Path | None = None
        self._admission_sha256: str | None = None
        self._admission: dict[str, Any] | None = None
        self._admitted_operations: tuple[_AdmittedOperation, ...] = ()
        self._provider_invariants: tuple[dict[str, Any], ...] = ()
        self._assurance_failure: dict[str, str] | None = None
        if admission_path is not None:
            self._load_admission(admission_path)
        if (
            not isinstance(self.bundle.manifest.behavior, WorldV1BehaviorSpec)
            and configured_actor is not None
        ):
            raise ProviderRuntimeError(
                "provider_runtime_actor_unsupported",
                "Configured actors apply only to world_v1_adapter provider behavior.",
            )
        expected_binding = self._run_binding(configured_actor=configured_actor)
        stored_metadata = self._prepare_run_directory(
            run_dir=run_dir,
            lifecycle=lifecycle,
            expected_binding=expected_binding,
        )
        run_metadata = (
            {
                **expected_binding,
                "run_id": f"run_{uuid4().hex}",
                "created_at": datetime.now(UTC).isoformat(),
            }
            if stored_metadata is None
            else stored_metadata
        )
        self._run_id = run_metadata["run_id"]
        self._created_at = run_metadata["created_at"]
        self.run_dir = run_dir
        self.backend: ProviderBehaviorBackend | None = None
        try:
            if isinstance(self.bundle.manifest.behavior, WorldV1BehaviorSpec):
                self.backend = ProviderBehaviorBackend(
                    bundle=self.bundle,
                    state_path=run_dir / "provider-state.sqlite3",
                    lifecycle=lifecycle,
                    configured_actor=configured_actor,
                )
            if lifecycle == "create":
                self._initialize_empty_ledger()
            else:
                _require_existing_run_file(
                    run_dir / "ledger.jsonl",
                    code="provider_runtime_run_ledger_missing",
                    description="provider call ledger",
                )
            self._new_gate()
            self._require_current_assurance(context="initialization")
            if lifecycle == "create":
                _write_json_exclusive(
                    run_dir / _RUN_METADATA_FILENAME,
                    run_metadata,
                    mode=0o600,
                )
        except Exception:
            if self.backend is not None:
                self.backend.close()
            if lifecycle == "create":
                shutil.rmtree(run_dir)
            raise

    @property
    def authorities(self) -> tuple[str, ...]:
        return self.bundle.manifest.authorities

    def _new_gate(self) -> None:
        ledger = SessionLedger(path=self.run_dir / "ledger.jsonl")
        behavior = self.bundle.manifest.behavior
        if isinstance(behavior, WorldV1BehaviorSpec):
            self.gate = GatedRuntime(ledger=ledger, world_backend=self.backend)
            return
        if not isinstance(behavior, GateConfigBehaviorSpec) or self.bundle.gate_config is None:
            raise TypeError("provider runtime bundle has no executable behavior")
        self.gate = GatedRuntime(
            ledger=ledger,
            policy=GatePolicy.from_config(self.bundle.gate_config.policy),
            response_cases=list(self.bundle.gate_config.response_cases),
        )

    def _run_binding(self, *, configured_actor: ActorContext | None) -> dict[str, Any]:
        return {
            "schema_version": _RUN_METADATA_SCHEMA_VERSION,
            "provider_id": self.bundle.manifest.provider_id,
            "bundle_version": self.bundle.manifest.bundle_version,
            "provider_runtime_sha256": _sha256_file(self.bundle.root / "provider-runtime.json"),
            "provider_admission_sha256": self._admission_sha256,
            "configured_actor": (
                None
                if configured_actor is None
                else {
                    "actor_id": configured_actor.actor_id,
                    "actor_role": configured_actor.role,
                }
            ),
        }

    @staticmethod
    def _prepare_run_directory(
        *,
        run_dir: Path,
        lifecycle: Literal["create", "resume"],
        expected_binding: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if lifecycle == "create":
            if run_dir.exists() or run_dir.is_symlink():
                raise ProviderRuntimeError(
                    "provider_runtime_run_exists",
                    "Create lifecycle requires a new provider runtime directory.",
                    {"path": str(run_dir)},
                )
            run_dir.parent.mkdir(parents=True, exist_ok=True)
            try:
                run_dir.mkdir(mode=0o700)
            except OSError as exc:
                raise ProviderRuntimeError(
                    "provider_runtime_run_create_failed",
                    f"Could not create provider runtime directory: {exc}.",
                    {"path": str(run_dir)},
                ) from exc
            return None

        if run_dir.is_symlink() or not run_dir.is_dir():
            raise ProviderRuntimeError(
                "provider_runtime_run_missing",
                "Resume lifecycle requires an existing provider runtime directory.",
                {"path": str(run_dir)},
            )
        actual_binding = _load_run_binding(run_dir / _RUN_METADATA_FILENAME)
        if any(actual_binding[field] != expected_binding[field] for field in _RUN_BINDING_FIELDS):
            mismatches = {
                field: {
                    "expected": deepcopy(expected_binding.get(field)),
                    "actual": deepcopy(actual_binding.get(field)),
                }
                for field in sorted(_RUN_BINDING_FIELDS)
                if actual_binding.get(field) != expected_binding.get(field)
            }
            raise ProviderRuntimeError(
                "provider_runtime_run_binding_mismatch",
                "Provider runtime run metadata does not bind the requested runtime configuration.",
                {"mismatches": mismatches},
            )
        return actual_binding

    def _initialize_empty_ledger(self) -> None:
        _write_bytes_exclusive(self.run_dir / "ledger.jsonl", b"", mode=0o600)

    def handle(self, request: CallRequest) -> GateResponse:
        request, blocked = self._bind_admitted_request(request)
        if blocked is not None:
            return blocked
        response = self._handle_bound_request(request)
        return self._return_with_assurance(request, response)

    def handle_as_principal(
        self,
        request: CallRequest,
        *,
        principal_context_id: str,
    ) -> GateResponse:
        """Execute through a provider-owned principal selected by a trusted controller."""

        request, blocked = self._bind_admitted_request(request)
        if blocked is not None:
            return blocked
        policy = self.bundle.identity_policy
        actor: ActorContext | None
        if isinstance(policy, FixedIdentityPolicy):
            actor = policy.actor if principal_context_id == FIXED_PRINCIPAL_CONTEXT_ID else None
        elif isinstance(policy, CredentialMapIdentityPolicy):
            matching = [
                principal.actor
                for principal in policy.principals
                if principal.principal_context_id == principal_context_id
            ]
            actor = matching[0] if len(matching) == 1 else None
        elif policy is None and isinstance(self.bundle.manifest.behavior, GateConfigBehaviorSpec):
            actor = None
            if principal_context_id != ANONYMOUS_PRINCIPAL_CONTEXT_ID:
                return self._unknown_principal_denial(request)
        else:
            raise TypeError("provider runtime has an unsupported identity policy")
        if policy is not None and actor is None:
            return self._unknown_principal_denial(request)

        safe_request = redact_external_request(request, policy)
        if actor is None:
            response = self.gate.handle(safe_request)
        else:
            response = self.gate.handle_as(safe_request, actor=actor)
        return self._return_with_assurance(safe_request, response)

    def _handle_bound_request(self, request: CallRequest) -> GateResponse:
        behavior = self.bundle.manifest.behavior
        if isinstance(behavior, WorldV1BehaviorSpec):
            identity_policy = self.bundle.identity_policy
            if identity_policy is None:
                raise TypeError("world provider runtime has no identity policy")
            try:
                resolved = resolve_external_identity(identity_policy, request)
            except IdentityResolutionError as exc:
                safe_request = redact_external_request(request, identity_policy)
                return self.gate.record_denial_response(
                    safe_request,
                    reason_code=exc.code,
                    body=exc.response.body,
                    headers=dict(exc.response.headers),
                    status_code=exc.response.status_code,
                )
            except ProviderRuntimeError as exc:
                safe_request = redact_external_request(request, identity_policy)
                return self.gate.record_denial(
                    safe_request,
                    reason_code=exc.code,
                    message=exc.message,
                    details=exc.details,
                    status_code=400,
                )
            return self.gate.handle_as(resolved.request, actor=resolved.actor)

        try:
            safe_request = sanitize_external_request(request)
        except ProviderRuntimeError as exc:
            safe_request = redact_external_request(request)
            return self.gate.record_denial(
                safe_request,
                reason_code=exc.code,
                message=exc.message,
                details=exc.details,
                status_code=400,
            )
        return self.gate.handle(safe_request)

    def request_for_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        actor: ActorContext,
    ) -> CallRequest:
        if self.backend is None:
            raise ProviderRuntimeError(
                "provider_runtime_tool_projection_unsupported",
                "This provider runtime does not declare a tool-to-request projection.",
            )
        return self.backend.request_for_tool(tool_name, arguments, actor=actor)

    def invoke_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        actor: ActorContext,
    ) -> GateResponse:
        """Trusted tool projection; actor identity never crosses the provider wire."""

        request = self.request_for_tool(tool_name, arguments, actor=actor)
        if self._admission is not None:
            if self._assurance_failure is not None:
                return self._assurance_denial(request)
            operation = self._match_admitted_operation(request)
            if operation is None or operation.operation_id != request.operation_id:
                response = self._record_denial(
                    request,
                    reason_code="provider_operation_not_admitted",
                    message="This provider tool projection is outside the admitted runtime surface.",
                    status_code=403,
                )
                return self._return_with_assurance(request, response)
            request = replace(request, operation_id=operation.operation_id)
        response = self.gate.handle_as(request, actor=actor)
        return self._return_with_assurance(request, response)

    def reset(self) -> dict[str, Any]:
        if self.backend is not None:
            self.backend.reset()
        ledger_path = self.run_dir / "ledger.jsonl"
        ledger_path.unlink(missing_ok=True)
        self._initialize_empty_ledger()
        self._new_gate()
        self._assurance_failure = None
        self._require_current_assurance(context="reset")
        return self.export()

    def export(self) -> dict[str, Any]:
        exported = self._base_export()
        if self._admission is None:
            return exported
        if self._assurance_failure is None:
            self._evaluate_current_assurance(exported)
        exported["provider_assurance"] = {
            "schema_version": self._admission["schema_version"],
            "provider_admission_sha256": self._admission_sha256,
            "operation_claims_sha256": self._admission["operation_claims_sha256"],
            "admitted_operation_ids": [
                operation.operation_id for operation in self._admitted_operations
            ],
            "status": "valid" if self._assurance_failure is None else "invalid",
            "failure": deepcopy(self._assurance_failure),
        }
        return exported

    def _base_export(self) -> dict[str, Any]:
        call_evidence = dataclass_to_dict(self.gate.export())
        call_evidence["run_id"] = self._run_id
        call_evidence["created_at"] = self._created_at
        if self.backend is not None:
            provider_state: dict[str, Any] = self.backend.session.export()
        else:
            provider_state = {
                "protocol": "gate_config_v1",
                "shadow_state": deepcopy(call_evidence["shadow_state"]),
            }
        return {
            "schema_version": "datalox_provider_run_v1",
            "provider_id": self.bundle.manifest.provider_id,
            "bundle_version": self.bundle.manifest.bundle_version,
            "authorities": list(self.authorities),
            "provider_state": provider_state,
            "call_evidence": call_evidence,
        }

    def _load_admission(self, admission_path: Path) -> None:
        from datalox_gated_runtime.provider_runtime.admission import load_provider_admission

        admission = load_provider_admission(admission_path)
        expected_runtime_digest = _sha256_file(self.bundle.root / "provider-runtime.json")
        mismatches: dict[str, object] = {}
        if admission["provider_id"] != self.bundle.manifest.provider_id:
            mismatches["provider_id"] = admission["provider_id"]
        if admission["bundle_version"] != self.bundle.manifest.bundle_version:
            mismatches["bundle_version"] = admission["bundle_version"]
        if admission["provider_runtime_sha256"] != expected_runtime_digest:
            mismatches["provider_runtime_sha256"] = admission["provider_runtime_sha256"]
        if mismatches:
            raise ProviderRuntimeError(
                "provider_runtime_admission_mismatch",
                "Provider admission does not bind this exact provider runtime bundle.",
                {
                    "mismatches": mismatches,
                    "expected_provider_id": self.bundle.manifest.provider_id,
                    "expected_bundle_version": self.bundle.manifest.bundle_version,
                    "expected_provider_runtime_sha256": expected_runtime_digest,
                },
            )
        operations = tuple(_admitted_operation(item) for item in admission["operations"])
        _reject_ambiguous_operations(operations)
        self._admission_path = admission_path.resolve(strict=True)
        self._admission_sha256 = _sha256_file(self._admission_path)
        self._admission = admission
        self._admitted_operations = operations
        self._provider_invariants = tuple(
            {key: deepcopy(value) for key, value in predicate.items() if key != "passed"}
            for predicate in admission["provider_invariants"]
        )

    def _match_admitted_operation(self, request: CallRequest) -> _AdmittedOperation | None:
        matches = [
            operation
            for operation in self._admitted_operations
            if request.scheme == "https"
            and request.authority == operation.authority
            and request.normalized_method() == operation.method
            and _path_matches(request.path, operation.path_segments)
        ]
        if len(matches) > 1:
            raise RuntimeError("ambiguous admitted operation escaped initialization validation")
        return matches[0] if matches else None

    def _bind_admitted_request(
        self, request: CallRequest
    ) -> tuple[CallRequest, GateResponse | None]:
        if self._admission is None:
            return request, None
        if self._assurance_failure is not None:
            return request, self._assurance_denial(request)
        operation = self._match_admitted_operation(request)
        if operation is None:
            response = self._record_denial(
                request,
                reason_code="provider_operation_not_admitted",
                message="This native provider operation is outside the admitted runtime surface.",
                status_code=403,
            )
            return request, self._return_with_assurance(request, response)
        if not self._world_mapping_matches(request, operation.operation_id):
            response = self._record_denial(
                request,
                reason_code="provider_operation_binding_mismatch",
                message="The admitted native surface does not map to its declared provider operation.",
                status_code=500,
            )
            return request, self._return_with_assurance(request, response)
        return replace(request, operation_id=operation.operation_id), None

    def _unknown_principal_denial(self, request: CallRequest) -> GateResponse:
        response = self._record_denial(
            request,
            reason_code="provider_principal_context_unknown",
            message="The provider runtime does not declare this principal context.",
            status_code=403,
        )
        return self._return_with_assurance(request, response)

    def _world_mapping_matches(self, request: CallRequest, operation_id: str) -> bool:
        if not isinstance(self.bundle.manifest.behavior, WorldV1BehaviorSpec):
            return True
        implementation = self.bundle.implementation
        if implementation is None:
            return False
        tool_id = implementation.tool_for_request(request)
        if tool_id is None:
            return False
        return implementation.operation_for_tool(tool_id) == operation_id

    def _return_with_assurance(self, request: CallRequest, response: GateResponse) -> GateResponse:
        if self._admission is None:
            return response
        if self._evaluate_current_assurance(self._base_export()):
            return response
        return self._assurance_denial(request)

    def _require_current_assurance(self, *, context: str) -> None:
        if self._admission is None:
            return
        if self._evaluate_current_assurance(self._base_export()):
            return
        failure = deepcopy(self._assurance_failure)
        raise ProviderRuntimeError(
            "provider_runtime_invariant_failed",
            f"An admitted provider invariant failed during {context}.",
            {"failure": failure},
        )

    def _evaluate_current_assurance(self, exported: Mapping[str, Any]) -> bool:
        for predicate in self._provider_invariants:
            if not _predicate_passes(predicate, exported):
                self._assurance_failure = {
                    "code": "provider_invariant_failed",
                    "predicate_id": predicate["predicate_id"],
                }
                return False
        return True

    def _assurance_denial(self, request: CallRequest) -> GateResponse:
        return self._record_denial(
            request,
            reason_code="provider_invariant_failed",
            message="The admitted provider runtime is invalid until a trusted reset succeeds.",
            details=deepcopy(self._assurance_failure),
            status_code=500,
        )

    def _record_denial(
        self,
        request: CallRequest,
        *,
        reason_code: str,
        message: str,
        status_code: int,
        details: dict[str, Any] | None = None,
    ) -> GateResponse:
        return self.gate.record_denial(
            redact_external_request(request, self.bundle.identity_policy),
            reason_code=reason_code,
            message=message,
            details=details,
            status_code=status_code,
        )

    def close(self) -> None:
        if self.backend is not None:
            self.backend.close()


def _admitted_operation(raw: Mapping[str, Any]) -> _AdmittedOperation:
    surface = raw["native_surface"]
    path_template = surface["path_template"]
    return _AdmittedOperation(
        operation_id=raw["operation_id"],
        authority=surface["authority"],
        method=surface["method"],
        path_segments=_template_segments(path_template),
    )


def _template_segments(path_template: str) -> tuple[str, ...]:
    if path_template == "/":
        return ()
    if not path_template.startswith("/") or path_template.endswith("/"):
        raise ProviderRuntimeError(
            "provider_runtime_admission_surface_invalid",
            "Admitted path templates must be absolute and have no trailing slash.",
        )
    segments = tuple(path_template[1:].split("/"))
    for segment in segments:
        is_parameter = _PATH_PARAMETER.fullmatch(segment) is not None
        if not segment or segment in {".", ".."} or (not is_parameter and "{" in segment):
            raise ProviderRuntimeError(
                "provider_runtime_admission_surface_invalid",
                "Admitted path parameters must occupy one complete path segment.",
                {"path_template": path_template},
            )
        if "}" in segment and not is_parameter:
            raise ProviderRuntimeError(
                "provider_runtime_admission_surface_invalid",
                "Admitted path parameters must occupy one complete path segment.",
                {"path_template": path_template},
            )
    return segments


def _reject_ambiguous_operations(operations: tuple[_AdmittedOperation, ...]) -> None:
    for index, left in enumerate(operations):
        for right in operations[index + 1 :]:
            if (
                left.authority == right.authority
                and left.method == right.method
                and _templates_overlap(left.path_segments, right.path_segments)
            ):
                raise ProviderRuntimeError(
                    "provider_runtime_admission_surface_ambiguous",
                    "Admitted native operation surfaces overlap.",
                    {"operation_ids": sorted((left.operation_id, right.operation_id))},
                )


def _templates_overlap(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    if len(left) != len(right):
        return False
    return all(
        _PATH_PARAMETER.fullmatch(left_segment) is not None
        or _PATH_PARAMETER.fullmatch(right_segment) is not None
        or left_segment == right_segment
        for left_segment, right_segment in zip(left, right)
    )


def _path_matches(path: str, template: tuple[str, ...]) -> bool:
    if path == "/":
        segments: tuple[str, ...] = ()
    elif not path.startswith("/") or path.endswith("/"):
        return False
    else:
        segments = tuple(path[1:].split("/"))
    if len(segments) != len(template):
        return False
    return all(
        segment not in {"", ".", ".."}
        and (_PATH_PARAMETER.fullmatch(pattern) is not None or segment == pattern)
        for segment, pattern in zip(segments, template)
    )


def _predicate_passes(predicate: Mapping[str, Any], export: Mapping[str, Any]) -> bool:
    source = export[predicate["source"]]
    exists, value = _resolve_pointer(source, predicate["pointer"])
    operator = predicate["operator"]
    if operator == "exists":
        return exists
    if operator == "equals":
        return (
            exists and type(value) is type(predicate["expected"]) and value == predicate["expected"]
        )
    if operator == "type":
        return exists and _json_type(value) == predicate["expected_type"]
    raise RuntimeError("invalid admitted provider invariant escaped strict admission loading")


def _resolve_pointer(value: Any, pointer: str) -> tuple[bool, Any]:
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


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    if type(value) is dict:
        return "object"
    raise RuntimeError("provider state contains a non-JSON value")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _load_run_binding(path: Path) -> dict[str, Any]:
    _require_existing_run_file(
        path,
        code="provider_runtime_run_metadata_missing",
        description="provider runtime run metadata",
    )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderRuntimeError(
            "provider_runtime_run_metadata_invalid",
            f"Could not load provider runtime run metadata: {exc}.",
            {"path": str(path)},
        ) from exc
    if not isinstance(raw, dict) or set(raw) != _RUN_METADATA_FIELDS:
        actual = set(raw) if isinstance(raw, dict) else set()
        raise ProviderRuntimeError(
            "provider_runtime_run_metadata_invalid",
            "Provider runtime run metadata fields do not match the contract.",
            {
                "missing": sorted(_RUN_METADATA_FIELDS - actual),
                "unknown": sorted(actual - _RUN_METADATA_FIELDS),
            },
        )
    if raw["schema_version"] != _RUN_METADATA_SCHEMA_VERSION:
        raise ProviderRuntimeError(
            "provider_runtime_run_metadata_invalid",
            "Provider runtime run metadata schema version is unsupported.",
            {"schema_version": raw["schema_version"]},
        )
    for field in ("provider_id", "bundle_version"):
        if not isinstance(raw[field], str) or not raw[field] or raw[field].strip() != raw[field]:
            raise ProviderRuntimeError(
                "provider_runtime_run_metadata_invalid",
                f"Provider runtime run metadata {field} must be a non-empty trimmed string.",
            )
    for field in ("provider_runtime_sha256", "provider_admission_sha256"):
        value = raw[field]
        if field == "provider_admission_sha256" and value is None:
            continue
        if (
            not isinstance(value, str)
            or not value.startswith("sha256:")
            or len(value) != 71
            or any(character not in "0123456789abcdef" for character in value[7:])
        ):
            raise ProviderRuntimeError(
                "provider_runtime_run_metadata_invalid",
                f"Provider runtime run metadata {field} is not a SHA-256 digest.",
            )
    actor = raw["configured_actor"]
    if actor is not None and (
        not isinstance(actor, dict)
        or set(actor) != {"actor_id", "actor_role"}
        or any(
            not isinstance(actor[field], str)
            or not actor[field]
            or actor[field].strip() != actor[field]
            for field in ("actor_id", "actor_role")
        )
    ):
        raise ProviderRuntimeError(
            "provider_runtime_run_metadata_invalid",
            "Provider runtime run metadata configured_actor is invalid.",
        )
    run_id = raw["run_id"]
    if (
        not isinstance(run_id, str)
        or not run_id.startswith("run_")
        or len(run_id) != 36
        or any(character not in "0123456789abcdef" for character in run_id[4:])
    ):
        raise ProviderRuntimeError(
            "provider_runtime_run_metadata_invalid",
            "Provider runtime run metadata run_id is invalid.",
        )
    created_at = raw["created_at"]
    try:
        parsed_created_at = datetime.fromisoformat(created_at)
    except (TypeError, ValueError) as exc:
        raise ProviderRuntimeError(
            "provider_runtime_run_metadata_invalid",
            "Provider runtime run metadata created_at is invalid.",
        ) from exc
    if parsed_created_at.tzinfo is None or parsed_created_at.utcoffset() != UTC.utcoffset(None):
        raise ProviderRuntimeError(
            "provider_runtime_run_metadata_invalid",
            "Provider runtime run metadata created_at must be an explicit UTC timestamp.",
        )
    return raw


def _require_existing_run_file(path: Path, *, code: str, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ProviderRuntimeError(
            code,
            f"Resume lifecycle requires an existing regular {description}.",
            {"path": str(path)},
        )


def _write_json_exclusive(path: Path, value: Mapping[str, Any], *, mode: int) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    _write_bytes_exclusive(path, payload, mode=mode)


def _write_bytes_exclusive(path: Path, payload: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise ProviderRuntimeError(
            "provider_runtime_run_artifact_exists",
            f"Provider runtime run artifact already exists: {path.name}.",
            {"path": str(path)},
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
