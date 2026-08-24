"""Stateful execution and trusted reset/export for a provider runtime bundle."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

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


class ProviderBehaviorBackend:
    def __init__(
        self,
        *,
        bundle: LoadedProviderRuntimeBundle,
        state_path: Path,
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
        self.session = WorldSession(state_path)
        self.reset()

    def close(self) -> None:
        self.session.close()

    def reset(self) -> None:
        self.bundle.implementation.initialize_episode(
            session=self.session,
            episode=deepcopy(self.bundle.seed),
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
            if tool_id is not None:
                self.catalog.require_invocation(actor, tool_id)
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
    ) -> None:
        self.bundle = load_provider_runtime_bundle(bundle_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir = run_dir
        self.backend: ProviderBehaviorBackend | None = None
        if isinstance(self.bundle.manifest.behavior, WorldV1BehaviorSpec):
            self.backend = ProviderBehaviorBackend(
                bundle=self.bundle,
                state_path=run_dir / "provider-state.sqlite3",
                configured_actor=configured_actor,
            )
        elif configured_actor is not None:
            raise ProviderRuntimeError(
                "provider_runtime_actor_unsupported",
                "Configured actors apply only to world_v1_adapter provider behavior.",
            )
        self._new_gate()

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

    def handle(self, request: CallRequest) -> GateResponse:
        return self.gate.handle(request)

    def reset(self) -> dict[str, Any]:
        if self.backend is not None:
            self.backend.reset()
        ledger_path = self.run_dir / "ledger.jsonl"
        ledger_path.unlink(missing_ok=True)
        self._new_gate()
        return self.export()

    def export(self) -> dict[str, Any]:
        call_evidence = dataclass_to_dict(self.gate.export())
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

    def close(self) -> None:
        if self.backend is not None:
            self.backend.close()
