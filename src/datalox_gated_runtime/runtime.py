from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any

from datalox_gated_runtime.binary_response import (
    BinaryResponseEnvelopeError,
    inspect_binary_response_body,
)
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import (
    CallRequest,
    GateDecision,
    GateResponse,
    ResponseCase,
    RunExport,
)
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.world_backend import WorldBackend, WorldResponse
from datalox_gated_runtime.world_v1.contracts import ActorContext


class GatedRuntime:
    def __init__(
        self,
        *,
        policy: GatePolicy | None = None,
        response_cases: list[ResponseCase] | None = None,
        ledger: SessionLedger | None = None,
        world_backend: WorldBackend | None = None,
    ) -> None:
        self.policy = policy or GatePolicy.default()
        self.response_cases = response_cases or []
        self.ledger = ledger or SessionLedger()
        self.world_backend = world_backend

    def handle(self, request: CallRequest) -> GateResponse:
        if self.world_backend is not None:
            world_response = self.world_backend.handle(request)
            if world_response is not None:
                return self._world_gate_response(request, world_response)

        response_case = self._find_response_case(request)
        shadow_write = (
            self.ledger.latest_shadow_write(request.path, request.query)
            if request.normalized_method() == "GET"
            else None
        )
        decision = self.policy.decide(
            request,
            has_response_case=response_case is not None,
            has_shadow_write=shadow_write is not None,
        )

        if decision.kind == "replay" and response_case is not None:
            invalid_binary = self._invalid_binary_response(
                request,
                body=response_case.body,
                status_code=response_case.status_code,
            )
            if invalid_binary is not None:
                return invalid_binary
            event = self.ledger.record(
                request=request,
                decision=decision,
                response_status_code=response_case.status_code,
                response_body=response_case.body,
                response_case_id=response_case.case_id,
            )
            return GateResponse(
                status_code=response_case.status_code,
                body=deepcopy(response_case.body),
                decision=decision,
                event_id=event.event_id,
                response_case_id=response_case.case_id,
            )

        if decision.kind == "shadow_read" and shadow_write is not None:
            body = deepcopy(shadow_write.get("body"))
            invalid_binary = self._invalid_binary_response(
                request,
                body=body,
                status_code=200,
            )
            if invalid_binary is not None:
                return invalid_binary
            event = self.ledger.record(
                request=request,
                decision=decision,
                response_status_code=200,
                response_body=body,
            )
            return GateResponse(
                status_code=200, body=body, decision=decision, event_id=event.event_id
            )

        if decision.kind == "shadow_write":
            shadow_mutation = {
                "method": request.normalized_method(),
                "path": request.path,
                "query": deepcopy(request.query),
                "body": deepcopy(request.body),
            }
            body: dict[str, Any] = {
                "ok": True,
                "mode": "shadow_write",
                "reason_code": decision.reason_code,
            }
            event = self.ledger.record(
                request=request,
                decision=decision,
                response_status_code=202,
                response_body=body,
                shadow_mutation=shadow_mutation,
            )
            return GateResponse(
                status_code=202, body=body, decision=decision, event_id=event.event_id
            )

        if decision.kind == "deny":
            body = {
                "error": {
                    "code": decision.reason_code,
                    "message": decision.message,
                    "rule_id": decision.rule_id,
                }
            }
            event = self.ledger.record(
                request=request,
                decision=decision,
                response_status_code=403,
                response_body=body,
            )
            return GateResponse(
                status_code=403, body=body, decision=decision, event_id=event.event_id
            )

        if decision.kind == "live_capture":
            decision = GateDecision(
                kind="deny",
                reason_code="provider_access_forbidden",
                message="Evaluated-agent execution cannot contact a provider.",
            )
            body = {
                "error": {
                    "code": decision.reason_code,
                    "message": decision.message,
                }
            }
            event = self.ledger.record(
                request=request,
                decision=decision,
                response_status_code=403,
                response_body=body,
            )
            return GateResponse(
                status_code=403,
                body=body,
                decision=decision,
                event_id=event.event_id,
            )

        body = {
            "error": {
                "code": decision.reason_code,
                "message": decision.message,
            }
        }
        event = self.ledger.record(
            request=request,
            decision=decision,
            response_status_code=404,
            response_body=body,
        )
        return GateResponse(
            status_code=404,
            body=body,
            decision=decision,
            event_id=event.event_id,
        )

    def handle_as(self, request: CallRequest, *, actor: ActorContext) -> GateResponse:
        """Execute a world call with identity supplied by a trusted controller path."""

        backend = self.world_backend
        if backend is None or not callable(getattr(backend, "handle_as", None)):
            raise TypeError("world backend does not support trusted actor execution")
        world_response = backend.handle_as(request, actor=actor)
        if world_response is None:
            return self.record_denial(
                request,
                reason_code="world_route_missing",
                message="The provider behavior pack has no route for this request.",
                status_code=404,
            )
        return self._world_gate_response(request, world_response)

    def _world_gate_response(
        self,
        request: CallRequest,
        world_response: WorldResponse,
    ) -> GateResponse:
        request = replace(
            request,
            operation_id=world_response.operation_id or request.operation_id,
        )
        invalid_binary = self._invalid_binary_response(
            request,
            body=world_response.body,
            headers=world_response.headers,
            status_code=world_response.status_code,
        )
        if invalid_binary is not None:
            return invalid_binary
        decision_kind = world_response.decision_kind or (
            "shadow_write" if world_response.is_mutation else "replay"
        )
        decision = GateDecision(
            kind=decision_kind,
            reason_code=world_response.reason_code
            or ("world_state_write" if world_response.is_mutation else "world_state_read"),
            message=world_response.message
            or (
                "World state was mutated."
                if world_response.is_mutation
                else "World state was read."
            ),
        )
        shadow_mutation = None
        if world_response.is_mutation:
            assert self.world_backend is not None
            shadow_mutation = {
                "mode": "world_state_write",
                "world": world_response.world_id or self.world_backend.world_id,
                "method": request.normalized_method(),
                "path": request.path,
                "query": deepcopy(request.query),
                "body": deepcopy(request.body),
                "response": deepcopy(world_response.body),
            }
        event = self.ledger.record(
            request=request,
            decision=decision,
            response_status_code=world_response.status_code,
            response_body=world_response.body,
            shadow_mutation=shadow_mutation,
        )
        return GateResponse(
            status_code=world_response.status_code,
            body=deepcopy(world_response.body),
            decision=decision,
            event_id=event.event_id,
            headers=deepcopy(world_response.headers),
        )

    def export(self) -> RunExport:
        return RunExport.from_parts(
            events=list(self.ledger.events),
            shadow_state=deepcopy(self.ledger.shadow_state),
        )

    def record_denial(
        self,
        request: CallRequest,
        *,
        reason_code: str,
        message: str,
        details: dict[str, Any] | None = None,
        status_code: int = 400,
    ) -> GateResponse:
        decision = GateDecision(kind="deny", reason_code=reason_code, message=message)
        body = {"error": {"code": reason_code, "message": message, "details": details or {}}}
        event = self.ledger.record(
            request=request,
            decision=decision,
            response_status_code=status_code,
            response_body=body,
        )
        return GateResponse(
            status_code=status_code,
            body=body,
            decision=decision,
            event_id=event.event_id,
        )

    def record_denial_response(
        self,
        request: CallRequest,
        *,
        reason_code: str,
        body: dict[str, Any] | list[Any] | str | None,
        headers: dict[str, str],
        status_code: int,
    ) -> GateResponse:
        """Record an evidenced provider-native identity failure response."""

        decision = GateDecision(
            kind="deny",
            reason_code=reason_code,
            message="The simulated provider rejected the supplied identity.",
        )
        event = self.ledger.record(
            request=request,
            decision=decision,
            response_status_code=status_code,
            response_body=body,
        )
        return GateResponse(
            status_code=status_code,
            body=deepcopy(body),
            decision=decision,
            event_id=event.event_id,
            headers=deepcopy(headers),
        )

    def _invalid_binary_response(
        self,
        request: CallRequest,
        *,
        body: object,
        status_code: int,
        headers: dict[str, str] | None = None,
    ) -> GateResponse | None:
        try:
            inspect_binary_response_body(
                body,
                headers=headers,
                status_code=status_code,
            )
        except BinaryResponseEnvelopeError as exc:
            return self.record_denial(
                request,
                reason_code=exc.code,
                message=exc.message,
                details=exc.details,
                status_code=500,
            )
        return None

    def _find_response_case(self, request: CallRequest) -> ResponseCase | None:
        for response_case in self.response_cases:
            if response_case.matches(request):
                return response_case
        return None
