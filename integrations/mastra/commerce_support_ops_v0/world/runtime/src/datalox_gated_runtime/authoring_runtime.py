"""Explicit provider-connected runtime used only by behavior authoring tools."""

from __future__ import annotations

from copy import deepcopy

from datalox_gated_runtime.capture import CaptureStore, LiveCaptureClient, LiveCaptureError
from datalox_gated_runtime.models import CallRequest, GateDecision, GateResponse
from datalox_gated_runtime.runtime import GatedRuntime


class AuthoringGatedRuntime(GatedRuntime):
    """Adds reviewed GET acquisition to the otherwise provider-offline runtime.

    This class deliberately lives outside the execution runtime module. It is
    instantiated only by explicit authoring commands and is never loaded by the
    transparent gateway.
    """

    def __init__(
        self,
        *,
        capture_client: LiveCaptureClient,
        capture_store: CaptureStore | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.capture_client = capture_client
        self.capture_store = capture_store

    def handle(self, request: CallRequest) -> GateResponse:
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
        if decision.kind != "live_capture":
            return super().handle(request)

        try:
            captured = self.capture_client.fetch(request)
        except LiveCaptureError as exc:
            return self.record_denial(
                request,
                reason_code=exc.code,
                message=exc.message,
                status_code=502,
            )

        invalid_binary = self._invalid_binary_response(
            request,
            body=captured.body,
            status_code=captured.status_code,
        )
        if invalid_binary is not None:
            return invalid_binary
        if self.capture_store is not None:
            try:
                self.capture_store.append(captured)
            except (OSError, TypeError, ValueError) as exc:
                return self.record_denial(
                    request,
                    reason_code="live_capture_store_failed",
                    message="Live capture response could not be persisted.",
                    details={"detail": str(exc)},
                    status_code=502,
                )

        live_decision = GateDecision(
            kind="live_capture",
            reason_code="live_capture_allowed",
            message="Response was acquired by the explicit authoring runtime.",
        )
        event = self.ledger.record(
            request=request,
            decision=live_decision,
            response_status_code=captured.status_code,
            response_body=captured.body,
            response_case_id=captured.case_id,
        )
        return GateResponse(
            status_code=captured.status_code,
            body=deepcopy(captured.body),
            decision=live_decision,
            event_id=event.event_id,
            response_case_id=captured.case_id,
        )
