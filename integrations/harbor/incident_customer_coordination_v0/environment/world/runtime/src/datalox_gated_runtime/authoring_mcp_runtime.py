"""Explicit provider-connected MCP acquisition runtime."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Protocol
from uuid import uuid4

from datalox_gated_runtime.mcp_capture import McpCaptureStore
from datalox_gated_runtime.mcp_runtime import McpGatedRuntime
from datalox_gated_runtime.models import McpDecision, McpGateResponse, McpResponseCase


class McpAuthoringUpstream(Protocol):
    async def call_tool(
        self,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]: ...


class AuthoringMcpGatedRuntime(McpGatedRuntime):
    def __init__(
        self,
        *,
        upstream_client: McpAuthoringUpstream,
        capture_store: McpCaptureStore | None = None,
        input_schemas: dict[str, dict[str, Any]] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.upstream_client = upstream_client
        self.capture_store = capture_store
        self.input_schemas = input_schemas if input_schemas is not None else {}

    async def _handle_live(
        self,
        *,
        tool_name: str,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> McpGateResponse:
        if upstream_name not in self.config.upstreams:
            return self._record_deny(
                tool_name=tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
                reason_code="mcp_upstream_unavailable",
                message="MCP authoring requires a declared upstream.",
            )
        try:
            result = await self.upstream_client.call_tool(
                upstream_name,
                upstream_tool_name,
                deepcopy(arguments),
            )
        except Exception:  # noqa: BLE001
            return self._record_deny(
                tool_name=tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
                reason_code="mcp_upstream_unavailable",
                message="MCP authoring upstream tool call failed.",
            )

        response_case_id = f"mcp_cap_{uuid4().hex}"
        response_case = McpResponseCase(
            case_id=response_case_id,
            tool_name=tool_name,
            arguments=deepcopy(arguments),
            result=deepcopy(result),
            evidence_ref=self.config.live[tool_name].evidence_ref,
            input_schema=deepcopy(self.input_schemas.get(tool_name)),
        )
        if self.capture_store is not None:
            self.capture_store.append(response_case)

        decision = McpDecision(
            kind="live",
            reason_code="mcp_live_captured",
            message="MCP tool call captured by the explicit authoring runtime.",
        )
        event = self.ledger.record_mcp(
            tool_name=tool_name,
            upstream_name=upstream_name,
            upstream_tool_name=upstream_tool_name,
            arguments=arguments,
            decision=decision,
            result=result,
            response_case_id=response_case_id,
        )
        return McpGateResponse(
            result=deepcopy(result),
            decision=decision,
            event_id=event.event_id,
            response_case_id=response_case_id,
        )
