from __future__ import annotations

from copy import deepcopy
from typing import Any, Protocol
from uuid import uuid4

from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.mcp_capture import McpCaptureStore, McpReplayStore
from datalox_gated_runtime.models import (
    McpDecision,
    McpGateConfig,
    McpGateResponse,
    McpResponseCase,
    McpToolCall,
)


class McpUpstreamClient(Protocol):
    async def call_tool(
        self,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]: ...


class McpGatedRuntime:
    def __init__(
        self,
        *,
        config: McpGateConfig,
        ledger: SessionLedger | None = None,
        upstream_client: McpUpstreamClient | None = None,
        capture_store: McpCaptureStore | None = None,
        allow_live: bool = False,
        input_schemas: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.config = config
        self.ledger = ledger or SessionLedger()
        self.upstream_client = upstream_client
        self.capture_store = capture_store
        self.allow_live = allow_live
        self.input_schemas = input_schemas if input_schemas is not None else {}
        self.replay_store = McpReplayStore(config.generated.response_cases)

    async def handle(self, call: McpToolCall) -> McpGateResponse:
        upstream_name, upstream_tool_name = _split_tool_name(call.tool_name)
        tool_decision = self.config.tools.get(call.tool_name)
        arguments = deepcopy(call.arguments)

        if tool_decision is None:
            return self._record_deny(
                tool_name=call.tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
                reason_code="mcp_tool_not_exposed",
                message="MCP tool is not exposed by this gated runtime.",
            )

        if tool_decision == "deny":
            return self._record_deny(
                tool_name=call.tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
                reason_code="mcp_tool_denied",
                message="MCP tool call denied by policy.",
            )

        if tool_decision == "shadow":
            return self._handle_shadow(
                tool_name=call.tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
            )

        if tool_decision == "replay":
            return self._handle_replay(
                tool_name=call.tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
            )

        return await self._handle_live(
            tool_name=call.tool_name,
            upstream_name=upstream_name,
            upstream_tool_name=upstream_tool_name,
            arguments=arguments,
        )

    def _handle_shadow(
        self,
        *,
        tool_name: str,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> McpGateResponse:
        decision = McpDecision(
            kind="shadow",
            reason_code="mcp_tool_shadowed",
            message="MCP tool call shadowed.",
        )
        result = {
            "structuredContent": {
                "ok": True,
                "mode": "shadow",
                "tool_name": tool_name,
                "reason_code": decision.reason_code,
            }
        }
        event_id = f"evt_{uuid4().hex}"
        result["structuredContent"]["event_id"] = event_id
        shadow_mutation = {
            "tool_name": tool_name,
            "arguments": deepcopy(arguments),
            "result": deepcopy(result["structuredContent"]),
        }
        event = self.ledger.record_mcp(
            event_id=event_id,
            tool_name=tool_name,
            upstream_name=upstream_name,
            upstream_tool_name=upstream_tool_name,
            arguments=arguments,
            decision=decision,
            result=result,
            shadow_mutation=shadow_mutation,
        )
        return McpGateResponse(result=result, decision=decision, event_id=event.event_id)

    def _handle_replay(
        self,
        *,
        tool_name: str,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> McpGateResponse:
        response_case = self.replay_store.find(tool_name, arguments)
        if response_case is None:
            return self._record_deny(
                tool_name=tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
                reason_code="mcp_replay_case_missing",
                message="MCP replay case missing for exact tool arguments.",
            )

        decision = McpDecision(
            kind="replay",
            reason_code="mcp_replay_case_matched",
            message="MCP response replayed from captured case.",
        )
        result = deepcopy(response_case.result)
        event = self.ledger.record_mcp(
            tool_name=tool_name,
            upstream_name=upstream_name,
            upstream_tool_name=upstream_tool_name,
            arguments=arguments,
            decision=decision,
            result=result,
            response_case_id=response_case.case_id,
        )
        return McpGateResponse(
            result=result,
            decision=decision,
            event_id=event.event_id,
            response_case_id=response_case.case_id,
        )

    async def _handle_live(
        self,
        *,
        tool_name: str,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> McpGateResponse:
        if not self.allow_live:
            return self._record_deny(
                tool_name=tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
                reason_code="mcp_live_disabled",
                message="MCP live capture is disabled for this session.",
            )

        if self.upstream_client is None:
            return self._record_deny(
                tool_name=tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
                reason_code="mcp_upstream_unavailable",
                message="MCP live capture requires an upstream client.",
            )

        if upstream_name not in self.config.upstreams:
            return self._record_deny(
                tool_name=tool_name,
                upstream_name=upstream_name,
                upstream_tool_name=upstream_tool_name,
                arguments=arguments,
                reason_code="mcp_upstream_unavailable",
                message="MCP live capture requires a declared upstream.",
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
                message="MCP upstream tool call failed.",
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
            message="MCP tool call captured from live upstream.",
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

    def _record_deny(
        self,
        *,
        tool_name: str,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
        reason_code: str,
        message: str,
    ) -> McpGateResponse:
        decision = McpDecision(kind="deny", reason_code=reason_code, message=message)
        result = _error_result(reason_code, message, tool_name)
        event = self.ledger.record_mcp(
            tool_name=tool_name,
            upstream_name=upstream_name,
            upstream_tool_name=upstream_tool_name,
            arguments=arguments,
            decision=decision,
            result=result,
        )
        return McpGateResponse(result=result, decision=decision, event_id=event.event_id)


def _error_result(reason_code: str, message: str, tool_name: str) -> dict[str, Any]:
    return {
        "isError": True,
        "structuredContent": {
            "error": {
                "code": reason_code,
                "message": message,
                "tool_name": tool_name,
            }
        },
    }


def _split_tool_name(tool_name: str) -> tuple[str, str]:
    upstream_name, _, upstream_tool_name = tool_name.partition(".")
    return upstream_name, upstream_tool_name
