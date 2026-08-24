from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Protocol

from mcp import types

from datalox_gated_runtime.models import CallRequest, McpGateConfig, McpToolCall
from datalox_gated_runtime.query import QueryParams
from datalox_gated_runtime.runtime import GatedRuntime
from datalox_gated_runtime.serializer import gate_response_envelope
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import WorldContractError
from datalox_gated_runtime.worlds.response_case_state_v0.mcp_tools import (
    world_tool_operation,
    world_tool_request,
    world_tool_schemas,
)
from datalox_gated_runtime.world_v1.errors import WorldV1Error


class McpToolSchemaClient(Protocol):
    async def list_tools(self, upstream_name: str) -> list[types.Tool]: ...


class McpRuntimeDispatcher(Protocol):
    async def handle(self, call: McpToolCall) -> Any: ...


UTILITY_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "get_task": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    "get_session_manifest": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    "gate_request": {
        "type": "object",
        "properties": {
            "method": {"type": "string"},
            "path": {"type": "string"},
            "query": {
                "type": "object",
                "additionalProperties": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                        },
                    ]
                },
            },
            "body": {},
        },
        "required": ["method", "path"],
        "additionalProperties": False,
    },
}

UTILITY_TOOL_DESCRIPTIONS = {
    "get_task": "Read the selected task brief for this session.",
    "get_session_manifest": "Read lifecycle paths and commands for this session.",
    "gate_request": "Send an HTTP-shaped request through the shared Datalox gate.",
}


class McpToolRegistry:
    def __init__(
        self,
        *,
        run_dir: Path,
        config: McpGateConfig,
        mcp_runtime: McpRuntimeDispatcher,
        upstream_client: McpToolSchemaClient | None = None,
        http_runtime: GatedRuntime | None = None,
        input_schemas: dict[str, dict[str, Any]] | None = None,
        world_backend: object | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.config = config
        self.mcp_runtime = mcp_runtime
        self.upstream_client = upstream_client
        self.http_runtime = http_runtime
        self.input_schemas = input_schemas if input_schemas is not None else {}
        self.world_backend = world_backend

    async def list_tools(self) -> list[types.Tool]:
        snapshot = await self.snapshot_declared_tool_schemas()
        tools = [
            types.Tool(
                name=name,
                description=UTILITY_TOOL_DESCRIPTIONS[name],
                inputSchema=deepcopy(schema),
            )
            for name, schema in UTILITY_TOOL_SCHEMAS.items()
        ]
        tools.extend(
            types.Tool(
                name=name,
                description=entry.get("description"),
                inputSchema=deepcopy(entry["inputSchema"]),
            )
            for name, entry in snapshot.items()
        )
        return tools

    async def snapshot_declared_tool_schemas(self) -> dict[str, dict[str, Any]]:
        snapshot: dict[str, dict[str, Any]] = {}
        for tool_name, decision in self.config.tools.items():
            if decision == "deny":
                continue
            entry = await self._resolve_tool_schema(tool_name)
            snapshot[tool_name] = entry
            self.input_schemas[tool_name] = deepcopy(entry["inputSchema"])

        for tool_name, entry in world_tool_schemas(self.world_backend).items():
            if tool_name in snapshot:
                raise ValueError(f"duplicate MCP tool declaration: {tool_name}")
            snapshot[tool_name] = deepcopy(entry)
            self.input_schemas[tool_name] = deepcopy(entry["inputSchema"])

        path = self.run_dir / "mcp_tool_schemas.json"
        path.write_text(
            json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return snapshot

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        payload = await self._call_tool_payload(name, arguments)
        return _dict_to_call_tool_result(payload)

    async def _call_tool_payload(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "get_task":
            return _read_json_object(
                self.run_dir / "task.json",
                error_code="task_unavailable",
                description="task json",
            )
        if name == "get_session_manifest":
            return _read_json_object(
                self.run_dir / "session_manifest.json",
                error_code="session_manifest_unavailable",
                description="session manifest json",
            )
        if name == "gate_request":
            if self.http_runtime is None:
                return {
                    "isError": True,
                    "structuredContent": {
                        "error": {
                            "code": "gate_request_unavailable",
                            "message": "HTTP gated runtime is not available.",
                        }
                    },
                }
            response = self.http_runtime.handle(
                CallRequest(
                    method=_require_string_argument(arguments, "method"),
                    path=_require_string_argument(arguments, "path"),
                    query=_optional_string_dict_argument(arguments, "query"),
                    body=arguments.get("body"),
                )
            )
            return gate_response_envelope(response)

        try:
            world_request = world_tool_request(self.world_backend, name, arguments)
        except (WorldContractError, WorldV1Error) as exc:
            details = getattr(exc, "details", getattr(exc, "context", {}))
            if self.http_runtime is not None:
                denied = self.http_runtime.record_denial(
                    CallRequest(
                        method="MCP",
                        path=f"/_datalox/world-tools/{name}",
                        body=deepcopy(arguments),
                        operation_id=world_tool_operation(self.world_backend, name),
                    ),
                    reason_code=exc.code,
                    message=exc.message,
                    details=details,
                )
                return gate_response_envelope(denied)
            return {
                "isError": True,
                "structuredContent": {
                    "error": {"code": exc.code, "message": exc.message, "details": details}
                },
            }
        if world_request is not None:
            if self.http_runtime is None:
                raise ValueError("world MCP tool requires the shared gated runtime")
            return gate_response_envelope(self.http_runtime.handle(world_request))

        response = await self.mcp_runtime.handle(McpToolCall(name, deepcopy(arguments)))
        result = response.result
        if not isinstance(result, dict):
            raise TypeError("mcp runtime result must be an object")
        return result

    async def _resolve_tool_schema(self, tool_name: str) -> dict[str, Any]:
        generated = self.config.generated.tool_schemas.get(tool_name)
        if generated is not None:
            return deepcopy(generated)

        upstream_name, upstream_tool_name = _split_declared_tool_name(tool_name)
        if self.upstream_client is None:
            raise ValueError(f"mcp tool schema unavailable: {tool_name}")

        tools = await self.upstream_client.list_tools(upstream_name)
        for tool in tools:
            if tool.name == upstream_tool_name:
                entry = {"inputSchema": deepcopy(tool.inputSchema)}
                if tool.description:
                    entry["description"] = tool.description
                return entry
        raise ValueError(f"mcp tool schema unavailable: {tool_name}")


def _dict_to_call_tool_result(payload: dict[str, Any]) -> types.CallToolResult:
    structured = (
        payload.get("structuredContent")
        if "structuredContent" in payload or "isError" in payload
        else payload
    )
    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=json.dumps(payload, sort_keys=True),
            )
        ],
        structuredContent=structured,
        isError=bool(payload.get("isError", False)),
    )


def _read_json_object(path: Path, *, error_code: str, description: str) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"error": {"code": error_code, "message": f"{description} not found: {path}"}}
    except json.JSONDecodeError:
        return {"error": {"code": error_code, "message": f"invalid {description}"}}

    if not isinstance(raw, dict):
        return {"error": {"code": error_code, "message": f"{description} must be an object"}}
    return raw


def _require_string_argument(arguments: dict[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_string_dict_argument(arguments: dict[str, Any], name: str) -> QueryParams:
    value = arguments.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    parsed: QueryParams = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
        if isinstance(item, str):
            parsed[key] = item
            continue
        if isinstance(item, list) and item and all(isinstance(entry, str) for entry in item):
            parsed[key] = tuple(item)
            continue
        raise ValueError(f"{name} values must be strings or non-empty arrays of strings")
    return parsed


def _split_declared_tool_name(tool_name: str) -> tuple[str, str]:
    upstream_name, _, upstream_tool_name = tool_name.partition(".")
    return upstream_name, upstream_tool_name
