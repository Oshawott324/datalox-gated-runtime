from __future__ import annotations

import asyncio
import json
from inspect import Parameter, Signature
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.fastmcp import FastMCP
from mcp.server.stdio import stdio_server
from mcp.server.transport_security import TransportSecuritySettings

from datalox_gated_runtime.capture import (
    CaptureStore,
    LiveCaptureClient,
    validate_live_capture_prefixes,
)
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.mcp_capture import McpCaptureStore
from datalox_gated_runtime.mcp_registry import McpToolRegistry, McpToolSchemaClient
from datalox_gated_runtime.mcp_runtime import McpGatedRuntime
from datalox_gated_runtime.mcp_upstream import StdioMcpUpstreamClient
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.runtime import GatedRuntime
from datalox_gated_runtime.serializer import gate_response_envelope
from datalox_gated_runtime.world_backend import create_world_backend
from datalox_gated_runtime.world_v1.contracts import ActorContext
from datalox_gated_runtime.world_v1.errors import WorldV1Error
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import WorldContractError
from datalox_gated_runtime.worlds.response_case_state_v0.mcp_tools import (
    world_tool_operation,
    world_tool_request,
    world_tool_schemas,
)


def build_server(
    run_dir: Path,
    *,
    actor_context: ActorContext | None = None,
    transport_security: TransportSecuritySettings | None = None,
    include_session_manifest_tool: bool = True,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> FastMCP | Server:
    config = load_gate_config(run_dir / "gate_config.json")
    if config.mcp is not None:
        return build_low_level_server(run_dir, actor_context=actor_context)

    world_backend = create_world_backend(
        run_dir=run_dir,
        config=config.world,
        actor_context=actor_context,
    )
    runtime = GatedRuntime(
        policy=GatePolicy.from_config(config.policy),
        response_cases=config.response_cases,
        ledger=SessionLedger(path=run_dir / "ledger.jsonl"),
        world_backend=world_backend,
    )
    server = FastMCP(
        "datalox-gated-runtime",
        transport_security=transport_security,
        host=host,
        port=port,
    )
    execution_lock = asyncio.Lock()

    @server.tool()
    async def get_task() -> dict[str, Any]:
        """Read the selected task brief for this session."""
        return await asyncio.to_thread(
            _read_json_object,
            run_dir / "task.json",
            error_code="task_unavailable",
            description="task json",
        )

    @server.tool()
    async def gate_request(
        method: str,
        path: str,
        query: dict[str, str | list[str]] | None = None,
        body: dict[str, Any] | list[Any] | str | None = None,
    ) -> dict:
        """Send an HTTP-shaped request through the shared Datalox gate."""
        request = CallRequest(
            method=method,
            path=path,
            query=query or {},
            body=body,
        )
        async with execution_lock:
            response = await _run_sync_to_completion(runtime.handle, request)
        return gate_response_envelope(response)

    if include_session_manifest_tool:

        @server.tool()
        async def get_session_manifest() -> dict[str, Any]:
            """Read lifecycle paths and commands for this session."""
            return await asyncio.to_thread(
                _read_json_object,
                run_dir / "session_manifest.json",
                error_code="session_manifest_unavailable",
                description="session manifest json",
            )

    _register_fastmcp_world_tools(
        server,
        runtime,
        world_backend,
        execution_lock=execution_lock,
    )
    return server


def build_low_level_server(
    run_dir: Path,
    *,
    allow_live: bool = False,
    upstream_client: McpToolSchemaClient | None = None,
    actor_context: ActorContext | None = None,
) -> Server:
    server, _ = _build_low_level_components(
        run_dir,
        allow_live=allow_live,
        upstream_client=upstream_client,
        actor_context=actor_context,
    )
    return server


def run_mcp(
    run_dir: Path,
    *,
    allow_live: bool = False,
    actor_context: ActorContext | None = None,
) -> None:
    config = load_gate_config(run_dir / "gate_config.json")
    if config.mcp is None:
        build_server(run_dir, actor_context=actor_context).run()
        return
    asyncio.run(
        _run_low_level_mcp(
            run_dir,
            allow_live=allow_live,
            actor_context=actor_context,
        )
    )


def _build_low_level_components(
    run_dir: Path,
    *,
    allow_live: bool = False,
    upstream_client: McpToolSchemaClient | None = None,
    actor_context: ActorContext | None = None,
) -> tuple[Server, McpToolRegistry]:
    config = load_gate_config(run_dir / "gate_config.json")
    if config.mcp is None:
        raise ValueError("mcp block is required for low-level MCP server")

    upstream_client = upstream_client or StdioMcpUpstreamClient(config.mcp.upstreams)
    capture_client = None
    capture_store = None
    if allow_live and config.policy is not None and config.policy.live_capture:
        if config.live is None:
            raise ValueError("--allow-live requires live.upstreams in gate_config.json")
        validate_live_capture_prefixes(config.policy, config.live)
        capture_client = LiveCaptureClient(config.live)
        capture_store = CaptureStore(run_dir / "captures.jsonl")
    ledger = SessionLedger(path=run_dir / "ledger.jsonl")
    world_backend = create_world_backend(
        run_dir=run_dir,
        config=config.world,
        actor_context=actor_context,
    )
    http_runtime = GatedRuntime(
        policy=GatePolicy.from_config(config.policy, allow_live=allow_live),
        response_cases=config.response_cases,
        ledger=ledger,
        capture_client=capture_client,
        capture_store=capture_store,
        world_backend=world_backend,
    )
    input_schemas: dict[str, dict[str, Any]] = {}
    mcp_runtime = McpGatedRuntime(
        config=config.mcp,
        ledger=ledger,
        upstream_client=upstream_client,
        capture_store=McpCaptureStore(run_dir / "mcp_captures.jsonl"),
        allow_live=allow_live,
        input_schemas=input_schemas,
    )
    registry = McpToolRegistry(
        run_dir=run_dir,
        config=config.mcp,
        mcp_runtime=mcp_runtime,
        upstream_client=upstream_client,
        http_runtime=http_runtime,
        input_schemas=input_schemas,
        world_backend=world_backend,
    )

    server = Server("datalox-gated-runtime")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return await registry.list_tools()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        return await registry.call_tool(name, arguments or {})

    return server, registry


async def _run_low_level_mcp(
    run_dir: Path,
    *,
    allow_live: bool = False,
    actor_context: ActorContext | None = None,
) -> None:
    server, registry = _build_low_level_components(
        run_dir,
        allow_live=allow_live,
        actor_context=actor_context,
    )
    await registry.snapshot_declared_tool_schemas()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
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


def _register_fastmcp_world_tools(
    server: FastMCP,
    runtime: GatedRuntime,
    world_backend: object | None,
    *,
    execution_lock: asyncio.Lock,
) -> None:
    for tool_name, entry in world_tool_schemas(world_backend).items():
        input_schema = entry["inputSchema"]
        handler = _fastmcp_world_handler(
            tool_name,
            runtime,
            world_backend,
            execution_lock=execution_lock,
        )
        handler.__signature__ = _signature_from_schema(input_schema)
        server.add_tool(
            handler,
            name=tool_name,
            description=entry.get("description"),
        )


def _fastmcp_world_handler(
    tool_name: str,
    runtime: GatedRuntime,
    world_backend: object | None,
    *,
    execution_lock: asyncio.Lock,
):
    def invoke(arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            request = world_tool_request(world_backend, tool_name, arguments)
        except (WorldContractError, WorldV1Error) as exc:
            details = getattr(exc, "details", getattr(exc, "context", {}))
            return gate_response_envelope(
                runtime.record_denial(
                    CallRequest(
                        method="MCP",
                        path=f"/_datalox/world-tools/{tool_name}",
                        body=arguments,
                        operation_id=world_tool_operation(world_backend, tool_name),
                    ),
                    reason_code=exc.code,
                    message=exc.message,
                    details=details,
                )
            )
        if request is None:
            return {
                "error": {
                    "code": "world_tool_not_declared",
                    "message": f"World tool is not declared: {tool_name}.",
                }
            }
        return gate_response_envelope(runtime.handle(request))

    async def handle_world_tool(**arguments: Any) -> dict[str, Any]:
        async with execution_lock:
            return await _run_sync_to_completion(invoke, arguments)

    return handle_world_tool


async def _run_sync_to_completion(function, *args):
    worker = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        await worker
        raise


def _signature_from_schema(schema: dict[str, Any]) -> Signature:
    required = set(schema.get("required", []))
    parameters = []
    for name, property_schema in schema.get("properties", {}).items():
        annotation = _annotation_for_json_type(property_schema.get("type"))
        default = Parameter.empty if name in required else None
        parameters.append(
            Parameter(
                name,
                Parameter.KEYWORD_ONLY,
                default=default,
                annotation=annotation,
            )
        )
    return Signature(parameters)


def _annotation_for_json_type(value: str | list[str] | None) -> Any:
    annotations = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "object": dict[str, Any],
        "array": list[Any],
        "null": type(None),
    }
    if isinstance(value, list):
        members = tuple(dict.fromkeys(annotations.get(item, Any) for item in value))
        if not members:
            return Any
        union = members[0]
        for member in members[1:]:
            union |= member
        return union
    return annotations.get(value, Any)
