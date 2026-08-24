from __future__ import annotations

from copy import deepcopy
from typing import Any

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client

from datalox_gated_runtime.models import McpUpstreamConfig


class InProcessMcpUpstreamClient:
    def __init__(
        self,
        *,
        tools: dict[str, list[types.Tool]] | None = None,
        results: dict[tuple[str, str], dict[str, Any]] | None = None,
    ) -> None:
        self.tools = tools if tools is not None else {}
        self.results = results if results is not None else {}

    async def list_tools(self, upstream_name: str) -> list[types.Tool]:
        if upstream_name not in self.tools:
            raise ValueError(f"mcp upstream not configured: {upstream_name}")
        return deepcopy(self.tools[upstream_name])

    async def call_tool(
        self,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        key = (upstream_name, upstream_tool_name)
        if key not in self.results:
            raise ValueError(
                f"mcp upstream tool result not configured: {upstream_name}.{upstream_tool_name}"
            )
        return deepcopy(self.results[key])


class StdioMcpUpstreamClient:
    def __init__(self, upstreams: dict[str, McpUpstreamConfig]) -> None:
        self.upstreams = upstreams

    async def list_tools(self, upstream_name: str) -> list[types.Tool]:
        config = self._require_upstream(upstream_name)
        params = StdioServerParameters(command=config.command, args=config.args)
        tools: list[types.Tool] = []
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    cursor: str | None = None
                    while True:
                        result = (
                            await session.list_tools()
                            if cursor is None
                            else await session.list_tools(cursor=cursor)
                        )
                        tools.extend(result.tools)
                        cursor = result.nextCursor
                        if cursor is None:
                            break
        except Exception as exc:
            raise ValueError(f"mcp upstream unavailable: {upstream_name}") from exc
        return tools

    async def call_tool(
        self,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        config = self._require_upstream(upstream_name)
        params = StdioServerParameters(command=config.command, args=config.args)
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool(upstream_tool_name, arguments)
        except Exception as exc:
            raise ValueError(f"mcp upstream unavailable: {upstream_name}") from exc
        return {
            "content": [block.model_dump(mode="json") for block in result.content],
            "structuredContent": result.structuredContent,
            "isError": result.isError,
        }

    def _require_upstream(self, upstream_name: str) -> McpUpstreamConfig:
        config = self.upstreams.get(upstream_name)
        if config is None:
            raise ValueError(f"mcp upstream not configured: {upstream_name}")
        return config
