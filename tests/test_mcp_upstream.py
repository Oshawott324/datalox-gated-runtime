import asyncio
from contextlib import asynccontextmanager
from typing import Any

import pytest
from mcp import types

from datalox_gated_runtime.models import McpUpstreamConfig
from datalox_gated_runtime.mcp_upstream import (
    InProcessMcpUpstreamClient,
    StdioMcpUpstreamClient,
)


class FakeClientSession:
    def __init__(self, read_stream: object, write_stream: object) -> None:
        self.read_stream = read_stream
        self.write_stream = write_stream

    async def __aenter__(self) -> "FakeClientSession":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="get_issue",
                    inputSchema={"type": "object", "properties": {"number": {"type": "integer"}}},
                )
            ]
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text="ok"),
            ],
            structuredContent={"name": name, "arguments": arguments},
            isError=False,
        )


class PaginatedClientSession(FakeClientSession):
    async def list_tools(self, cursor: str | None = None) -> types.ListToolsResult:
        if cursor is None:
            return types.ListToolsResult(
                tools=[
                    types.Tool(
                        name="first_page",
                        inputSchema={"type": "object"},
                    )
                ],
                nextCursor="page_2",
            )
        if cursor == "page_2":
            return types.ListToolsResult(
                tools=[
                    types.Tool(
                        name="second_page",
                        inputSchema={"type": "object"},
                    )
                ],
            )
        raise AssertionError(f"Unexpected cursor: {cursor}")


class FailingClientSession(FakeClientSession):
    async def list_tools(self, cursor: str | None = None) -> types.ListToolsResult:
        raise RuntimeError("server started but did not speak MCP")


def test_stdio_client_uses_config_argv_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    @asynccontextmanager
    async def fake_stdio_client(params):
        seen["command"] = params.command
        seen["args"] = list(params.args)
        yield object(), object()

    monkeypatch.setattr("datalox_gated_runtime.mcp_upstream.stdio_client", fake_stdio_client)
    monkeypatch.setattr("datalox_gated_runtime.mcp_upstream.ClientSession", FakeClientSession)
    client = StdioMcpUpstreamClient(
        {
            "github": McpUpstreamConfig(
                transport="stdio",
                command="github-mcp-server",
                args=["--flag", "value with spaces"],
            )
        }
    )

    tools = asyncio.run(client.list_tools("github"))
    result = asyncio.run(client.call_tool("github", "get_issue", {"number": 123}))

    assert seen == {"command": "github-mcp-server", "args": ["--flag", "value with spaces"]}
    assert tools[0].name == "get_issue"
    assert result == {
        "content": [types.TextContent(type="text", text="ok").model_dump(mode="json")],
        "structuredContent": {"name": "get_issue", "arguments": {"number": 123}},
        "isError": False,
    }


def test_stdio_client_collects_all_list_tools_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    @asynccontextmanager
    async def fake_stdio_client(params):
        yield object(), object()

    monkeypatch.setattr("datalox_gated_runtime.mcp_upstream.stdio_client", fake_stdio_client)
    monkeypatch.setattr("datalox_gated_runtime.mcp_upstream.ClientSession", PaginatedClientSession)
    client = StdioMcpUpstreamClient(
        {
            "github": McpUpstreamConfig(
                transport="stdio",
                command="github-mcp-server",
                args=[],
            )
        }
    )

    tools = asyncio.run(client.list_tools("github"))

    assert [tool.name for tool in tools] == ["first_page", "second_page"]


def test_stdio_client_wraps_sdk_failures_as_stable_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @asynccontextmanager
    async def fake_stdio_client(params):
        yield object(), object()

    monkeypatch.setattr("datalox_gated_runtime.mcp_upstream.stdio_client", fake_stdio_client)
    monkeypatch.setattr("datalox_gated_runtime.mcp_upstream.ClientSession", FailingClientSession)
    client = StdioMcpUpstreamClient(
        {
            "github": McpUpstreamConfig(
                transport="stdio",
                command="github-mcp-server",
                args=[],
            )
        }
    )

    with pytest.raises(ValueError, match="mcp upstream unavailable: github"):
        asyncio.run(client.list_tools("github"))


def test_unknown_upstream_fails_closed() -> None:
    client = StdioMcpUpstreamClient({})

    with pytest.raises(ValueError, match="mcp upstream not configured: github"):
        asyncio.run(client.list_tools("github"))


def test_in_process_client_returns_configured_tools_and_results() -> None:
    client = InProcessMcpUpstreamClient(
        tools={
            "github": [
                types.Tool(
                    name="get_issue",
                    inputSchema={"type": "object", "properties": {"number": {"type": "integer"}}},
                )
            ]
        },
        results={
            ("github", "get_issue"): {
                "structuredContent": {"number": 123, "state": "open"},
                "isError": False,
            }
        },
    )

    tools = asyncio.run(client.list_tools("github"))
    result = asyncio.run(client.call_tool("github", "get_issue", {"number": 123}))

    assert tools[0].name == "get_issue"
    assert result["structuredContent"] == {"number": 123, "state": "open"}
