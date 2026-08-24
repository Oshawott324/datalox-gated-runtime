from __future__ import annotations

from typing import Any, Protocol

from datalox_gated_runtime.models import CallRequest


class WorldMcpBackend(Protocol):
    def tool_schemas(self) -> dict[str, dict[str, Any]]: ...

    def request_for_tool(self, name: str, arguments: dict[str, Any]) -> CallRequest | None: ...


def world_tool_schemas(backend: object | None) -> dict[str, dict[str, Any]]:
    if backend is None or not hasattr(backend, "tool_schemas"):
        return {}
    return backend.tool_schemas()


def world_tool_request(
    backend: object | None,
    name: str,
    arguments: dict[str, Any],
) -> CallRequest | None:
    if backend is None or not hasattr(backend, "request_for_tool"):
        return None
    return backend.request_for_tool(name, arguments)


def world_tool_operation(backend: object | None, name: str) -> str | None:
    if backend is None or not hasattr(backend, "operation_for_tool"):
        return None
    return backend.operation_for_tool(name)
