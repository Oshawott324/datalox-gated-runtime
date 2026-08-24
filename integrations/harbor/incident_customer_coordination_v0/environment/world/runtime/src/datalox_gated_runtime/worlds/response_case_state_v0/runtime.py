from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from datalox_gated_runtime.models import CallRequest, ResponseCaseStateWorldConfig
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import (
    Effect,
    Operation,
    PathBinding,
    Route,
    ToolContract,
    WorldContractError,
)
from datalox_gated_runtime.worlds.response_case_state_v0.router import match_route, render_path
from datalox_gated_runtime.worlds.response_case_state_v0.state import (
    connect,
    load_metadata,
    load_state,
    record_world_event,
    resolve_state_db_path,
    write_state,
)
from datalox_gated_runtime.worlds.response_case_state_v0.transitions import (
    apply_effects,
    resolve_pointer,
)


class ResponseCaseStateWorldBackend:
    world_id = "response_case_state_v0"

    def __init__(self, *, run_dir: Path, config: ResponseCaseStateWorldConfig) -> None:
        self.db_path = resolve_state_db_path(run_dir, config)
        if not self.db_path.exists():
            raise ValueError(f"response_case_state_v0 state is not initialized: {self.db_path}")
        with connect(self.db_path) as connection:
            self.routes = [_route_from_dict(item) for item in load_metadata(connection, "routes")]
            self.operations = {
                operation.operation_id: operation
                for operation in (
                    _operation_from_dict(item) for item in load_metadata(connection, "operations")
                )
            }
            self.tools = [_tool_from_dict(item) for item in load_metadata(connection, "tools")]
        self.routes_by_operation = {route.operation_id: route for route in self.routes}
        self.tools_by_name = {tool.name: tool for tool in self.tools}

    def handle(self, request: CallRequest) -> WorldResponse | None:
        try:
            matched = match_route(
                self.routes,
                request.normalized_method(),
                request.path,
                request.query,
            )
        except WorldContractError as exc:
            return self._error_response(exc, operation_id=request.operation_id)
        if matched is None:
            return self._error_response(
                WorldContractError(
                    "world_route_not_declared",
                    f"No declared world route matches {request.normalized_method()} {request.path}.",
                ),
                operation_id=request.operation_id,
                status_code=404,
                decision_kind="miss",
            )

        route = matched.route
        try:
            with connect(self.db_path) as connection:
                state = load_state(connection)
                _validate_path_bindings(route, matched.path_parameters, state)

                if route.method == "GET":
                    _validate_request(
                        {} if request.body is None else request.body, route.request_schema
                    )
                    return WorldResponse(
                        route.success_status_code,
                        deepcopy(state[route.response_state]),
                        False,
                        world_id=self.world_id,
                        operation_id=route.operation_id,
                        decision_kind="replay",
                        reason_code="world_state_read",
                        message="World state was read.",
                    )

                operation = self.operations.get(route.operation_id)
                if operation is None:
                    raise WorldContractError(
                        "undeclared_route_operation",
                        f"Route operation is not declared: {route.operation_id}.",
                    )
                if operation.disposition == "deny":
                    return WorldResponse(
                        403,
                        _error_body(
                            operation.reason_code or "world_operation_denied",
                            operation.message or "Operation denied.",
                        ),
                        False,
                        world_id=self.world_id,
                        operation_id=route.operation_id,
                        decision_kind="deny",
                        reason_code=operation.reason_code,
                        message=operation.message,
                    )

                request_body = {} if request.body is None else request.body
                _validate_request(request_body, route.request_schema)
                connection.execute("BEGIN IMMEDIATE")
                updated = apply_effects(state, request_body, operation.effects)
                response_body = (
                    deepcopy(updated[route.response_state])
                    if route.response_state is not None
                    else None
                )
                write_state(connection, updated)
                record_world_event(
                    connection,
                    operation_id=route.operation_id,
                    route_id=route.route_id,
                    method=route.method,
                    path=request.path,
                    request=request_body,
                    response=response_body,
                    created_at=_now(),
                )
                connection.commit()
                return WorldResponse(
                    route.success_status_code,
                    response_body,
                    True,
                    world_id=self.world_id,
                    operation_id=route.operation_id,
                    decision_kind="shadow_write",
                    reason_code="world_state_write",
                    message="World state was mutated.",
                )
        except WorldContractError as exc:
            return self._error_response(exc, operation_id=route.operation_id)

    def tool_schemas(self) -> dict[str, dict[str, Any]]:
        return {
            tool.name: {
                "description": tool.description,
                "inputSchema": deepcopy(tool.input_schema),
            }
            for tool in self.tools
        }

    def request_for_tool(self, name: str, arguments: dict[str, Any]) -> CallRequest | None:
        tool = self.tools_by_name.get(name)
        if tool is None:
            return None
        route = self.routes_by_operation[tool.operation_id]
        _validate_request(arguments, tool.input_schema)
        path, body = render_path(route, arguments)
        return CallRequest(
            method=route.method,
            path=path,
            query=deepcopy(route.query),
            body=None if route.method == "GET" else body,
            operation_id=route.operation_id,
        )

    def operation_for_tool(self, name: str) -> str | None:
        tool = self.tools_by_name.get(name)
        return tool.operation_id if tool is not None else None

    def _error_response(
        self,
        error: WorldContractError,
        *,
        operation_id: str | None,
        status_code: int = 400,
        decision_kind: str = "deny",
    ) -> WorldResponse:
        return WorldResponse(
            status_code,
            _error_body(error.code, error.message, error.details),
            False,
            world_id=self.world_id,
            operation_id=operation_id,
            decision_kind=decision_kind,
            reason_code=error.code,
            message=error.message,
        )


def _validate_path_bindings(
    route: Route,
    actual_parameters: dict[str, str],
    state: dict[str, Any],
) -> None:
    for name, binding in route.path_parameters.items():
        expected = resolve_pointer(state[binding.state_key], binding.pointer)
        if not isinstance(expected, str) or actual_parameters[name] != expected:
            raise WorldContractError(
                "world_path_parameter_mismatch",
                f"Path parameter {name} does not identify the selected episode state.",
                details={"parameter": name},
            )


def _validate_request(value: Any, schema: dict[str, Any]) -> None:
    _validate_schema_value(value, schema, "")


def _validate_schema_value(value: Any, schema: dict[str, Any], pointer: str) -> None:
    expected_type = schema["type"]
    if not _matches_type(value, expected_type):
        location = pointer or "request body"
        raise WorldContractError(
            "invalid_world_request",
            f"Request value {location} has the wrong type.",
            details={"pointer": pointer, "expected_type": expected_type},
        )
    if "enum" in schema and value not in schema["enum"]:
        raise WorldContractError(
            "invalid_world_request",
            f"Request value {pointer or 'request body'} is not an allowed value.",
            details={"pointer": pointer, "allowed": schema["enum"]},
        )
    if expected_type == "array" and "items" in schema:
        for index, item in enumerate(value):
            _validate_schema_value(item, schema["items"], f"{pointer}/{index}")
        return
    if expected_type != "object":
        return

    properties = schema.get("properties", {})
    required = schema.get("required", [])
    missing = [name for name in required if name not in value]
    if missing:
        raise WorldContractError(
            "invalid_world_request",
            f"Request is missing required fields: {', '.join(missing)}.",
            details={"pointer": pointer, "missing": missing},
        )
    unknown = sorted(set(value) - set(properties))
    if unknown and schema.get("additionalProperties") is False:
        raise WorldContractError(
            "invalid_world_request",
            f"Request has undeclared fields: {', '.join(unknown)}.",
            details={"pointer": pointer, "unknown": unknown},
        )
    for name, item in value.items():
        property_schema = properties.get(name)
        if property_schema is None:
            continue
        _validate_schema_value(item, property_schema, f"{pointer}/{name}")


def _matches_type(value: Any, expected: str) -> bool:
    checks = {
        "string": lambda: isinstance(value, str),
        "integer": lambda: type(value) is int,
        "number": lambda: type(value) in {int, float},
        "boolean": lambda: type(value) is bool,
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
        "null": lambda: value is None,
    }
    return checks[expected]()


def _route_from_dict(raw: dict[str, Any]) -> Route:
    return Route(
        route_id=raw["route_id"],
        method=raw["method"],
        path_template=raw["path_template"],
        operation_id=raw["operation_id"],
        query=raw["query"],
        success_status_code=raw["success_status_code"],
        response_state=raw["response_state"],
        path_parameters={
            name: PathBinding(**binding) for name, binding in raw["path_parameters"].items()
        },
        request_schema=raw["request_schema"],
    )


def _operation_from_dict(raw: dict[str, Any]) -> Operation:
    return Operation(
        operation_id=raw["operation_id"],
        disposition=raw["disposition"],
        effects=[Effect(**effect) for effect in raw["effects"]],
        reason_code=raw.get("reason_code"),
        message=raw.get("message"),
    )


def _tool_from_dict(raw: dict[str, Any]) -> ToolContract:
    return ToolContract(**raw)


def _error_body(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details or {}}}


def _now() -> str:
    return datetime.now(UTC).isoformat()
