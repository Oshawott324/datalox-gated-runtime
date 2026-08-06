from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from datalox_gated_runtime.models import (
    ResponseCaseStateWorldConfig,
    TaskBrief,
)
from datalox_gated_runtime.query import QueryParams, normalize_query

JsonValue = dict[str, Any] | list[Any] | str | int | float | bool | None
TransitionOperator = Literal[
    "set_literal",
    "set_from_request",
    "set_from_state_lookup",
    "append_from_request",
    "copy_state",
]
VerifierAssertionType = Literal[
    "state_equals",
    "state_values_equal",
    "state_text_contains_all",
    "state_array_projection_equals_unordered",
    "operation_present",
    "operation_absent",
    "operation_not_attempted",
    "operation_denied",
    "operation_order",
    "request_value_equals",
]

PROVENANCE_CLASSIFICATIONS = {
    "official_documented_example",
    "official_schema_instantiated",
    "fixture_authored",
    "model_generated",
}


class WorldContractError(ValueError):
    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass(frozen=True)
class Episode:
    episode_id: str
    state: dict[str, JsonValue]
    task: TaskBrief
    metadata: dict[str, Any] = field(default_factory=dict)
    expected: dict[str, Any] = field(default_factory=dict)
    provenance: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class PathBinding:
    state_key: str
    pointer: str


@dataclass(frozen=True)
class Route:
    route_id: str
    method: str
    path_template: str
    operation_id: str
    query: QueryParams
    success_status_code: int
    response_state: str | None
    path_parameters: dict[str, PathBinding]
    request_schema: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "query", normalize_query(self.query))


@dataclass(frozen=True)
class Effect:
    operator: TransitionOperator
    state_key: str
    target: str
    value: JsonValue | None = None
    request_pointer: str | None = None
    source_state_key: str | None = None
    source_pointer: str | None = None
    match_pointer: str | None = None
    value_pointer: str | None = None


@dataclass(frozen=True)
class Operation:
    operation_id: str
    disposition: Literal["mutate", "deny"]
    effects: list[Effect]
    reason_code: str | None = None
    message: str | None = None


@dataclass(frozen=True)
class ToolContract:
    name: str
    operation_id: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class VerifierAssertion:
    name: str
    assertion_type: VerifierAssertionType
    state_key: str | None = None
    pointer: str | None = None
    another_state_key: str | None = None
    another_pointer: str | None = None
    expected: JsonValue | None = None
    expected_pointer: str | None = None
    item_pointer: str | None = None
    operation_id: str | None = None
    operations: list[str] = field(default_factory=list)
    request_pointer: str | None = None


@dataclass(frozen=True)
class WorldArtifacts:
    episodes: list[Episode]
    routes: list[Route]
    operations: list[Operation]
    verifier_assertions: list[VerifierAssertion]
    tools: list[ToolContract]
    sources: list[dict[str, Any]]


def load_world_artifacts(source_dir: Path, config: ResponseCaseStateWorldConfig) -> WorldArtifacts:
    episodes = parse_episodes_jsonl(_artifact_path(source_dir, config.episodes))
    routes = parse_routes(_read_json(_artifact_path(source_dir, config.routes), "routes"))
    operations = parse_operations(
        _read_json(_artifact_path(source_dir, config.transitions), "transitions")
    )
    verifier_assertions = parse_verifier(
        _read_json(_artifact_path(source_dir, config.verifier), "verifier")
    )
    tools = parse_tool_catalog(
        _read_json(_artifact_path(source_dir, config.tool_catalog), "tool catalog")
    )
    sources = parse_sources(_read_json(_artifact_path(source_dir, config.sources), "sources"))
    _validate_cross_references(routes, operations, tools, verifier_assertions)
    return WorldArtifacts(episodes, routes, operations, verifier_assertions, tools, sources)


def parse_episodes_jsonl(path: Path) -> list[Episode]:
    episodes: list[Episode] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise WorldContractError(
            "world_artifact_missing", f"Episode artifact not found: {path}"
        ) from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise WorldContractError(
                "invalid_episodes_jsonl", f"Invalid episode JSON at line {line_number}."
            ) from exc
        episodes.append(_parse_episode(raw, line_number))
    if not episodes:
        raise WorldContractError(
            "empty_episodes", "episodes.jsonl must contain at least one episode."
        )
    _reject_duplicate([episode.episode_id for episode in episodes], "episode_id")
    return episodes


def parse_routes(raw: Any) -> list[Route]:
    root = _strict_object(raw, {"version", "routes"}, "routes")
    _require_version(root, "response_case_routes_v0", "routes")
    items = _object_list(root.get("routes"), "routes.routes")
    routes = [_parse_route(item, index) for index, item in enumerate(items)]
    if not routes:
        raise WorldContractError("empty_routes", "routes.routes must not be empty.")
    _reject_duplicate([route.route_id for route in routes], "route_id")
    _reject_duplicate(
        [
            (route.method, route.path_template, tuple(sorted(route.query.items())))
            for route in routes
        ],
        "route signature",
    )
    return routes


def parse_operations(raw: Any) -> list[Operation]:
    root = _strict_object(raw, {"version", "operations"}, "transitions")
    _require_version(root, "response_case_transitions_v0", "transitions")
    items = _object_list(root.get("operations"), "transitions.operations")
    operations = [_parse_operation(item, index) for index, item in enumerate(items)]
    _reject_duplicate([operation.operation_id for operation in operations], "operation_id")
    return operations


def parse_tool_catalog(raw: Any) -> list[ToolContract]:
    root = _strict_object(raw, {"version", "tools"}, "tool_catalog")
    _require_version(root, "response_case_tool_catalog_v0", "tool_catalog")
    tools = [
        _parse_tool(item, index)
        for index, item in enumerate(_object_list(root.get("tools"), "tools"))
    ]
    _reject_duplicate([tool.name for tool in tools], "tool name")
    _reject_duplicate([tool.operation_id for tool in tools], "tool operation_id")
    return tools


def parse_verifier(raw: Any) -> list[VerifierAssertion]:
    root = _strict_object(raw, {"version", "assertions"}, "verifier")
    _require_version(root, "response_case_verifier_v0", "verifier")
    assertions = [
        _parse_verifier_assertion(item, index)
        for index, item in enumerate(_object_list(root.get("assertions"), "verifier.assertions"))
    ]
    _reject_duplicate([assertion.name for assertion in assertions], "verifier assertion name")
    return assertions


def parse_sources(raw: Any) -> list[dict[str, Any]]:
    root = _strict_object(raw, {"version", "sources"}, "sources")
    _require_version(root, "response_case_sources_v0", "sources")
    allowed = {
        "source_id",
        "classification",
        "url",
        "locator",
        "generation_model",
        "generation_version",
        "notes",
    }
    sources: list[dict[str, Any]] = []
    for index, item in enumerate(_object_list(root.get("sources"), "sources.sources")):
        source = _strict_object(
            item, allowed, f"sources.sources[{index}]", required={"source_id", "classification"}
        )
        _non_empty_string(source.get("source_id"), f"sources.sources[{index}].source_id")
        classification = source.get("classification")
        if classification not in PROVENANCE_CLASSIFICATIONS:
            raise WorldContractError(
                "invalid_provenance_classification",
                f"sources.sources[{index}].classification is not supported.",
            )
        for key in allowed - {"classification"}:
            if key in source:
                _non_empty_string(source[key], f"sources.sources[{index}].{key}")
        sources.append(source)
    _reject_duplicate([source["source_id"] for source in sources], "source_id")
    return sources


def _parse_episode(raw: Any, line_number: int) -> Episode:
    context = f"episodes[{line_number}]"
    item = _strict_object(
        raw,
        {"episode_id", "state", "metadata", "task", "expected", "provenance"},
        context,
        required={"episode_id", "state"},
    )
    episode_id = _non_empty_string(item.get("episode_id"), f"{context}.episode_id")
    state = item.get("state")
    if not isinstance(state, dict) or not state:
        raise WorldContractError(
            "invalid_episode_state", f"{context}.state must be a non-empty object."
        )
    for state_key in state:
        _non_empty_string(state_key, f"{context}.state key")
    metadata = _optional_object(item, "metadata", context)
    task = _parse_task(item.get("task"), context)
    expected = _optional_object(item, "expected", context)
    provenance = item.get("provenance", [])
    if not isinstance(provenance, list) or any(not isinstance(entry, dict) for entry in provenance):
        raise WorldContractError(
            "invalid_episode_provenance", f"{context}.provenance must be a list of objects."
        )
    for index, entry in enumerate(provenance):
        entry = _strict_object(
            entry,
            {
                "classification",
                "source_id",
                "source_url",
                "locator",
                "generation_model",
                "generation_version",
                "notes",
            },
            f"{context}.provenance[{index}]",
            required={"classification"},
        )
        classification = entry.get("classification")
        if classification not in PROVENANCE_CLASSIFICATIONS:
            raise WorldContractError(
                "invalid_provenance_classification",
                f"{context}.provenance[{index}].classification is not supported.",
            )
        for key, value in entry.items():
            if key != "classification":
                _non_empty_string(value, f"{context}.provenance[{index}].{key}")
    return Episode(
        episode_id=episode_id,
        state=state,
        task=task,
        metadata=metadata,
        expected=expected,
        provenance=provenance,
    )


def _parse_task(raw: Any, context: str) -> TaskBrief:
    task = _strict_object(
        raw,
        {"task_id", "title", "instructions", "success_criteria"},
        f"{context}.task",
    )
    success_criteria = task.get("success_criteria")
    if not isinstance(success_criteria, list) or not success_criteria:
        raise WorldContractError(
            "invalid_episode_task",
            f"{context}.task.success_criteria must be a non-empty list of strings.",
        )
    return TaskBrief(
        task_id=_non_empty_string(task.get("task_id"), f"{context}.task.task_id"),
        title=_non_empty_string(task.get("title"), f"{context}.task.title"),
        instructions=_non_empty_string(task.get("instructions"), f"{context}.task.instructions"),
        success_criteria=[
            _non_empty_string(value, f"{context}.task.success_criteria")
            for value in success_criteria
        ],
    )


def _parse_route(raw: dict[str, Any], index: int) -> Route:
    context = f"routes.routes[{index}]"
    item = _strict_object(
        raw,
        {
            "route_id",
            "method",
            "path_template",
            "operation_id",
            "query",
            "success_status_code",
            "response_state",
            "path_parameters",
            "request_schema",
        },
        context,
        required={
            "route_id",
            "method",
            "path_template",
            "operation_id",
            "query",
            "success_status_code",
            "response_state",
        },
    )
    route_id = _non_empty_string(item.get("route_id"), f"{context}.route_id")
    method = _non_empty_string(item.get("method"), f"{context}.method").upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise WorldContractError("invalid_route_method", f"{context}.method is not supported.")
    path_template = _non_empty_string(item.get("path_template"), f"{context}.path_template")
    operation_id = _non_empty_string(item.get("operation_id"), f"{context}.operation_id")
    query = item.get("query")
    if not isinstance(query, dict) or any(
        not isinstance(key, str)
        or not key
        or not (
            isinstance(value, str)
            or (isinstance(value, list) and value and all(isinstance(item, str) for item in value))
        )
        for key, value in query.items()
    ):
        raise WorldContractError(
            "invalid_route_query",
            f"{context}.query values must be strings or non-empty arrays of strings.",
        )
    query = normalize_query(query)
    success_status_code = item.get("success_status_code")
    if type(success_status_code) is not int or not 200 <= success_status_code <= 299:
        raise WorldContractError(
            "invalid_success_status_code",
            f"{context}.success_status_code must be an HTTP 2xx status.",
        )
    response_state_raw = item.get("response_state")
    response_state = (
        _non_empty_string(response_state_raw, f"{context}.response_state")
        if response_state_raw is not None
        else None
    )
    if method == "GET" and response_state is None:
        raise WorldContractError(
            "invalid_route_response", f"{context} GET routes require response_state."
        )
    if success_status_code == 204 and response_state is not None:
        raise WorldContractError(
            "invalid_route_response", f"{context} 204 routes require a null response_state."
        )
    parameters_raw = item.get("path_parameters", {})
    if not isinstance(parameters_raw, dict):
        raise WorldContractError(
            "invalid_path_parameters", f"{context}.path_parameters must be an object."
        )
    parameters: dict[str, PathBinding] = {}
    for name, binding_raw in parameters_raw.items():
        _non_empty_string(name, f"{context}.path_parameters key")
        binding = _strict_object(
            binding_raw,
            {"state_key", "pointer"},
            f"{context}.path_parameters.{name}",
            required={"state_key", "pointer"},
        )
        parameters[name] = PathBinding(
            _non_empty_string(
                binding.get("state_key"), f"{context}.path_parameters.{name}.state_key"
            ),
            _json_pointer(binding.get("pointer"), f"{context}.path_parameters.{name}.pointer"),
        )
    schema = item.get(
        "request_schema", {"type": "object", "properties": {}, "additionalProperties": False}
    )
    _validate_schema(schema, f"{context}.request_schema")
    return Route(
        route_id,
        method,
        path_template,
        operation_id,
        dict(query),
        success_status_code,
        response_state,
        parameters,
        schema,
    )


def _parse_operation(raw: dict[str, Any], index: int) -> Operation:
    context = f"transitions.operations[{index}]"
    item = _strict_object(
        raw,
        {"operation_id", "disposition", "effects", "reason_code", "message"},
        context,
        required={"operation_id", "disposition", "effects"},
    )
    operation_id = _non_empty_string(item.get("operation_id"), f"{context}.operation_id")
    disposition = item.get("disposition")
    if disposition not in {"mutate", "deny"}:
        raise WorldContractError(
            "invalid_operation_disposition", f"{context}.disposition must be mutate or deny."
        )
    effects = [
        _parse_effect(effect, effect_index, context)
        for effect_index, effect in enumerate(
            _object_list(item.get("effects"), f"{context}.effects")
        )
    ]
    reason_code = item.get("reason_code")
    message = item.get("message")
    if disposition == "mutate":
        if not effects:
            raise WorldContractError(
                "empty_transition", f"{context}.effects must not be empty for mutate."
            )
        if reason_code is not None or message is not None:
            raise WorldContractError(
                "invalid_transition_operands", f"{context} mutate cannot declare denial fields."
            )
    else:
        if effects:
            raise WorldContractError(
                "invalid_denied_operation", f"{context} deny cannot declare effects."
            )
        reason_code = _non_empty_string(reason_code, f"{context}.reason_code")
        message = _non_empty_string(message, f"{context}.message")
    return Operation(operation_id, disposition, effects, reason_code, message)


def _parse_effect(raw: dict[str, Any], index: int, parent: str) -> Effect:
    context = f"{parent}.effects[{index}]"
    item = _strict_object(
        raw,
        {
            "operator",
            "state_key",
            "target",
            "value",
            "request_pointer",
            "source_state_key",
            "source_pointer",
            "match_pointer",
            "value_pointer",
        },
        context,
        required={"operator", "state_key", "target"},
    )
    operator = item.get("operator")
    required_by_operator = {
        "set_literal": {"value"},
        "set_from_request": {"request_pointer"},
        "set_from_state_lookup": {
            "request_pointer",
            "source_state_key",
            "source_pointer",
            "match_pointer",
            "value_pointer",
        },
        "append_from_request": {"request_pointer"},
        "copy_state": {"source_state_key", "source_pointer"},
    }
    if operator not in required_by_operator:
        raise WorldContractError(
            "unknown_transition_operator", f"{context}.operator is not supported."
        )
    required = required_by_operator[operator]
    operand_fields = {
        "value",
        "request_pointer",
        "source_state_key",
        "source_pointer",
        "match_pointer",
        "value_pointer",
    }
    operands = operand_fields & set(item)
    if operands != required:
        raise WorldContractError(
            "invalid_transition_operands",
            f"{context} requires exactly these operands: {', '.join(sorted(required))}.",
        )
    request_pointer = item.get("request_pointer")
    source_pointer = item.get("source_pointer")
    match_pointer = item.get("match_pointer")
    value_pointer = item.get("value_pointer")
    return Effect(
        operator=operator,
        state_key=_non_empty_string(item.get("state_key"), f"{context}.state_key"),
        target=_json_pointer(item.get("target"), f"{context}.target"),
        value=item.get("value"),
        request_pointer=_json_pointer(request_pointer, f"{context}.request_pointer")
        if request_pointer is not None
        else None,
        source_state_key=(
            _non_empty_string(item.get("source_state_key"), f"{context}.source_state_key")
            if "source_state_key" in item
            else None
        ),
        source_pointer=_json_pointer(source_pointer, f"{context}.source_pointer")
        if source_pointer is not None
        else None,
        match_pointer=_json_pointer(match_pointer, f"{context}.match_pointer")
        if match_pointer is not None
        else None,
        value_pointer=_json_pointer(value_pointer, f"{context}.value_pointer")
        if value_pointer is not None
        else None,
    )


def _parse_tool(raw: dict[str, Any], index: int) -> ToolContract:
    context = f"tool_catalog.tools[{index}]"
    item = _strict_object(
        raw,
        {"name", "operation_id", "description", "input_schema"},
        context,
        required={"name", "operation_id", "description", "input_schema"},
    )
    schema = item.get("input_schema")
    _validate_schema(schema, f"{context}.input_schema")
    return ToolContract(
        _non_empty_string(item.get("name"), f"{context}.name"),
        _non_empty_string(item.get("operation_id"), f"{context}.operation_id"),
        _non_empty_string(item.get("description"), f"{context}.description"),
        schema,
    )


def _parse_verifier_assertion(raw: dict[str, Any], index: int) -> VerifierAssertion:
    context = f"verifier.assertions[{index}]"
    common = {"name", "type"}
    assertion_type = raw.get("type") if isinstance(raw, dict) else None
    fields_by_type = {
        "state_equals": {"state_key", "pointer"},
        "state_values_equal": {
            "state_key",
            "pointer",
            "another_state_key",
            "another_pointer",
        },
        "state_text_contains_all": {"state_key", "pointer"},
        "state_array_projection_equals_unordered": {
            "state_key",
            "pointer",
            "item_pointer",
        },
        "operation_present": {"operation_id"},
        "operation_absent": {"operation_id"},
        "operation_not_attempted": {"operation_id"},
        "operation_denied": {"operation_id"},
        "operation_order": {"operations"},
        "request_value_equals": {"operation_id", "request_pointer"},
    }
    if assertion_type not in fields_by_type:
        raise WorldContractError("unknown_verifier_assertion", f"{context}.type is not supported.")
    required = common | fields_by_type[assertion_type]
    allowed = set(required)
    expected_assertion_types = {
        "state_equals",
        "state_text_contains_all",
        "state_array_projection_equals_unordered",
        "request_value_equals",
    }
    if assertion_type in expected_assertion_types:
        allowed.update({"expected", "expected_pointer"})
    item = _strict_object(raw, allowed, context, required=required)
    if assertion_type in expected_assertion_types:
        expected_fields = {"expected", "expected_pointer"} & set(item)
        if len(expected_fields) != 1:
            raise WorldContractError(
                "invalid_verifier_expected",
                f"{context} requires exactly one of expected or expected_pointer.",
            )
    name = _non_empty_string(item.get("name"), f"{context}.name")
    state_key = item.get("state_key")
    another_state_key = item.get("another_state_key")
    operation_id = item.get("operation_id")
    operations = item.get("operations", [])
    if assertion_type == "operation_order":
        if not isinstance(operations, list) or len(operations) < 2:
            raise WorldContractError(
                "invalid_operation_order", f"{context}.operations must contain at least two ids."
            )
        operations = [_non_empty_string(value, f"{context}.operations") for value in operations]
    if (
        assertion_type == "state_array_projection_equals_unordered"
        and item.get("item_pointer") == ""
    ):
        raise WorldContractError(
            "invalid_verifier_projection",
            f"{context}.item_pointer must select a value within each array item.",
        )
    if "expected" in item:
        _validate_literal_verifier_expected(assertion_type, item["expected"], context)
    return VerifierAssertion(
        name=name,
        assertion_type=assertion_type,
        state_key=_non_empty_string(state_key, f"{context}.state_key")
        if state_key is not None
        else None,
        pointer=_json_pointer(item.get("pointer"), f"{context}.pointer")
        if "pointer" in item
        else None,
        another_state_key=(
            _non_empty_string(another_state_key, f"{context}.another_state_key")
            if another_state_key is not None
            else None
        ),
        another_pointer=(
            _json_pointer(item.get("another_pointer"), f"{context}.another_pointer")
            if "another_pointer" in item
            else None
        ),
        expected=item.get("expected"),
        expected_pointer=(
            _json_pointer(item.get("expected_pointer"), f"{context}.expected_pointer")
            if "expected_pointer" in item
            else None
        ),
        item_pointer=(
            _json_pointer(item.get("item_pointer"), f"{context}.item_pointer")
            if "item_pointer" in item
            else None
        ),
        operation_id=(
            _non_empty_string(operation_id, f"{context}.operation_id")
            if operation_id is not None
            else None
        ),
        operations=operations,
        request_pointer=(
            _json_pointer(item.get("request_pointer"), f"{context}.request_pointer")
            if "request_pointer" in item
            else None
        ),
    )


def _validate_literal_verifier_expected(
    assertion_type: str,
    expected: Any,
    context: str,
) -> None:
    if assertion_type == "state_text_contains_all" and (
        not isinstance(expected, list)
        or not expected
        or any(not isinstance(value, str) or not value.strip() for value in expected)
    ):
        raise WorldContractError(
            "invalid_verifier_expected",
            f"{context}.expected must be a non-empty list of non-empty strings.",
        )
    if assertion_type == "state_array_projection_equals_unordered" and (
        not isinstance(expected, list) or any(isinstance(value, (dict, list)) for value in expected)
    ):
        raise WorldContractError(
            "invalid_verifier_expected",
            f"{context}.expected must be a list of JSON scalar values.",
        )


def _validate_cross_references(
    routes: list[Route],
    operations: list[Operation],
    tools: list[ToolContract],
    assertions: list[VerifierAssertion],
) -> None:
    operation_ids = {operation.operation_id for operation in operations}
    route_operations = {route.operation_id for route in routes}
    unrouted_operations = operation_ids - route_operations
    if unrouted_operations:
        raise WorldContractError(
            "unrouted_world_operation",
            f"Operations have no declared route: {', '.join(sorted(unrouted_operations))}.",
        )
    for route in routes:
        if route.method != "GET" and route.operation_id not in operation_ids:
            raise WorldContractError(
                "undeclared_route_operation",
                f"Route {route.route_id} references undeclared operation {route.operation_id}.",
            )
    for tool in tools:
        if tool.operation_id not in route_operations:
            raise WorldContractError(
                "undeclared_tool_operation",
                f"Tool {tool.name} references undeclared route operation {tool.operation_id}.",
            )
    for assertion in assertions:
        referenced = [assertion.operation_id] if assertion.operation_id is not None else []
        referenced.extend(assertion.operations)
        unknown = sorted(set(referenced) - route_operations)
        if unknown:
            raise WorldContractError(
                "undeclared_verifier_operation",
                f"Verifier assertion {assertion.name} references undeclared operations: {', '.join(unknown)}.",
            )


def _read_json(path: Path, description: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorldContractError(
            "world_artifact_missing", f"{description} artifact not found: {path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise WorldContractError(
            "invalid_world_artifact_json", f"Invalid {description} JSON."
        ) from exc


def _artifact_path(source_dir: Path, relative_path: str) -> Path:
    world_root = (source_dir / "world").resolve()
    artifact = (source_dir / relative_path).resolve()
    if artifact.parent != world_root:
        raise WorldContractError(
            "world_artifact_path_escape",
            f"World artifact escapes the world directory: {relative_path}.",
        )
    return artifact


def _strict_object(
    raw: Any,
    allowed: set[str],
    context: str,
    *,
    required: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise WorldContractError("invalid_world_contract", f"{context} must be an object.")
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise WorldContractError(
            "unknown_world_contract_field", f"{context} has unknown fields: {', '.join(unknown)}."
        )
    missing = sorted((required or allowed) - set(raw))
    if missing:
        raise WorldContractError(
            "missing_world_contract_field", f"{context} is missing fields: {', '.join(missing)}."
        )
    return raw


def _object_list(raw: Any, context: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        raise WorldContractError("invalid_world_contract", f"{context} must be a list of objects.")
    return raw


def _require_version(raw: dict[str, Any], expected: str, context: str) -> None:
    if raw.get("version") != expected:
        raise WorldContractError(
            "unsupported_world_contract_version", f"{context}.version must be {expected}."
        )


def _non_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorldContractError("invalid_world_contract", f"{context} must be a non-empty string.")
    return value


def _json_pointer(value: Any, context: str) -> str:
    pointer = _non_empty_string(value, context) if value != "" else ""
    if pointer != "" and not pointer.startswith("/"):
        raise WorldContractError(
            "invalid_json_pointer", f"{context} must be an RFC 6901 JSON pointer."
        )
    index = 0
    while index < len(pointer):
        if pointer[index] == "~":
            if index + 1 >= len(pointer) or pointer[index + 1] not in {"0", "1"}:
                raise WorldContractError(
                    "invalid_json_pointer", f"{context} has an invalid escape."
                )
            index += 2
            continue
        index += 1
    if any(token == "-" for token in pointer.split("/")[1:]):
        raise WorldContractError(
            "invalid_array_index", f"{context} cannot contain the '-' array index."
        )
    return pointer


def _validate_schema(raw: Any, context: str) -> None:
    schema = _validate_value_schema(raw, context)
    if schema.get("type") != "object":
        raise WorldContractError("invalid_request_schema", f"{context}.type must be object.")
    if schema.get("additionalProperties") is not False:
        raise WorldContractError(
            "invalid_request_schema", f"{context}.additionalProperties must be false."
        )


def _validate_value_schema(raw: Any, context: str) -> dict[str, Any]:
    schema = _strict_object(
        raw,
        {"type", "properties", "required", "additionalProperties", "enum", "items"},
        context,
        required={"type"},
    )
    schema_type = schema.get("type")
    if schema_type not in {
        "string",
        "integer",
        "number",
        "boolean",
        "object",
        "array",
        "null",
    }:
        raise WorldContractError("invalid_request_schema", f"{context}.type is unsupported.")

    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise WorldContractError(
            "invalid_request_schema", f"{context}.enum must be a non-empty list."
        )

    if schema_type != "object" and any(
        key in schema for key in ("properties", "required", "additionalProperties")
    ):
        raise WorldContractError(
            "invalid_request_schema", f"{context} object keywords require type object."
        )

    if schema_type != "array" and "items" in schema:
        raise WorldContractError("invalid_request_schema", f"{context}.items requires type array.")

    if schema_type == "array" and "items" in schema:
        _validate_value_schema(schema["items"], f"{context}.items")

    if schema_type != "object":
        return schema

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise WorldContractError(
            "invalid_request_schema", f"{context}.properties must be an object."
        )
    for name, property_schema in properties.items():
        _non_empty_string(name, f"{context}.properties key")
        _validate_value_schema(property_schema, f"{context}.properties.{name}")
    required = schema.get("required", [])
    if (
        not isinstance(required, list)
        or any(not isinstance(name, str) or name not in properties for name in required)
        or len(required) != len(set(required))
    ):
        raise WorldContractError(
            "invalid_request_schema", f"{context}.required must reference declared properties."
        )
    declares_object_shape = any(
        key in schema for key in ("properties", "required", "additionalProperties")
    )
    if declares_object_shape and schema.get("additionalProperties") is not False:
        raise WorldContractError(
            "invalid_request_schema", f"{context}.additionalProperties must be false."
        )
    return schema


def _optional_object(raw: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = raw.get(key, {})
    if not isinstance(value, dict):
        raise WorldContractError("invalid_world_contract", f"{context}.{key} must be an object.")
    return value


def _reject_duplicate(values: list[Any], description: str) -> None:
    seen: set[Any] = set()
    for value in values:
        if value in seen:
            raise WorldContractError(
                "duplicate_world_contract_id", f"Duplicate {description}: {value}."
            )
        seen.add(value)
