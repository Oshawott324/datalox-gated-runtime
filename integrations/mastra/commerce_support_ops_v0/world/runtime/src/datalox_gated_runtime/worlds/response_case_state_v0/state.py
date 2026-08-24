from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from datalox_gated_runtime.models import ResponseCaseStateWorldConfig, TaskBrief
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import (
    Effect,
    Episode,
    Route,
    WorldArtifacts,
    WorldContractError,
    load_world_artifacts,
)
from datalox_gated_runtime.worlds.response_case_state_v0.router import validate_routes
from datalox_gated_runtime.worlds.response_case_state_v0.transitions import (
    decode_pointer,
    json_type,
    resolve_pointer,
)

WORLD_KIND = "response_case_state_v0"
WORLD_DIR_NAME = WORLD_KIND
RUN_METADATA_NAME = "run.json"


def connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def world_dir(run_dir: Path) -> Path:
    return run_dir / "world" / WORLD_DIR_NAME


def metadata_path(run_dir: Path) -> Path:
    return world_dir(run_dir) / RUN_METADATA_NAME


def resolve_state_db_path(
    run_dir: Path,
    config: ResponseCaseStateWorldConfig | None = None,
) -> Path:
    if config is not None:
        return world_dir(run_dir) / config.state_db
    try:
        metadata = json.loads(metadata_path(run_dir).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid response_case_state_v0 run metadata") from exc
    state_db = metadata.get("state_db")
    if not isinstance(state_db, str) or not state_db or "/" in state_db or "\\" in state_db:
        raise ValueError("invalid response_case_state_v0 run metadata state_db")
    return world_dir(run_dir) / state_db


def initialize_world_state(
    *,
    run_dir: Path,
    config: ResponseCaseStateWorldConfig,
    source_dir: Path,
) -> None:
    artifacts = load_world_artifacts(source_dir, config)
    validate_routes(artifacts.routes)
    for candidate in artifacts.episodes:
        _validate_episode(artifacts, candidate)
    episode_index = config.seed % len(artifacts.episodes)
    episode = artifacts.episodes[episode_index]

    directory = world_dir(run_dir)
    db_path = resolve_state_db_path(run_dir, config)
    run_metadata_path = metadata_path(run_dir)
    if db_path.exists() or run_metadata_path.exists():
        raise FileExistsError(f"Run directory already contains {WORLD_KIND} state: {directory}")
    directory.mkdir(parents=True, exist_ok=True)

    with connect(db_path) as connection:
        connection.executescript(SCHEMA_SQL)
        for state_key, value in episode.state.items():
            connection.execute(
                "INSERT INTO state_views (state_key, value_json) VALUES (?, ?)",
                (state_key, dumps_json(value)),
            )
        metadata = {
            "episode": asdict(episode),
            "routes": [asdict(route) for route in artifacts.routes],
            "operations": [asdict(operation) for operation in artifacts.operations],
            "verifier_assertions": [
                asdict(assertion) for assertion in artifacts.verifier_assertions
            ],
            "tools": [asdict(tool) for tool in artifacts.tools],
            "sources": artifacts.sources,
        }
        for key, value in metadata.items():
            connection.execute(
                "INSERT INTO world_metadata (key, value_json) VALUES (?, ?)",
                (key, dumps_json(value)),
            )

    run_metadata = {
        "world": WORLD_KIND,
        "seed": config.seed,
        "episode_index": episode_index,
        "episode_id": episode.episode_id,
        "state_db": config.state_db,
        "verifier": "response_case_state_v0",
    }
    run_metadata_path.write_text(
        json.dumps(run_metadata, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_state(connection: sqlite3.Connection) -> dict[str, Any]:
    return {
        row["state_key"]: loads_json(row["value_json"])
        for row in connection.execute(
            "SELECT state_key, value_json FROM state_views ORDER BY state_key"
        )
    }


def load_metadata(connection: sqlite3.Connection, key: str) -> Any:
    row = connection.execute(
        "SELECT value_json FROM world_metadata WHERE key = ?", (key,)
    ).fetchone()
    if row is None:
        raise ValueError(f"missing response_case_state_v0 metadata: {key}")
    return loads_json(row["value_json"])


def load_selected_task(run_dir: Path) -> TaskBrief:
    with connect(resolve_state_db_path(run_dir)) as connection:
        episode = load_metadata(connection, "episode")
    return TaskBrief(**episode["task"])


def write_state(connection: sqlite3.Connection, state: dict[str, Any]) -> None:
    for state_key, value in state.items():
        cursor = connection.execute(
            "UPDATE state_views SET value_json = ? WHERE state_key = ?",
            (dumps_json(value), state_key),
        )
        if cursor.rowcount != 1:
            raise WorldContractError(
                "state_key_missing", f"State key is not declared: {state_key}."
            )


def record_world_event(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    route_id: str,
    method: str,
    path: str,
    request: Any,
    response: Any,
    created_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO world_events (
          operation_id, route_id, method, path, request_json, response_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            operation_id,
            route_id,
            method,
            path,
            dumps_json(request),
            dumps_json(response),
            created_at,
        ),
    )


def dumps_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def loads_json(value: str) -> Any:
    return json.loads(value)


def _validate_episode(artifacts: WorldArtifacts, episode: Episode) -> None:
    state_keys = set(episode.state)
    for route in artifacts.routes:
        if route.response_state is not None and route.response_state not in state_keys:
            raise WorldContractError(
                "state_key_missing", f"Route {route.route_id} response state is not declared."
            )
        for name, binding in route.path_parameters.items():
            if binding.state_key not in state_keys:
                raise WorldContractError(
                    "state_key_missing", f"Route {route.route_id} binding state is not declared."
                )
            value = resolve_pointer(episode.state[binding.state_key], binding.pointer)
            if not isinstance(value, str):
                raise WorldContractError(
                    "invalid_path_parameter_binding",
                    f"Route {route.route_id} binding {name} must resolve to a string.",
                )

    routes_by_operation: dict[str, list[Route]] = {}
    for route in artifacts.routes:
        routes_by_operation.setdefault(route.operation_id, []).append(route)
    for operation in artifacts.operations:
        for effect in operation.effects:
            if effect.state_key not in state_keys:
                raise WorldContractError(
                    "state_key_missing",
                    f"Operation {operation.operation_id} target state is not declared.",
                )
            if effect.target == "":
                raise WorldContractError(
                    "state_parent_missing",
                    f"Operation {operation.operation_id} cannot replace a state view root.",
                )
            target_value = resolve_pointer(episode.state[effect.state_key], effect.target)
            if effect.source_state_key is not None and effect.source_state_key not in state_keys:
                raise WorldContractError(
                    "state_key_missing",
                    f"Operation {operation.operation_id} source state is not declared.",
                )
            if effect.operator == "set_literal":
                _require_type(
                    json_type(target_value), json_type(effect.value), operation.operation_id
                )
            elif effect.operator in {"set_from_request", "append_from_request"}:
                request_type = _request_pointer_type(
                    routes_by_operation.get(operation.operation_id, []),
                    effect.request_pointer or "",
                    operation.operation_id,
                )
                if effect.operator == "set_from_request":
                    _require_type(json_type(target_value), request_type, operation.operation_id)
                else:
                    if not isinstance(target_value, list):
                        raise WorldContractError(
                            "state_type_mismatch",
                            f"Operation {operation.operation_id} append target must be an array.",
                        )
                    for item in target_value:
                        _require_type(json_type(item), request_type, operation.operation_id)
            elif effect.operator == "set_from_state_lookup":
                _validate_state_lookup(
                    episode=episode,
                    operation_id=operation.operation_id,
                    effect=effect,
                    target_value=target_value,
                    routes=routes_by_operation.get(operation.operation_id, []),
                )
            elif effect.operator == "copy_state":
                source_value = resolve_pointer(
                    episode.state[effect.source_state_key], effect.source_pointer or ""
                )
                _require_type(
                    json_type(target_value),
                    json_type(source_value),
                    operation.operation_id,
                )
    for assertion in artifacts.verifier_assertions:
        if assertion.state_key is not None and assertion.state_key not in state_keys:
            raise WorldContractError(
                "state_key_missing", f"Verifier assertion {assertion.name} state is not declared."
            )
        if (
            assertion.another_state_key is not None
            and assertion.another_state_key not in state_keys
        ):
            raise WorldContractError(
                "state_key_missing",
                f"Verifier assertion {assertion.name} comparison state is not declared.",
            )
        if assertion.assertion_type == "state_values_equal":
            state_value = resolve_pointer(
                episode.state[assertion.state_key], assertion.pointer or ""
            )
            another_value = resolve_pointer(
                episode.state[assertion.another_state_key],
                assertion.another_pointer or "",
            )
            _require_type(
                json_type(state_value),
                json_type(another_value),
                assertion.name,
            )
            continue
        expected = (
            resolve_pointer(
                episode.expected,
                assertion.expected_pointer,
                missing_code="expected_value_missing",
            )
            if assertion.expected_pointer is not None
            else assertion.expected
        )
        if assertion.state_key is not None:
            state_value = resolve_pointer(
                episode.state[assertion.state_key], assertion.pointer or ""
            )
            if assertion.assertion_type == "state_text_contains_all":
                _validate_text_contains_expected(assertion.name, state_value, expected)
            elif assertion.assertion_type == "state_array_projection_equals_unordered":
                _validate_array_projection_expected(
                    assertion.name,
                    state_value,
                    assertion.item_pointer or "",
                    expected,
                )
            else:
                _require_type(json_type(state_value), json_type(expected), assertion.name)
        if assertion.assertion_type == "request_value_equals":
            request_type = _request_pointer_type(
                routes_by_operation.get(assertion.operation_id or "", []),
                assertion.request_pointer or "",
                assertion.operation_id or assertion.name,
            )
            _require_type(request_type, json_type(expected), assertion.name)

    source_by_id = {source["source_id"]: source for source in artifacts.sources}
    for index, provenance in enumerate(episode.provenance):
        source_id = provenance.get("source_id")
        if source_id is None:
            continue
        source = source_by_id.get(source_id)
        if source is None:
            raise WorldContractError(
                "unknown_provenance_source",
                f"Episode {episode.episode_id} provenance[{index}] references unknown source {source_id}.",
            )
        if source["classification"] != provenance["classification"]:
            raise WorldContractError(
                "provenance_classification_mismatch",
                f"Episode {episode.episode_id} provenance[{index}] classification does not match its source.",
            )


def _request_pointer_type(routes: list[Route], pointer: str, operation_id: str) -> str:
    declared_types = {
        _schema_pointer_type(route.request_schema, pointer, operation_id) for route in routes
    }
    declared_types.discard(None)
    if len(declared_types) != 1:
        raise WorldContractError(
            "request_value_missing",
            f"Operation {operation_id} request pointer is not declared consistently by its routes.",
        )
    return declared_types.pop()


def _schema_pointer_type(schema: dict[str, Any], pointer: str, operation_id: str) -> str | None:
    current = schema
    for token in decode_pointer(pointer):
        if current.get("type") == "object":
            current = current.get("properties", {}).get(token)
        elif current.get("type") == "array" and token.isascii() and token.isdigit():
            current = current.get("items")
        else:
            current = None
        if not isinstance(current, dict):
            raise WorldContractError(
                "request_value_missing",
                f"Operation {operation_id} request pointer is not declared by its routes.",
            )
    return current.get("type")


def _validate_state_lookup(
    *,
    episode: Episode,
    operation_id: str,
    effect: Effect,
    target_value: Any,
    routes: list[Route],
) -> None:
    request_type = _request_pointer_type(
        routes,
        effect.request_pointer or "",
        operation_id,
    )
    source = resolve_pointer(
        episode.state[effect.source_state_key],
        effect.source_pointer or "",
        missing_code="state_lookup_source_missing",
    )
    if not isinstance(source, list):
        raise WorldContractError(
            "state_lookup_source_not_array",
            f"Operation {operation_id} lookup source must be an array.",
        )
    if not source:
        raise WorldContractError(
            "state_lookup_source_empty",
            f"Operation {operation_id} lookup source must not be empty.",
        )

    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(source):
        match_value = resolve_pointer(
            item,
            effect.match_pointer or "",
            missing_code="state_lookup_match_missing",
        )
        projected_value = resolve_pointer(
            item,
            effect.value_pointer or "",
            missing_code="state_lookup_value_missing",
        )
        match_type = json_type(match_value)
        if match_type != request_type:
            raise WorldContractError(
                "state_lookup_match_type_mismatch",
                f"Operation {operation_id} lookup item {index} match type is incompatible with its request pointer.",
            )
        if json_type(projected_value) != json_type(target_value):
            raise WorldContractError(
                "state_lookup_value_type_mismatch",
                f"Operation {operation_id} lookup item {index} value type is incompatible with its target.",
            )
        key = (match_type, dumps_json(match_value))
        if key in seen:
            raise WorldContractError(
                "state_lookup_ambiguous",
                f"Operation {operation_id} lookup match values must be unique.",
            )
        seen.add(key)


def _require_type(actual: str, expected: str, operation_id: str) -> None:
    if actual != expected:
        raise WorldContractError(
            "state_type_mismatch",
            f"Operation or assertion {operation_id} has incompatible declared JSON value types.",
        )


def _validate_text_contains_expected(name: str, state_value: Any, expected: Any) -> None:
    if not isinstance(state_value, str):
        raise WorldContractError(
            "state_type_mismatch",
            f"Verifier assertion {name} must target a string state value.",
        )
    if (
        not isinstance(expected, list)
        or not expected
        or any(not isinstance(value, str) or not value.strip() for value in expected)
    ):
        raise WorldContractError(
            "invalid_verifier_expected",
            f"Verifier assertion {name} requires a non-empty list of non-empty strings.",
        )


def _validate_array_projection_expected(
    name: str,
    state_value: Any,
    item_pointer: str,
    expected: Any,
) -> None:
    if not isinstance(state_value, list) or not isinstance(expected, list):
        raise WorldContractError(
            "state_type_mismatch",
            f"Verifier assertion {name} requires array state and expected values.",
        )
    projected = [resolve_pointer(item, item_pointer) for item in state_value]
    for value in [*projected, *expected]:
        if isinstance(value, (dict, list)):
            raise WorldContractError(
                "invalid_verifier_expected",
                f"Verifier assertion {name} projections must be JSON scalar values.",
            )
    projected_types = {json_type(value) for value in projected}
    expected_types = {json_type(value) for value in expected}
    if projected_types and expected_types and projected_types != expected_types:
        raise WorldContractError(
            "state_type_mismatch",
            f"Verifier assertion {name} projection types do not match expected values.",
        )


SCHEMA_SQL = """
CREATE TABLE world_metadata (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL
);

CREATE TABLE state_views (
  state_key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL
);

CREATE TABLE world_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id TEXT NOT NULL,
  route_id TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  request_json TEXT NOT NULL,
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_world_events_operation ON world_events(operation_id, id);
"""
