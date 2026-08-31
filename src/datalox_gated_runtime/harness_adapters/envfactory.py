from __future__ import annotations

import atexit
import hashlib
import json
import re
import shutil
import tempfile
from collections import defaultdict
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools import Tool
from mcp.server.fastmcp.utilities.func_metadata import ArgModelBase, FuncMetadata
from pydantic import ConfigDict, create_model

from datalox_gated_runtime.harness_adapters._shared import atomic_output, sha256
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    build_provider_runtime_from_world,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.world_v1.backend import (
    WorldBundleBackend,
    initialize_world_bundle_session,
)
from datalox_gated_runtime.world_v1.bundle import validate_world_bundle
from datalox_gated_runtime.world_v1.contracts import ActorContext, ToolDefinition

ENVFACTORY_PROJECTION_SCHEMA_VERSION = "datalox_envfactory_projection_v2"
ENVFACTORY_COMPATIBILITY_COMMIT = "eff3b22d3fc26afa14165cfe208c2a4c9ecc39e3"
ENVFACTORY_SCENARIO_SCHEMA_VERSION = "datalox_envfactory_scenario_v1"
_ENVFACTORY_PATCH_NAME = f"envfactory-{ENVFACTORY_COMPATIBILITY_COMMIT}.patch"
_LIFECYCLE_TOOLS = frozenset({"load_scenario", "save_scenario"})
_CHECKPOINT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "metadata": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"clock": {"type": "string", "format": "date-time"}},
            "required": ["clock"],
        },
        "state": {"type": "object"},
    },
    "required": ["id", "metadata", "state"],
}
_CHECKPOINT_VALIDATOR = Draft202012Validator(
    _CHECKPOINT_SCHEMA,
    format_checker=FormatChecker(),
)


class EnvFactoryProjectionError(ValueError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = deepcopy(details or {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "details": deepcopy(self.details),
        }


class _SparseArgModelBase(ArgModelBase):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    def model_dump_one_level(self) -> dict[str, Any]:
        arguments: dict[str, Any] = {}
        for field_name, field_info in self.__class__.model_fields.items():
            if field_name not in self.model_fields_set:
                continue
            output_name = field_info.alias or field_name
            arguments[output_name] = getattr(self, field_name)
        return arguments


class _ProjectionRuntime:
    def __init__(self, root: Path, projection: dict[str, Any]) -> None:
        self.root = root
        self.projection = projection
        self.bundle_dir = root / projection["provider_runtime_path"]
        self.bundle = load_provider_runtime_bundle(self.bundle_dir)
        if self.bundle.seed is None or not self.bundle.tools:
            raise EnvFactoryProjectionError(
                "envfactory.provider_runtime_unsupported",
                "EnvFactory projection requires a stateful provider runtime with tools.",
            )
        self.tools = {tool.id: tool for tool in self.bundle.tools}
        self.tool_by_name = {item["name"]: item for item in projection["tools"]}
        self.root_dir = Path(tempfile.mkdtemp(prefix="datalox-envfactory-runtime-"))
        self.runtime: ProviderRuntime | None = None
        self.run_dir: Path | None = None
        self.scenario_id: str | None = None
        self.template_id: str | None = None
        self.loaded_scenario: dict[str, Any] | None = None
        self.loaded_checkpoint: dict[str, Any] | None = None
        self.run_index = 0

    def cleanup(self) -> None:
        self._close_runtime()
        shutil.rmtree(self.root_dir, ignore_errors=True)

    def _close_runtime(self) -> None:
        if self.runtime is not None:
            self.runtime.close()
            self.runtime = None
        if self.run_dir is not None:
            shutil.rmtree(self.run_dir, ignore_errors=True)
            self.run_dir = None

    def load_scenario(self, scenario: Any) -> None:
        _validate_envfactory_scenario(scenario, projection=self.projection)
        template_id = scenario["template_id"]
        checkpoint = scenario.get("checkpoint")
        if checkpoint is None:
            template_path = self.root / self.projection["scenario_templates"][template_id]
            checkpoint = _read_object(template_path)
        _validate_checkpoint(checkpoint, seed=self.bundle.seed)
        self._close_runtime()
        run_dir = self.root_dir / f"run-{self.run_index:04d}"
        self.run_index += 1
        runtime = ProviderRuntime(bundle_dir=self.bundle_dir, run_dir=run_dir)
        try:
            if runtime.backend is None:
                raise EnvFactoryProjectionError(
                    "envfactory.provider_runtime_unsupported",
                    "Projected provider runtime does not expose resettable state.",
                )
            runtime.backend.session.reset(
                episode_id=checkpoint["id"],
                initial_state=deepcopy(checkpoint["state"]),
                initial_time=checkpoint["metadata"]["clock"],
            )
        except Exception:
            runtime.close()
            shutil.rmtree(run_dir, ignore_errors=True)
            raise
        self.runtime = runtime
        self.run_dir = run_dir
        self.scenario_id = checkpoint["id"]
        self.template_id = template_id
        self.loaded_scenario = deepcopy(scenario)
        self.loaded_checkpoint = deepcopy(checkpoint)

    def save_scenario(self) -> dict[str, Any]:
        runtime = self._require_runtime()
        assert runtime.backend is not None
        checkpoint = {
            "id": self.scenario_id or runtime.backend.session.episode_id,
            "metadata": {"clock": runtime.backend.session.current_time()},
            "state": deepcopy(runtime.backend.session.list_state()),
        }
        _validate_checkpoint(checkpoint, seed=self.bundle.seed)
        if checkpoint == self.loaded_checkpoint and self.loaded_scenario is not None:
            return deepcopy(self.loaded_scenario)
        return {
            "schema_version": ENVFACTORY_SCENARIO_SCHEMA_VERSION,
            "template_id": self.template_id,
            "seed": 0,
            "checkpoint": checkpoint,
        }

    def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        runtime = self._require_runtime()
        item = self.tool_by_name[tool_name]
        operation_id = item["operation_id"]
        validator = Draft202012Validator(
            self.tools[operation_id].input_schema,
            format_checker=FormatChecker(),
        )
        errors = sorted(validator.iter_errors(arguments), key=lambda error: list(error.path))
        if errors:
            error = errors[0]
            raise EnvFactoryProjectionError(
                "envfactory.invalid_arguments",
                error.message,
                {"operation_id": operation_id, "path": list(error.path)},
            )
        actor = ActorContext(
            actor_id=item["service_actor_id"],
            role=item["service_actor_role"],
        )
        response = runtime.invoke_tool(operation_id, arguments, actor=actor)
        if response.status_code >= 400:
            raise EnvFactoryProjectionError(
                response.decision.reason_code or "envfactory.operation_failed",
                response.decision.message or "Provider operation failed.",
                {
                    "operation_id": operation_id,
                    "status_code": response.status_code,
                    "response": deepcopy(response.body),
                },
            )
        return deepcopy(response.body)

    def _require_runtime(self) -> ProviderRuntime:
        if self.runtime is None:
            raise EnvFactoryProjectionError(
                "envfactory.scenario_not_loaded",
                "No scenario is loaded. EnvFactory must call load_scenario first.",
            )
        return self.runtime


def build_envfactory_projection(
    *,
    source_world_dir: Path,
    trajectory_path: Path,
    output_dir: Path,
    provider_id: str,
    authorities: tuple[str, ...],
    episode_id: str,
    server_name: str | None = None,
    scenario_templates: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    """Compile one admitted provider world into an EnvFactory-native overlay."""

    source = validate_world_bundle(source_world_dir)
    if source.episode(episode_id)["id"] != episode_id:
        raise EnvFactoryProjectionError(
            "envfactory.episode_invalid",
            "Selected episode id does not match its declared id.",
        )
    resolved_name = _validated_server_name(server_name or _server_name(provider_id))
    outputs, actor_ids_by_role = _observe_outputs(
        source_world_dir=source_world_dir,
        trajectory_path=trajectory_path,
        episode_id=episode_id,
    )
    safe_names = _safe_tool_names(source.tools)
    missing_outputs = sorted(tool.id for tool in source.tools if tool.id not in outputs)
    if missing_outputs:
        raise EnvFactoryProjectionError(
            "envfactory.output_observation_incomplete",
            "Every projected tool must have at least one successful observed response.",
            {"missing_operation_ids": missing_outputs},
        )

    with atomic_output(output_dir) as temporary:
        datalox_dir = temporary / "envs" / "datalox" / resolved_name
        provider_runtime_dir = datalox_dir / "provider_runtime"
        build_provider_runtime_from_world(
            source_world_dir=source_world_dir,
            output_dir=provider_runtime_dir,
            provider_id=provider_id,
            authorities=authorities,
            episode_id=episode_id,
        )
        bundle = load_provider_runtime_bundle(provider_runtime_dir)
        assert bundle.seed is not None
        templates = _scenario_templates(bundle.seed, scenario_templates)
        template_paths: dict[str, str] = {}
        for template_id, checkpoint in templates.items():
            relative = Path("scenario_templates") / f"{template_id}.json"
            _write_json(datalox_dir / relative, checkpoint)
            template_paths[template_id] = relative.as_posix()
        tools = [
            _project_tool(
                tool,
                safe_name=safe_names[tool.id],
                outputs=outputs[tool.id],
                default_role=bundle.manifest.behavior.default_actor_role,
                actor_ids_by_role=actor_ids_by_role,
            )
            for tool in bundle.tools
        ]
        projection = {
            "schema_version": ENVFACTORY_PROJECTION_SCHEMA_VERSION,
            "provider_id": provider_id,
            "bundle_version": bundle.manifest.bundle_version,
            "server_name": resolved_name,
            "provider_runtime_path": "provider_runtime",
            "scenario_schema_version": ENVFACTORY_SCENARIO_SCHEMA_VERSION,
            "scenario_templates": template_paths,
            "actor_policy": "declared_role_with_observed_scenario_actor_v1",
            "output_contract_provenance": "successful_reference_trajectory_observation_v1",
            "envfactory_compatibility": {
                "commit": ENVFACTORY_COMPATIBILITY_COMMIT,
                "fastmcp": "3.1.0",
            },
            "tools": tools,
        }
        metadata = {
            "class_name": resolved_name,
            "description": (
                f"Datalox resettable {provider_id} provider behavior projected for EnvFactory."
            ),
            "tools": [
                {
                    "name": tool["name"],
                    "operation_id": tool["operation_id"],
                    "service_actor_id": tool["service_actor_id"],
                    "service_actor_role": tool["service_actor_role"],
                    "description": tool["description"],
                    "input_schema": tool["input_schema"],
                    "output_schema": tool["output_schema"],
                }
                for tool in tools
            ],
        }
        tool_path = f"envs/tools/{resolved_name}.py"
        metadata_path = f"envs/metadata/{resolved_name}_metadata.json"
        config = {"mcpServers": {resolved_name: {"tool_path": tool_path, "stateless": False}}}
        _write_json(datalox_dir / "projection.json", projection)
        _write_json(temporary / metadata_path, metadata)
        _write_json(temporary / "configs" / "mcp_server.fragment.json", config)
        generated_tool_path = temporary / tool_path
        generated_tool_path.parent.mkdir(parents=True, exist_ok=True)
        generated_tool_path.write_text(
            _server_source(server_name=resolved_name, template_ids=tuple(templates)),
            encoding="utf-8",
        )
        patch_dir = temporary / "patches"
        patch_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            Path(__file__).with_name(_ENVFACTORY_PATCH_NAME), patch_dir / _ENVFACTORY_PATCH_NAME
        )
        (temporary / "install.py").write_text(_INSTALLER_SOURCE, encoding="utf-8")
        (temporary / "README.md").write_text(
            _readme(
                provider_id=provider_id,
                server_name=resolved_name,
                tool_count=len(tools),
                template_count=len(templates),
            ),
            encoding="utf-8",
        )
        _remove_python_caches(temporary)
        manifest = {
            "schema_version": ENVFACTORY_PROJECTION_SCHEMA_VERSION,
            "provider_id": provider_id,
            "server_name": resolved_name,
            "tool_count": len(tools),
            "source_world_id": source.manifest.world_id,
            "source_episode_id": episode_id,
            "source_trajectory_sha256": sha256(trajectory_path),
            "envfactory_compatibility_commit": ENVFACTORY_COMPATIBILITY_COMMIT,
            "tool_path": tool_path,
            "metadata_path": metadata_path,
            "scenario_template_count": len(templates),
            "files": {
                path.relative_to(temporary).as_posix(): sha256(path)
                for path in sorted(temporary.rglob("*"))
                if path.is_file() and path.name != "manifest.json"
            },
        }
        _write_json(temporary / "manifest.json", manifest)
    return {**manifest, "out_dir": str(output_dir.resolve())}


def create_envfactory_server(projection_dir: Path) -> FastMCP:
    root = projection_dir.resolve(strict=True)
    projection = _read_object(root / "projection.json")
    if projection.get("schema_version") != ENVFACTORY_PROJECTION_SCHEMA_VERSION:
        raise EnvFactoryProjectionError(
            "envfactory.projection_version_unsupported",
            "Unsupported EnvFactory projection schema version.",
        )
    runtime = _ProjectionRuntime(root, projection)
    atexit.register(runtime.cleanup)
    server = FastMCP(name=projection["server_name"])

    def load_scenario(scenario: dict) -> str:
        try:
            runtime.load_scenario(deepcopy(scenario))
        except EnvFactoryProjectionError as error:
            raise _json_error(error) from error
        except Exception as error:
            raise _json_error(
                EnvFactoryProjectionError(
                    "envfactory.load_failed",
                    "Loading the provider scenario failed.",
                    {"detail": str(error)},
                )
            ) from error
        return "Successfully loaded scenario"

    def save_scenario() -> dict[str, Any]:
        try:
            return runtime.save_scenario()
        except EnvFactoryProjectionError as error:
            raise _json_error(error) from error

    server.tool(description="Load one resettable Datalox provider scenario.")(load_scenario)
    server.tool(description="Save the current Datalox provider scenario.")(save_scenario)
    for item in projection["tools"]:
        _register_tool(server, runtime, item)
    server._datalox_projection_runtime = runtime
    return server


def _register_tool(
    server: FastMCP,
    runtime: _ProjectionRuntime,
    item: dict[str, Any],
) -> None:
    name = item["name"]

    def handler(**arguments: Any) -> Any:
        try:
            return runtime.dispatch(name, dict(arguments))
        except EnvFactoryProjectionError as error:
            raise _json_error(error) from error

    handler.__name__ = name
    handler.__doc__ = item["description"]
    arg_model = _build_arg_model(name, item["input_schema"])
    server._tool_manager._tools[name] = Tool(
        fn=handler,
        name=name,
        title=None,
        description=item["description"],
        parameters=deepcopy(item["input_schema"]),
        fn_metadata=FuncMetadata(arg_model=arg_model),
        is_async=False,
        meta={
            "operation_id": item["operation_id"],
            "service_actor_id": item["service_actor_id"],
            "service_actor_role": item["service_actor_role"],
        },
    )


def _build_arg_model(name: str, schema: dict[str, Any]) -> type[_SparseArgModelBase]:
    properties = schema.get("properties", {})
    required = set(schema.get("required", ()))
    fields = {key: (Any, ... if key in required else None) for key in properties}
    return create_model(
        f"{name}_Arguments",
        __base__=_SparseArgModelBase,
        __config__=ConfigDict(extra="forbid"),
        **fields,
    )


def _observe_outputs(
    *,
    source_world_dir: Path,
    trajectory_path: Path,
    episode_id: str,
) -> tuple[dict[str, list[Any]], dict[str, str]]:
    trajectory_payload = _read_object(trajectory_path)
    trajectories = trajectory_payload.get("trajectories")
    if not isinstance(trajectories, list):
        raise EnvFactoryProjectionError(
            "envfactory.trajectory_invalid",
            "Trajectory file must contain a trajectories array.",
        )
    references = [item for item in trajectories if item.get("kind") == "reference"]
    if len(references) != 1 or references[0].get("episode_id") != episode_id:
        raise EnvFactoryProjectionError(
            "envfactory.reference_trajectory_invalid",
            "Exactly one reference trajectory must match the selected episode.",
        )
    root = Path(tempfile.mkdtemp(prefix="datalox-envfactory-observe-"))
    backend: WorldBundleBackend | None = None
    outputs: dict[str, list[Any]] = defaultdict(list)
    actor_ids: dict[str, set[str]] = defaultdict(set)
    try:
        initialize_world_bundle_session(
            source_bundle_dir=source_world_dir,
            run_dir=root / "run",
            episode_id=episode_id,
        )
        backend = WorldBundleBackend(run_dir=root / "run")
        for index, step in enumerate(references[0].get("steps", [])):
            try:
                operation_id = step["tool_name"]
                actor = ActorContext(step["actor_id"], step["actor_role"])
                actor_ids[actor.role].add(actor.actor_id)
                request = backend.request_for_tool(
                    operation_id,
                    step.get("arguments", {}),
                    actor=actor,
                )
                response = backend.handle(request)
            except (KeyError, TypeError, ValueError) as error:
                raise EnvFactoryProjectionError(
                    "envfactory.reference_step_invalid",
                    "Reference trajectory step is invalid.",
                    {"step_index": index, "detail": str(error)},
                ) from error
            if response is None or response.status_code >= 400:
                raise EnvFactoryProjectionError(
                    "envfactory.reference_step_failed",
                    "Reference trajectory must produce successful provider responses.",
                    {
                        "step_index": index,
                        "operation_id": operation_id,
                        "status_code": None if response is None else response.status_code,
                    },
                )
            outputs[operation_id].append(deepcopy(response.body))
    finally:
        if backend is not None:
            backend.close()
        shutil.rmtree(root, ignore_errors=True)
    ambiguous = {role: sorted(ids) for role, ids in actor_ids.items() if len(ids) != 1}
    if ambiguous:
        raise EnvFactoryProjectionError(
            "envfactory.scenario_actor_ambiguous",
            "Each projected scenario role must resolve to exactly one service actor id.",
            {"actor_ids_by_role": ambiguous},
        )
    return dict(outputs), {role: next(iter(ids)) for role, ids in actor_ids.items()}


def _project_tool(
    tool: ToolDefinition,
    *,
    safe_name: str,
    outputs: list[Any],
    default_role: str,
    actor_ids_by_role: dict[str, str],
) -> dict[str, Any]:
    role = _service_actor_role(tool, default_role=default_role)
    actor_id = actor_ids_by_role.get(role)
    if actor_id is None:
        raise EnvFactoryProjectionError(
            "envfactory.scenario_actor_missing",
            "Selected invoking role has no observed scenario actor.",
            {"operation_id": tool.id, "actor_role": role},
        )
    output_schema = _infer_schema(outputs)
    validator = Draft202012Validator(output_schema)
    for value in outputs:
        validator.validate(value)
    return {
        "name": safe_name,
        "operation_id": tool.id,
        "service_actor_id": actor_id,
        "service_actor_role": role,
        "description": tool.description,
        "input_schema": deepcopy(dict(tool.input_schema)),
        "output_schema": output_schema,
        "observed_response_count": len(outputs),
    }


def _service_actor_role(tool: ToolDefinition, *, default_role: str) -> str:
    if not tool.invoke_roles:
        raise EnvFactoryProjectionError(
            "envfactory.tool_not_invokable",
            "Projected tools must declare at least one invoking role.",
            {"operation_id": tool.id},
        )
    if default_role in tool.invoke_roles:
        return default_role
    return min(tool.invoke_roles)


def _safe_tool_names(tools: tuple[ToolDefinition, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    occupied = set(_LIFECYCLE_TOOLS)
    for tool in tools:
        base = re.sub(r"[^A-Za-z0-9_]", "_", tool.id)
        if not base or base[0].isdigit():
            base = f"tool_{base}"
        name = base
        if name in occupied:
            suffix = hashlib.sha256(tool.id.encode("utf-8")).hexdigest()[:8]
            name = f"{base}_{suffix}"
        if name in occupied:
            raise EnvFactoryProjectionError(
                "envfactory.tool_name_collision",
                "Could not derive unique EnvFactory tool names.",
                {"operation_id": tool.id},
            )
        occupied.add(name)
        result[tool.id] = name
    return result


def _infer_schema(values: list[Any]) -> dict[str, Any]:
    if not values:
        return {}
    by_type: dict[str, list[Any]] = defaultdict(list)
    for value in values:
        by_type[_json_type(value)].append(value)
    if set(by_type) == {"integer", "number"}:
        return {"type": "number"}
    schemas = [_infer_same_type(kind, by_type[kind]) for kind in sorted(by_type)]
    return schemas[0] if len(schemas) == 1 else {"anyOf": schemas}


def _infer_same_type(kind: str, values: list[Any]) -> dict[str, Any]:
    if kind == "object":
        keys = sorted({key for value in values for key in value})
        properties = {
            key: _infer_schema([value[key] for value in values if key in value]) for key in keys
        }
        required = [key for key in keys if all(key in value for value in values)]
        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": True,
        }
        if required:
            schema["required"] = required
        return schema
    if kind == "array":
        items = [item for value in values for item in value]
        return {"type": "array", "items": _infer_schema(items)}
    return {"type": kind}


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise EnvFactoryProjectionError(
        "envfactory.response_not_json",
        "Observed provider responses must be JSON values.",
        {"python_type": type(value).__name__},
    )


def _validate_checkpoint(value: Any, *, seed: dict[str, Any]) -> None:
    errors = sorted(_CHECKPOINT_VALIDATOR.iter_errors(value), key=lambda error: list(error.path))
    if errors:
        error = errors[0]
        raise EnvFactoryProjectionError(
            "envfactory.invalid_checkpoint",
            error.message,
            {"path": list(error.path)},
        )
    seed_state = seed.get("state", seed.get("initial_state"))
    if not isinstance(seed_state, dict):
        raise EnvFactoryProjectionError(
            "envfactory.seed_invalid",
            "Provider runtime seed does not contain object state.",
        )
    actual_keys = set(value["state"])
    expected_keys = set(seed_state)
    if actual_keys != expected_keys:
        raise EnvFactoryProjectionError(
            "envfactory.invalid_state_shape",
            "Scenario state views must exactly match the provider runtime seed.",
            {
                "missing_state_views": sorted(expected_keys - actual_keys),
                "extra_state_views": sorted(actual_keys - expected_keys),
            },
        )
    try:
        json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise EnvFactoryProjectionError(
            "envfactory.invalid_json",
            "Scenario must contain canonical JSON values.",
            {"detail": str(error)},
        ) from error


def _checkpoint_from_seed(seed: dict[str, Any]) -> dict[str, Any]:
    state = seed.get("state", seed.get("initial_state"))
    metadata = seed.get("metadata", {})
    checkpoint = {
        "id": seed.get("id"),
        "metadata": {"clock": metadata.get("clock")},
        "state": deepcopy(state),
    }
    _validate_checkpoint(checkpoint, seed=seed)
    return checkpoint


def _scenario_templates(
    seed: dict[str, Any],
    supplied: Mapping[str, Path] | None,
) -> dict[str, dict[str, Any]]:
    templates = {"baseline": _checkpoint_from_seed(seed)}
    for template_id, path in sorted((supplied or {}).items()):
        _validate_template_id(template_id)
        if template_id == "baseline":
            raise EnvFactoryProjectionError(
                "envfactory.template_reserved",
                "The baseline scenario template is generated from the selected provider seed.",
            )
        checkpoint = _read_object(path.resolve(strict=True))
        _validate_checkpoint(checkpoint, seed=seed)
        templates[template_id] = checkpoint
    return templates


def _validate_envfactory_scenario(value: Any, *, projection: dict[str, Any]) -> None:
    if not isinstance(value, dict):
        raise EnvFactoryProjectionError(
            "envfactory.invalid_scenario",
            "EnvFactory scenario must be an object.",
        )
    required = {"schema_version", "template_id", "seed", "checkpoint"}
    if set(value) != required:
        raise EnvFactoryProjectionError(
            "envfactory.invalid_scenario",
            "EnvFactory scenario fields must exactly match the exported scenario contract.",
            {
                "missing_fields": sorted(required - set(value)),
                "extra_fields": sorted(set(value) - required),
            },
        )
    if value["schema_version"] != ENVFACTORY_SCENARIO_SCHEMA_VERSION:
        raise EnvFactoryProjectionError(
            "envfactory.invalid_scenario_version",
            "EnvFactory scenario schema version is unsupported.",
        )
    templates = projection.get("scenario_templates", {})
    if value["template_id"] not in templates:
        raise EnvFactoryProjectionError(
            "envfactory.template_unknown",
            "Scenario template is not included in this projection.",
            {"template_id": value["template_id"], "allowed": sorted(templates)},
        )
    if value["seed"] != 0:
        raise EnvFactoryProjectionError(
            "envfactory.seed_unsupported",
            "This projection exposes one deterministic seed per scenario template.",
        )
    checkpoint = value["checkpoint"]
    if checkpoint is not None and not isinstance(checkpoint, dict):
        raise EnvFactoryProjectionError(
            "envfactory.invalid_checkpoint",
            "Scenario checkpoint must be null or an object.",
        )
    try:
        json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise EnvFactoryProjectionError(
            "envfactory.invalid_json",
            "Scenario must contain canonical JSON values.",
            {"detail": str(error)},
        ) from error


def _server_name(provider_id: str) -> str:
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", provider_id) if part]
    if not parts:
        raise EnvFactoryProjectionError(
            "envfactory.provider_id_invalid",
            "Provider id cannot produce an EnvFactory server name.",
        )
    return "Datalox" + "".join(part[:1].upper() + part[1:] for part in parts)


def _validated_server_name(value: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
        raise EnvFactoryProjectionError(
            "envfactory.server_name_invalid",
            "EnvFactory server name must be a valid Python identifier.",
            {"server_name": value},
        )
    return value


def _validate_template_id(value: str) -> None:
    if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) is None:
        raise EnvFactoryProjectionError(
            "envfactory.template_id_invalid",
            "Scenario template id must match [a-z][a-z0-9_]{0,63}.",
            {"template_id": value},
        )


def _json_error(error: EnvFactoryProjectionError) -> RuntimeError:
    return RuntimeError(json.dumps({"error": error.to_dict()}, sort_keys=True))


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EnvFactoryProjectionError(
            "envfactory.json_invalid",
            f"Could not read JSON object: {path}",
            {"detail": str(error)},
        ) from error
    if not isinstance(value, dict):
        raise EnvFactoryProjectionError(
            "envfactory.json_invalid",
            f"JSON file must contain an object: {path}",
        )
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _remove_python_caches(root: Path) -> None:
    for cache in root.rglob("__pycache__"):
        shutil.rmtree(cache)


def _server_source(*, server_name: str, template_ids: tuple[str, ...]) -> str:
    literal_values = ", ".join(repr(value) for value in template_ids)
    return f'''from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from datalox_gated_runtime.harness_adapters.envfactory import create_envfactory_server


class DataloxScenarioMetadata(BaseModel):
    """Clock metadata stored in a provider-state checkpoint."""

    model_config = ConfigDict(extra="forbid")

    clock: str = Field(description="ISO 8601 simulation clock for the checkpoint.")


class DataloxCheckpoint(BaseModel):
    """A complete provider-state checkpoint returned by save_scenario."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, description="Provider episode identifier.")
    metadata: DataloxScenarioMetadata
    state: dict[str, Any] = Field(description="Complete resettable provider state views.")


class DataloxScenario(BaseModel):
    """Select a bundled state template or continue from a saved checkpoint."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["{ENVFACTORY_SCENARIO_SCHEMA_VERSION}"] = (
        "{ENVFACTORY_SCENARIO_SCHEMA_VERSION}"
    )
    template_id: Literal[{literal_values}] = Field(
        description="Bundled provider-state template to materialize."
    )
    seed: Literal[0] = Field(default=0, description="Only the deterministic exported seed exists.")
    checkpoint: DataloxCheckpoint | None = Field(
        default=None,
        description=(
            "Use null when generating a fresh scenario. Only reuse a checkpoint object "
            "returned by save_scenario."
        ),
    )


Scenario_Schema = [DataloxScenarioMetadata, DataloxCheckpoint, DataloxScenario]

_PROJECTION_DIR = Path(__file__).resolve().parents[1] / "datalox" / "{server_name}"
mcp = create_envfactory_server(_PROJECTION_DIR)


if __name__ == "__main__":
    mcp.run()
'''


def _readme(
    *,
    provider_id: str,
    server_name: str,
    tool_count: int,
    template_count: int,
) -> str:
    return f"""# {server_name}

This overlay adds a task-free Datalox provider runtime for `{provider_id}` to
EnvFactory. It exposes {tool_count} provider operations, {template_count}
resettable state template(s), and EnvFactory's `load_scenario` and
`save_scenario` lifecycle.

## Install

Install `datalox-gated-runtime` in EnvFactory's Python environment, then run:

```bash
python install.py /path/to/EnvFactory
```

The installer requires EnvFactory commit `{ENVFACTORY_COMPATIBILITY_COMMIT}`. It
copies the native `envs/tools`, `envs/metadata`, and `envs/datalox` files,
registers `{server_name}` in `configs/mcp_server.json`, and applies the included
compatibility patch. It refuses incompatible commits, overwrites, and config
collisions.

The patch gives every stateful EnvFactory client its own stdio process for
pass@k isolation and teaches ToolGraph to retain root array, primitive, and
union outputs. It is version-pinned because it changes EnvFactory internals.

## Data boundary

The metadata preserves original response shapes. Output schemas are inferred
from successful reference behavior and describe observed shapes only. The
provider runtime contains no task, verifier, reward, credential, or live-provider
client. EnvFactory owns task and trajectory generation; Datalox supplies the
resettable provider behavior substrate.

`DataloxScenario` selects a bundled template. `save_scenario` emits a complete
checkpoint only after state changes, so a later long-horizon step can reload the
exact state. The exported seed is deterministic; the adapter does not invent
unsupported scenario diversity.
"""


_INSTALLER_SOURCE = r"""from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path


EXPECTED_COMMIT = "eff3b22d3fc26afa14165cfe208c2a4c9ecc39e3"


def run(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Install one Datalox provider overlay.")
    parser.add_argument("envfactory_root")
    args = parser.parse_args()
    overlay = Path(__file__).resolve().parent
    target = Path(args.envfactory_root).resolve(strict=True)

    commit = run("git", "rev-parse", "HEAD", cwd=target).stdout.strip()
    if commit != EXPECTED_COMMIT:
        raise SystemExit(f"EnvFactory commit must be {EXPECTED_COMMIT}; found {commit}.")

    fragment = json.loads(
        (overlay / "configs" / "mcp_server.fragment.json").read_text(encoding="utf-8")
    )
    config_path = target / "configs" / "mcp_server.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    additions = fragment["mcpServers"]
    collisions = sorted(set(additions) & set(config.get("mcpServers", {})))
    if collisions:
        raise SystemExit(f"MCP server already registered: {', '.join(collisions)}")

    sources = [path for path in (overlay / "envs").rglob("*") if path.is_file()]
    destinations = [(path, target / path.relative_to(overlay)) for path in sources]
    existing = [str(destination) for _, destination in destinations if destination.exists()]
    if existing:
        raise SystemExit("Refusing to overwrite existing files:\n" + "\n".join(existing))

    patch = next((overlay / "patches").glob("envfactory-*.patch"))
    can_apply = run("git", "apply", "--check", str(patch), cwd=target, check=False)
    if can_apply.returncode == 0:
        run("git", "apply", str(patch), cwd=target)
    else:
        already_applied = run(
            "git", "apply", "--reverse", "--check", str(patch), cwd=target, check=False
        )
        if already_applied.returncode != 0:
            raise SystemExit("EnvFactory compatibility patch cannot be applied cleanly.")

    for source, destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    config.setdefault("mcpServers", {}).update(additions)
    temporary = config_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(config, indent=4) + "\n", encoding="utf-8")
    temporary.replace(config_path)
    print(f"Installed: {', '.join(sorted(additions))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""
