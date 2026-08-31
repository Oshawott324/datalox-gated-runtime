"""Task-free, content-addressed provider runtime bundles."""

from __future__ import annotations

import hashlib
import json
import shutil
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.data_plane import normalize_authority
from datalox_gated_runtime.models import GateConfig
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.provider_runtime.identity import (
    FixedIdentityPolicy,
    IdentityPolicy,
    load_identity_policy,
)
from datalox_gated_runtime.world_v1.backend import world_runtime_files
from datalox_gated_runtime.world_v1.bundle import (
    ValidatedWorldBundle,
    WorldBundleManifest,
    instantiate_validated_world_bundle,
    validate_world_bundle,
)
from datalox_gated_runtime.world_v1.contracts import RoleDefinition, ToolDefinition

PROVIDER_RUNTIME_SCHEMA_VERSION = "datalox_provider_runtime_v2"
PROVIDER_RUNTIME_MANIFEST = "provider-runtime.json"
FORBIDDEN_RUNTIME_NAMES = frozenset(
    {"task.json", "episodes.jsonl", "verifier.json", "reward.json", "rewards.json"}
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "provider_id",
        "bundle_version",
        "authorities",
        "wire_protocol",
        "behavior",
        "source_path",
        "content_hashes",
    }
)
_WORLD_BEHAVIOR_FIELDS = frozenset(
    {
        "protocol",
        "implementation",
        "seed_path",
        "roles_path",
        "tools_path",
        "identity_path",
        "default_actor_role",
        "required_runtime_capabilities",
    }
)
_GATE_CONFIG_BEHAVIOR_FIELDS = frozenset({"protocol", "config_path"})


@dataclass(frozen=True)
class WorldV1BehaviorSpec:
    protocol: str
    implementation: str
    seed_path: str
    roles_path: str
    tools_path: str
    identity_path: str
    default_actor_role: str
    required_runtime_capabilities: tuple[str, ...]


@dataclass(frozen=True)
class GateConfigBehaviorSpec:
    protocol: str
    config_path: str


ProviderBehaviorSpec = WorldV1BehaviorSpec | GateConfigBehaviorSpec


@dataclass(frozen=True)
class ProviderRuntimeManifest:
    schema_version: str
    provider_id: str
    bundle_version: str
    authorities: tuple[str, ...]
    wire_protocol: str
    behavior: ProviderBehaviorSpec
    source_path: str
    content_hashes: dict[str, str]


@dataclass(frozen=True)
class LoadedProviderRuntimeBundle:
    root: Path
    manifest: ProviderRuntimeManifest
    seed: dict[str, Any] | None
    roles: tuple[RoleDefinition, ...]
    tools: tuple[ToolDefinition, ...]
    identity_policy: IdentityPolicy | None
    implementation: Any | None
    gate_config: GateConfig | None
    source: dict[str, Any]


class WorldProviderBehaviorAdapter:
    """Expose only provider behavior from a legacy world implementation."""

    def __init__(self, implementation: Any) -> None:
        self._implementation = implementation

    def initialize_episode(self, *, session: Any, episode: dict[str, Any]) -> Any:
        return self._implementation.initialize_episode(session=session, episode=episode)

    def tool_for_request(self, request: Any) -> Any:
        return self._implementation.tool_for_request(request)

    def request_for_tool(self, tool_name: str, arguments: Any, *, actor: Any) -> Any:
        return self._implementation.request_for_tool(tool_name, arguments, actor=actor)

    def operation_for_tool(self, tool_name: str) -> Any:
        return self._implementation.operation_for_tool(tool_name)

    def handle(self, request: Any, *, actor: Any, session: Any) -> Any:
        return self._implementation.handle(request, actor=actor, session=session)


def build_provider_runtime_from_world(
    *,
    source_world_dir: Path,
    output_dir: Path,
    provider_id: str,
    authorities: tuple[str, ...],
    episode_id: str,
    identity_policy_path: Path | None = None,
) -> Path:
    """Compile existing behavior code and one reset seed without task/verifier assets."""

    if output_dir.exists():
        raise ProviderRuntimeError(
            "provider_runtime_output_exists",
            "Provider runtime output directory already exists.",
            {"path": str(output_dir)},
        )
    source = validate_world_bundle(source_world_dir)
    episode = deepcopy(source.episode(episode_id))
    for world_owned_key in ("task", "hidden", "expected"):
        episode.pop(world_owned_key, None)
    state = episode.get("state", episode.get("initial_state"))
    if not isinstance(episode.get("id"), str) or not isinstance(state, dict):
        raise ProviderRuntimeError(
            "provider_runtime_seed_invalid",
            "Selected world episode does not provide an id and object reset state.",
        )

    canonical_authorities = _authorities(authorities)
    output_dir.mkdir(parents=True)
    runtime_root = output_dir / "runtime"
    for source_file in world_runtime_files(source):
        relative = source_file.relative_to(source.root)
        destination = runtime_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, destination)

    _write_json(output_dir / "seed.json", episode)
    _write_json(
        output_dir / "roles.json",
        {"roles": [{"id": role.id, "description": role.description} for role in source.roles]},
    )
    _write_json(
        output_dir / "tools.json",
        {
            "tools": [
                {
                    "id": tool.id,
                    "description": tool.description,
                    "list_roles": sorted(tool.list_roles),
                    "invoke_roles": sorted(tool.invoke_roles),
                    "input_schema": dict(tool.input_schema),
                    "source_refs": list(tool.source_refs),
                    "operation_family": tool.operation_family,
                }
                for tool in source.tools
            ]
        },
    )
    if identity_policy_path is None:
        identity_policy: IdentityPolicy = FixedIdentityPolicy(
            actor_id="agent",
            actor_role=source.manifest.default_actor_role,
        )
    else:
        identity_policy = load_identity_policy(
            _load_json(identity_policy_path),
            declared_roles=frozenset(role.id for role in source.roles),
        )
    _write_json(output_dir / "identity.json", identity_policy.to_dict())
    source_manifest_path = source.root / "world" / "manifest.json"
    _write_json(
        output_dir / "source.json",
        {
            "schema_version": "datalox_provider_runtime_source_v1",
            "source_world_id": source.manifest.world_id,
            "source_bundle_version": source.manifest.bundle_version,
            "source_episode_id": episode_id,
            "source_manifest_sha256": _sha256(source_manifest_path),
            "source_declaration": _load_json(source.root / source.manifest.sources_path),
        },
    )

    implementation_path, factory = source.manifest.implementation.split(":", 1)
    hashes = compute_provider_runtime_hashes(output_dir)
    manifest = {
        "schema_version": PROVIDER_RUNTIME_SCHEMA_VERSION,
        "provider_id": _identifier(provider_id, "provider_id"),
        "bundle_version": source.manifest.bundle_version,
        "authorities": list(canonical_authorities),
        "wire_protocol": "standard_http_v1",
        "behavior": {
            "protocol": "world_v1_adapter",
            "implementation": f"runtime/{implementation_path}:{factory}",
            "seed_path": "seed.json",
            "roles_path": "roles.json",
            "tools_path": "tools.json",
            "identity_path": "identity.json",
            "default_actor_role": source.manifest.default_actor_role,
            "required_runtime_capabilities": list(source.manifest.required_runtime_capabilities),
        },
        "source_path": "source.json",
        "content_hashes": hashes,
    }
    _write_json(output_dir / PROVIDER_RUNTIME_MANIFEST, manifest)
    load_provider_runtime_bundle(output_dir)
    return output_dir / PROVIDER_RUNTIME_MANIFEST


def build_provider_runtime_from_gate_config(
    *,
    source_gate_config: Path,
    output_dir: Path,
    provider_id: str,
    authorities: tuple[str, ...],
    bundle_version: str = "1.0.0",
) -> Path:
    """Compile a task-free replay/deny/shadow provider runtime from a gate config."""

    if output_dir.exists():
        raise ProviderRuntimeError(
            "provider_runtime_output_exists",
            "Provider runtime output directory already exists.",
            {"path": str(output_dir)},
        )
    config = load_gate_config(source_gate_config)
    if config.world is not None or config.mcp is not None:
        raise ProviderRuntimeError(
            "provider_runtime_config_unsupported",
            "Gate-config provider compilation accepts HTTP endpoint assets without a world or MCP surface.",
        )
    raw = _require_object(_load_json(source_gate_config), source_gate_config.name)
    policy = deepcopy(raw.get("policy", {"deny": [], "shadow_write": [], "live_capture": []}))
    if not isinstance(policy, dict):
        raise ProviderRuntimeError(
            "provider_runtime_config_invalid", "Gate config policy must be an object."
        )
    policy["live_capture"] = []
    runtime_config = {
        "config_id": config.config_id,
        "response_cases": deepcopy(raw.get("response_cases", [])),
        "audit_rules": [],
        "metadata": deepcopy(config.metadata),
        "policy": policy,
    }
    output_dir.mkdir(parents=True)
    _write_json(output_dir / "gate-config.json", runtime_config)
    _write_json(
        output_dir / "source.json",
        {
            "schema_version": "datalox_provider_runtime_source_v1",
            "source_kind": "gate_config",
            "source_config_id": config.config_id,
            "source_gate_config_sha256": _sha256(source_gate_config),
            "source_metadata": deepcopy(config.metadata),
        },
    )
    manifest = {
        "schema_version": PROVIDER_RUNTIME_SCHEMA_VERSION,
        "provider_id": _identifier(provider_id, "provider_id"),
        "bundle_version": _identifier(bundle_version, "bundle_version", allow_dot=True),
        "authorities": list(_authorities(authorities)),
        "wire_protocol": "standard_http_v1",
        "behavior": {"protocol": "gate_config_v1", "config_path": "gate-config.json"},
        "source_path": "source.json",
        "content_hashes": compute_provider_runtime_hashes(output_dir),
    }
    _write_json(output_dir / PROVIDER_RUNTIME_MANIFEST, manifest)
    load_provider_runtime_bundle(output_dir)
    return output_dir / PROVIDER_RUNTIME_MANIFEST


def load_provider_runtime_bundle(bundle_dir: Path) -> LoadedProviderRuntimeBundle:
    root = bundle_dir.resolve(strict=True)
    raw = _load_json(root / PROVIDER_RUNTIME_MANIFEST)
    if not isinstance(raw, dict):
        raise ProviderRuntimeError(
            "provider_runtime_manifest_invalid", "Provider runtime manifest must be an object."
        )
    if set(raw) != _MANIFEST_FIELDS:
        raise ProviderRuntimeError(
            "provider_runtime_manifest_invalid",
            "Provider runtime manifest fields do not match the v2 contract.",
            {
                "missing": sorted(_MANIFEST_FIELDS - set(raw)),
                "unknown": sorted(set(raw) - _MANIFEST_FIELDS),
            },
        )
    if raw["schema_version"] != PROVIDER_RUNTIME_SCHEMA_VERSION:
        raise ProviderRuntimeError(
            "provider_runtime_schema_unsupported", "Unsupported provider runtime schema."
        )
    behavior = _behavior(raw["behavior"])
    if raw["wire_protocol"] != "standard_http_v1":
        raise ProviderRuntimeError(
            "provider_runtime_wire_protocol_unsupported",
            "Unsupported provider wire protocol.",
        )
    manifest = ProviderRuntimeManifest(
        schema_version=raw["schema_version"],
        provider_id=_identifier(raw["provider_id"], "provider_id"),
        bundle_version=_identifier(raw["bundle_version"], "bundle_version", allow_dot=True),
        authorities=_authorities(raw["authorities"]),
        wire_protocol=raw["wire_protocol"],
        behavior=behavior,
        source_path=_relative_path(raw["source_path"]),
        content_hashes=_hashes(raw["content_hashes"]),
    )
    _validate_file_set(root, manifest)
    source = _require_object(_load_json(root / manifest.source_path), manifest.source_path)
    seed: dict[str, Any] | None = None
    roles: tuple[RoleDefinition, ...] = ()
    tools: tuple[ToolDefinition, ...] = ()
    implementation: Any | None = None
    gate_config: GateConfig | None = None
    identity_policy: IdentityPolicy | None = None
    if isinstance(behavior, WorldV1BehaviorSpec):
        seed = _require_object(_load_json(root / behavior.seed_path), behavior.seed_path)
        roles = _roles(_load_json(root / behavior.roles_path))
        tools = _tools(_load_json(root / behavior.tools_path), roles)
        if behavior.default_actor_role not in {role.id for role in roles}:
            raise ProviderRuntimeError(
                "provider_runtime_role_invalid", "default_actor_role is not declared."
            )
        identity_policy = load_identity_policy(
            _load_json(root / behavior.identity_path),
            declared_roles=frozenset(role.id for role in roles),
        )
        implementation = _instantiate_world_adapter(root, manifest, seed, roles, tools)
    else:
        gate_config = _load_runtime_gate_config(root / behavior.config_path)
    return LoadedProviderRuntimeBundle(
        root=root,
        manifest=manifest,
        seed=seed,
        roles=roles,
        tools=tools,
        identity_policy=identity_policy,
        implementation=implementation,
        gate_config=gate_config,
        source=source,
    )


def compute_provider_runtime_hashes(bundle_dir: Path) -> dict[str, str]:
    root = bundle_dir.resolve(strict=True)
    return {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and path.name != PROVIDER_RUNTIME_MANIFEST
        and "__pycache__" not in path.parts
    }


def _instantiate_world_adapter(
    root: Path,
    manifest: ProviderRuntimeManifest,
    seed: dict[str, Any],
    roles: tuple[RoleDefinition, ...],
    tools: tuple[ToolDefinition, ...],
) -> Any:
    behavior = manifest.behavior
    if not isinstance(behavior, WorldV1BehaviorSpec):
        raise TypeError("world adapter requires WorldV1BehaviorSpec")
    fake_manifest = WorldBundleManifest(
        schema_version="datalox_world_bundle_v1",
        world_id=manifest.provider_id,
        bundle_version=manifest.bundle_version,
        implementation=behavior.implementation,
        episodes_path=behavior.seed_path,
        roles_path=behavior.roles_path,
        tools_path=behavior.tools_path,
        verifier_path="runtime:not_present",
        sources_path=manifest.source_path,
        default_actor_role=behavior.default_actor_role,
        required_runtime_capabilities=behavior.required_runtime_capabilities,
        trajectory_paths=(),
        content_hashes=manifest.content_hashes,
    )
    validated = ValidatedWorldBundle(
        root=root,
        manifest=fake_manifest,
        roles=roles,
        tools=tools,
        episodes=(seed,),
        sources=(),
        grounding_gaps=(),
    )
    implementation = instantiate_validated_world_bundle(validated).implementation
    return WorldProviderBehaviorAdapter(implementation)


def _load_runtime_gate_config(path: Path) -> GateConfig:
    try:
        config = load_gate_config(path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProviderRuntimeError(
            "provider_runtime_config_invalid", f"Runtime gate config is invalid: {exc}."
        ) from exc
    if (
        config.world is not None
        or config.mcp is not None
        or config.live is not None
        or config.auth_profiles.profiles
        or config.audit_rules
        or (config.policy is not None and config.policy.live_capture)
    ):
        raise ProviderRuntimeError(
            "provider_runtime_config_unsafe",
            "Runtime gate config must not contain world, MCP, auth, audit, or live-provider surfaces.",
        )
    return config


def _validate_file_set(root: Path, manifest: ProviderRuntimeManifest) -> None:
    if any(path.is_symlink() for path in root.rglob("*")):
        raise ProviderRuntimeError(
            "provider_runtime_symlink_forbidden",
            "Provider runtime bundles must not contain symbolic links.",
        )
    actual = set(compute_provider_runtime_hashes(root))
    declared = set(manifest.content_hashes)
    if actual != declared:
        raise ProviderRuntimeError(
            "provider_runtime_file_set_mismatch",
            "Provider runtime files do not match its content hashes.",
            {"missing": sorted(declared - actual), "extra": sorted(actual - declared)},
        )
    for relative, expected in manifest.content_hashes.items():
        path = root / _relative_path(relative)
        if path.name in FORBIDDEN_RUNTIME_NAMES:
            raise ProviderRuntimeError(
                "provider_runtime_world_asset_forbidden",
                f"Provider runtime must not contain {path.name}.",
            )
        actual_digest = _sha256(path)
        if actual_digest != expected:
            raise ProviderRuntimeError(
                "provider_runtime_hash_mismatch",
                f"Content hash mismatch for {relative}.",
            )


def _behavior(raw: Any) -> ProviderBehaviorSpec:
    if not isinstance(raw, dict):
        raise ProviderRuntimeError(
            "provider_runtime_behavior_invalid", "behavior must be an object."
        )
    protocol = raw.get("protocol")
    if protocol == "world_v1_adapter":
        if set(raw) != _WORLD_BEHAVIOR_FIELDS:
            raise ProviderRuntimeError(
                "provider_runtime_behavior_invalid",
                "world_v1_adapter behavior fields do not match the provider runtime contract.",
            )
        return WorldV1BehaviorSpec(
            protocol=protocol,
            implementation=_relative_entrypoint(raw["implementation"]),
            seed_path=_relative_path(raw["seed_path"]),
            roles_path=_relative_path(raw["roles_path"]),
            tools_path=_relative_path(raw["tools_path"]),
            identity_path=_relative_path(raw["identity_path"]),
            default_actor_role=_identifier(raw["default_actor_role"], "default_actor_role"),
            required_runtime_capabilities=_string_tuple(
                raw["required_runtime_capabilities"], "required_runtime_capabilities"
            ),
        )
    if protocol == "gate_config_v1":
        if set(raw) != _GATE_CONFIG_BEHAVIOR_FIELDS:
            raise ProviderRuntimeError(
                "provider_runtime_behavior_invalid",
                "gate_config_v1 behavior fields do not match the provider runtime contract.",
            )
        return GateConfigBehaviorSpec(
            protocol=protocol,
            config_path=_relative_path(raw["config_path"]),
        )
    raise ProviderRuntimeError(
        "provider_runtime_protocol_unsupported", "Unsupported provider behavior protocol."
    )


def _roles(raw: Any) -> tuple[RoleDefinition, ...]:
    if not isinstance(raw, dict) or set(raw) != {"roles"} or not isinstance(raw["roles"], list):
        raise ProviderRuntimeError("provider_runtime_roles_invalid", "roles.json is invalid.")
    try:
        roles = tuple(RoleDefinition(**item) for item in raw["roles"])
    except (TypeError, ValueError) as exc:
        raise ProviderRuntimeError(
            "provider_runtime_roles_invalid", f"roles.json is invalid: {exc}."
        ) from exc
    if not roles or len({role.id for role in roles}) != len(roles):
        raise ProviderRuntimeError(
            "provider_runtime_roles_invalid", "roles.json must declare unique roles."
        )
    return roles


def _tools(raw: Any, roles: tuple[RoleDefinition, ...]) -> tuple[ToolDefinition, ...]:
    if not isinstance(raw, dict) or set(raw) != {"tools"} or not isinstance(raw["tools"], list):
        raise ProviderRuntimeError("provider_runtime_tools_invalid", "tools.json is invalid.")
    role_ids = {role.id for role in roles}
    tools: list[ToolDefinition] = []
    try:
        for item in raw["tools"]:
            tools.append(
                ToolDefinition(
                    id=item["id"],
                    description=item["description"],
                    list_roles=frozenset(item["list_roles"]),
                    invoke_roles=frozenset(item["invoke_roles"]),
                    input_schema=item["input_schema"],
                    source_refs=tuple(item.get("source_refs", [])),
                    operation_family=item.get("operation_family"),
                )
            )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProviderRuntimeError(
            "provider_runtime_tools_invalid", f"tools.json is invalid: {exc}."
        ) from exc
    if len({tool.id for tool in tools}) != len(tools) or any(
        (tool.list_roles | tool.invoke_roles) - role_ids for tool in tools
    ):
        raise ProviderRuntimeError(
            "provider_runtime_tools_invalid", "tools.json has duplicate tools or unknown roles."
        )
    return tuple(tools)


def _authorities(raw: Any) -> tuple[str, ...]:
    if (
        not isinstance(raw, (list, tuple))
        or not raw
        or any(not isinstance(item, str) for item in raw)
    ):
        raise ProviderRuntimeError(
            "provider_runtime_authorities_invalid", "authorities must be a non-empty string list."
        )
    normalized = tuple(normalize_authority(item, scheme="https") for item in raw)
    if len(set(normalized)) != len(normalized):
        raise ProviderRuntimeError(
            "provider_runtime_authorities_invalid", "authorities must be unique."
        )
    return normalized


def _identifier(value: Any, field: str, *, allow_dot: bool = False) -> str:
    allowed = "_-" + ("." if allow_dot else "")
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or not value[0].isalnum()
        or any(not (char.isalnum() or char in allowed) for char in value)
    ):
        raise ProviderRuntimeError(
            "provider_runtime_manifest_invalid", f"{field} is not a valid identifier."
        )
    return value


def _relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ProviderRuntimeError("provider_runtime_path_invalid", "Bundle path is invalid.")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or parsed.as_posix() != value or ".." in parsed.parts:
        raise ProviderRuntimeError("provider_runtime_path_invalid", "Bundle path is invalid.")
    return value


def _relative_entrypoint(value: Any) -> str:
    if not isinstance(value, str) or value.count(":") != 1:
        raise ProviderRuntimeError(
            "provider_runtime_entrypoint_invalid", "implementation entrypoint is invalid."
        )
    path, factory = value.split(":", 1)
    _relative_path(path)
    if not path.endswith(".py") or not factory.isidentifier():
        raise ProviderRuntimeError(
            "provider_runtime_entrypoint_invalid", "implementation entrypoint is invalid."
        )
    return value


def _string_tuple(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ProviderRuntimeError(
            "provider_runtime_manifest_invalid", f"{field} must be a string list."
        )
    if len(set(value)) != len(value):
        raise ProviderRuntimeError("provider_runtime_manifest_invalid", f"{field} must be unique.")
    return tuple(value)


def _hashes(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or any(
        not isinstance(path, str)
        or not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != 71
        or any(character not in "0123456789abcdef" for character in digest[7:])
        for path, digest in value.items()
    ):
        raise ProviderRuntimeError("provider_runtime_hashes_invalid", "content_hashes is invalid.")
    return dict(value)


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderRuntimeError(
            "provider_runtime_json_invalid", f"{path} must contain an object."
        )
    return value


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderRuntimeError(
            "provider_runtime_json_invalid", f"Could not load {path.name}: {exc}."
        ) from exc


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"
