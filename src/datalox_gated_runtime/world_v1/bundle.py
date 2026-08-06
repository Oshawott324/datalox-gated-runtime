from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
import types
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from datalox_gated_runtime.world_v1.contracts import (
    RoleDefinition,
    ToolCatalog,
    ToolDefinition,
    WorldImplementationV1,
)
from datalox_gated_runtime.world_v1.errors import WorldBundleError

WORLD_BUNDLE_SCHEMA_VERSION = "datalox_world_bundle_v1"
SUPPORTED_RUNTIME_CAPABILITIES = frozenset(
    {
        "actors",
        "mcp_response_body_sha256",
        "role_scoped_tools",
        "transactions",
        "artifacts",
        "clock",
        "scheduled_events",
        "conversations",
        "handoffs",
    }
)

_MANIFEST_RELATIVE_PATH = "world/manifest.json"
_GENERATED_FILES = frozenset({"world_admission.json"})
_WORLD_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "world_id",
        "bundle_version",
        "implementation",
        "episodes_path",
        "roles_path",
        "tools_path",
        "verifier_path",
        "sources_path",
        "default_actor_role",
        "required_runtime_capabilities",
        "trajectory_paths",
        "content_hashes",
    }
)
_MANIFEST_REQUIRED_FIELDS = _MANIFEST_FIELDS - {"trajectory_paths"}


@dataclass(frozen=True)
class WorldBundleManifest:
    schema_version: str
    world_id: str
    bundle_version: str
    implementation: str
    episodes_path: str
    roles_path: str
    tools_path: str
    verifier_path: str
    sources_path: str
    default_actor_role: str
    required_runtime_capabilities: tuple[str, ...]
    content_hashes: dict[str, str]
    trajectory_paths: tuple[str, ...] = ()

    def referenced_paths(self) -> tuple[str, ...]:
        implementation_path, _ = split_implementation_entrypoint(self.implementation)
        return (
            implementation_path,
            self.episodes_path,
            self.roles_path,
            self.tools_path,
            self.verifier_path,
            self.sources_path,
            *self.trajectory_paths,
        )


@dataclass(frozen=True)
class ValidatedWorldBundle:
    root: Path
    manifest: WorldBundleManifest
    roles: tuple[RoleDefinition, ...]
    tools: tuple[ToolDefinition, ...]
    episodes: tuple[dict[str, Any], ...]
    sources: tuple[dict[str, Any], ...]
    grounding_gaps: tuple[dict[str, Any], ...]

    @property
    def tool_catalog(self) -> ToolCatalog:
        return ToolCatalog(roles=self.roles, tools=self.tools)

    def episode(self, episode_id: str) -> dict[str, Any]:
        for episode in self.episodes:
            if episode["id"] == episode_id:
                return episode
        raise WorldBundleError(
            "world_bundle_episode_unknown",
            f"Episode {episode_id!r} is not declared by world {self.manifest.world_id!r}.",
            episode_id=episode_id,
            world_id=self.manifest.world_id,
        )


@dataclass(frozen=True)
class LoadedWorldBundle:
    validated: ValidatedWorldBundle
    implementation: WorldImplementationV1

    @property
    def root(self) -> Path:
        return self.validated.root

    @property
    def manifest(self) -> WorldBundleManifest:
        return self.validated.manifest

    @property
    def roles(self) -> tuple[RoleDefinition, ...]:
        return self.validated.roles

    @property
    def tools(self) -> tuple[ToolDefinition, ...]:
        return self.validated.tools

    @property
    def episodes(self) -> tuple[dict[str, Any], ...]:
        return self.validated.episodes

    @property
    def tool_catalog(self) -> ToolCatalog:
        return self.validated.tool_catalog

    def episode(self, episode_id: str) -> dict[str, Any]:
        return self.validated.episode(episode_id)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WorldBundleError(
                "world_bundle_duplicate_key",
                f"JSON object contains duplicate key {key!r}.",
                key=key,
            )
        result[key] = value
    return result


def _load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_json_keys
        )
    except WorldBundleError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorldBundleError(
            "world_bundle_json_invalid",
            f"Could not parse bundle JSON file {path.name!r}: {exc}.",
            path=str(path),
        ) from exc


def _require_object(value: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorldBundleError(
            "world_bundle_schema_invalid",
            f"{path!r} must contain a JSON object.",
            path=path,
        )
    return value


def _require_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise WorldBundleError(
            "world_bundle_schema_invalid",
            f"Manifest field {field!r} must be a non-empty, trimmed string.",
            field=field,
        )
    return value


def _require_string_list(value: Any, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item or item.strip() != item for item in value
    ):
        raise WorldBundleError(
            "world_bundle_schema_invalid",
            f"Manifest field {field!r} must be a list of non-empty, trimmed strings.",
            field=field,
        )
    if len(set(value)) != len(value):
        raise WorldBundleError(
            "world_bundle_duplicate_id",
            f"Manifest field {field!r} contains a duplicate value.",
            field=field,
        )
    return tuple(value)


def _parse_manifest(data: Any) -> WorldBundleManifest:
    raw = _require_object(data, path=_MANIFEST_RELATIVE_PATH)
    unknown = sorted(raw.keys() - _MANIFEST_FIELDS)
    if unknown:
        raise WorldBundleError(
            "world_bundle_manifest_unknown_field",
            f"World manifest contains unknown fields: {', '.join(unknown)}.",
            fields=unknown,
        )
    missing = sorted(_MANIFEST_REQUIRED_FIELDS - raw.keys())
    if missing:
        raise WorldBundleError(
            "world_bundle_manifest_missing_field",
            f"World manifest is missing fields: {', '.join(missing)}.",
            fields=missing,
        )

    schema_version = _require_string(raw["schema_version"], field="schema_version")
    if schema_version != WORLD_BUNDLE_SCHEMA_VERSION:
        raise WorldBundleError(
            "world_bundle_schema_unsupported",
            f"Unsupported world bundle schema {schema_version!r}.",
            schema_version=schema_version,
            supported_schema_version=WORLD_BUNDLE_SCHEMA_VERSION,
        )

    world_id = _require_string(raw["world_id"], field="world_id")
    if _WORLD_ID_PATTERN.fullmatch(world_id) is None:
        raise WorldBundleError(
            "world_bundle_world_id_invalid",
            "world_id must match ^[a-z][a-z0-9_]*$.",
            world_id=world_id,
        )
    bundle_version = _require_string(raw["bundle_version"], field="bundle_version")
    if _VERSION_PATTERN.fullmatch(bundle_version) is None:
        raise WorldBundleError(
            "world_bundle_version_invalid",
            "bundle_version contains unsupported characters.",
            bundle_version=bundle_version,
        )

    capabilities = _require_string_list(
        raw["required_runtime_capabilities"], field="required_runtime_capabilities"
    )
    trajectory_paths = _require_string_list(
        raw.get("trajectory_paths", []), field="trajectory_paths"
    )
    hashes = raw["content_hashes"]
    if not isinstance(hashes, dict) or any(
        not isinstance(path, str) or not isinstance(digest, str) for path, digest in hashes.items()
    ):
        raise WorldBundleError(
            "world_bundle_schema_invalid",
            "Manifest field 'content_hashes' must map relative paths to sha256 digests.",
            field="content_hashes",
        )

    manifest = WorldBundleManifest(
        schema_version=schema_version,
        world_id=world_id,
        bundle_version=bundle_version,
        implementation=_require_string(raw["implementation"], field="implementation"),
        episodes_path=_require_string(raw["episodes_path"], field="episodes_path"),
        roles_path=_require_string(raw["roles_path"], field="roles_path"),
        tools_path=_require_string(raw["tools_path"], field="tools_path"),
        verifier_path=_require_string(raw["verifier_path"], field="verifier_path"),
        sources_path=_require_string(raw["sources_path"], field="sources_path"),
        default_actor_role=_require_string(raw["default_actor_role"], field="default_actor_role"),
        required_runtime_capabilities=capabilities,
        trajectory_paths=trajectory_paths,
        content_hashes=dict(hashes),
    )
    split_implementation_entrypoint(manifest.implementation)
    return manifest


def split_implementation_entrypoint(entrypoint: str) -> tuple[str, str]:
    if entrypoint.count(":") != 1:
        raise WorldBundleError(
            "world_bundle_entrypoint_invalid",
            "implementation must use the form 'relative/path.py:factory'.",
            implementation=entrypoint,
        )
    relative_path, factory_name = entrypoint.split(":", 1)
    _validate_relative_path(relative_path)
    if not relative_path.endswith(".py") or not factory_name.isidentifier():
        raise WorldBundleError(
            "world_bundle_entrypoint_invalid",
            "implementation must reference a Python file and a simple factory identifier.",
            implementation=entrypoint,
        )
    return relative_path, factory_name


def _validate_relative_path(relative_path: str) -> PurePosixPath:
    if not isinstance(relative_path, str) or not relative_path or "\\" in relative_path:
        raise WorldBundleError(
            "world_bundle_path_invalid",
            "Bundle paths must be non-empty POSIX relative paths.",
            path=relative_path,
        )
    parsed = PurePosixPath(relative_path)
    if (
        parsed.is_absolute()
        or relative_path != parsed.as_posix()
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise WorldBundleError(
            "world_bundle_path_invalid",
            "Bundle paths may not be absolute, non-canonical, or contain parent traversal.",
            path=relative_path,
        )
    return parsed


def _resolve_path(root: Path, relative_path: str, *, require_file: bool = True) -> Path:
    parsed = _validate_relative_path(relative_path)
    candidate = root.joinpath(*parsed.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorldBundleError(
            "world_bundle_file_missing",
            f"Bundle file {relative_path!r} does not exist.",
            path=relative_path,
        ) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise WorldBundleError(
            "world_bundle_path_escape",
            f"Bundle path {relative_path!r} resolves outside the bundle root.",
            path=relative_path,
        ) from exc
    if require_file and not resolved.is_file():
        raise WorldBundleError(
            "world_bundle_file_missing",
            f"Bundle path {relative_path!r} is not a regular file.",
            path=relative_path,
        )
    return resolved


def _is_generated_path(relative_path: str) -> bool:
    parsed = PurePosixPath(relative_path)
    return (
        relative_path in _GENERATED_FILES
        or "__pycache__" in parsed.parts
        or parsed.suffix == ".pyc"
    )


def _authored_files(root: Path) -> tuple[str, ...]:
    result: list[str] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in tuple(directory_names) + tuple(file_names):
            child = directory_path / name
            if not child.is_symlink():
                continue
            relative = child.relative_to(root).as_posix()
            try:
                resolved = child.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, RuntimeError, ValueError) as exc:
                raise WorldBundleError(
                    "world_bundle_path_escape",
                    f"Bundle symlink {relative!r} escapes the bundle or is dangling.",
                    path=relative,
                ) from exc
            raise WorldBundleError(
                "world_bundle_symlink_unsupported",
                f"Bundle artifacts may not be symlinks: {relative!r}.",
                path=relative,
            )

        directory_names[:] = [name for name in directory_names if name != "__pycache__"]
        for name in file_names:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            if relative == _MANIFEST_RELATIVE_PATH or _is_generated_path(relative):
                continue
            if path.is_file():
                result.append(relative)
    return tuple(sorted(result))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def compute_bundle_hashes(bundle_dir: Path) -> dict[str, str]:
    root = bundle_dir.resolve(strict=True)
    if not root.is_dir():
        raise WorldBundleError(
            "world_bundle_root_invalid",
            f"Bundle root {str(bundle_dir)!r} is not a directory.",
            path=str(bundle_dir),
        )
    return {relative: _sha256(root / relative) for relative in _authored_files(root)}


def _validate_hashes(root: Path, manifest: WorldBundleManifest) -> None:
    for relative_path, digest in manifest.content_hashes.items():
        _validate_relative_path(relative_path)
        if relative_path == _MANIFEST_RELATIVE_PATH:
            raise WorldBundleError(
                "world_bundle_hash_invalid",
                "The world manifest must not hash itself.",
                path=relative_path,
            )
        if _HASH_PATTERN.fullmatch(digest) is None:
            raise WorldBundleError(
                "world_bundle_hash_invalid",
                f"Content hash for {relative_path!r} is not a canonical sha256 digest.",
                path=relative_path,
                digest=digest,
            )

    actual_files = set(_authored_files(root))
    declared_files = set(manifest.content_hashes)
    missing_hashes = sorted(actual_files - declared_files)
    if missing_hashes:
        raise WorldBundleError(
            "world_bundle_hash_missing",
            f"Authored bundle files are missing content hashes: {', '.join(missing_hashes)}.",
            paths=missing_hashes,
        )
    unknown_hashes = sorted(declared_files - actual_files)
    if unknown_hashes:
        raise WorldBundleError(
            "world_bundle_hash_unknown",
            f"Content hashes reference missing files: {', '.join(unknown_hashes)}.",
            paths=unknown_hashes,
        )

    for relative_path, expected in sorted(manifest.content_hashes.items()):
        actual = _sha256(_resolve_path(root, relative_path))
        if actual != expected:
            raise WorldBundleError(
                "world_bundle_hash_mismatch",
                f"Content hash mismatch for {relative_path!r}.",
                path=relative_path,
                expected=expected,
                actual=actual,
            )


def _load_roles(path: Path, relative_path: str) -> tuple[RoleDefinition, ...]:
    raw = _require_object(_load_json(path), path=relative_path)
    if set(raw) != {"roles"} or not isinstance(raw["roles"], list):
        raise WorldBundleError(
            "world_bundle_roles_invalid",
            "roles.json must contain exactly one 'roles' array.",
            path=relative_path,
        )
    roles: list[RoleDefinition] = []
    seen: set[str] = set()
    for index, value in enumerate(raw["roles"]):
        if not isinstance(value, dict) or set(value) != {"id", "description"}:
            raise WorldBundleError(
                "world_bundle_roles_invalid",
                "Each role must contain exactly 'id' and 'description'.",
                path=relative_path,
                index=index,
            )
        try:
            role = RoleDefinition(id=value["id"], description=value["description"])
        except (TypeError, ValueError) as exc:
            raise WorldBundleError(
                "world_bundle_roles_invalid",
                f"Invalid role at index {index}: {exc}.",
                path=relative_path,
                index=index,
            ) from exc
        if role.id in seen:
            raise WorldBundleError(
                "world_bundle_duplicate_id",
                f"Duplicate role id {role.id!r}.",
                kind="role",
                id=role.id,
            )
        seen.add(role.id)
        roles.append(role)
    if not roles:
        raise WorldBundleError(
            "world_bundle_roles_invalid",
            "A world bundle must declare at least one role.",
            path=relative_path,
        )
    return tuple(roles)


def _load_tools(path: Path, relative_path: str) -> tuple[ToolDefinition, ...]:
    raw = _require_object(_load_json(path), path=relative_path)
    if set(raw) != {"tools"} or not isinstance(raw["tools"], list):
        raise WorldBundleError(
            "world_bundle_tools_invalid",
            "tools.json must contain exactly one 'tools' array.",
            path=relative_path,
        )
    required_fields = {"id", "description", "list_roles", "invoke_roles", "input_schema"}
    optional_fields = {"source_refs", "operation_family"}
    tools: list[ToolDefinition] = []
    seen: set[str] = set()
    for index, value in enumerate(raw["tools"]):
        if (
            not isinstance(value, dict)
            or not required_fields.issubset(value)
            or not set(value).issubset(required_fields | optional_fields)
        ):
            raise WorldBundleError(
                "world_bundle_tools_invalid",
                "Each tool must contain the required fields and only declared optional fields.",
                path=relative_path,
                index=index,
                required_fields=sorted(required_fields),
                optional_fields=sorted(optional_fields),
            )
        if not isinstance(value["list_roles"], list) or not isinstance(value["invoke_roles"], list):
            raise WorldBundleError(
                "world_bundle_tools_invalid",
                "Tool list_roles and invoke_roles must be arrays.",
                path=relative_path,
                index=index,
            )
        if len(set(value["list_roles"])) != len(value["list_roles"]) or len(
            set(value["invoke_roles"])
        ) != len(value["invoke_roles"]):
            raise WorldBundleError(
                "world_bundle_duplicate_id",
                "Tool role lists may not contain duplicate role ids.",
                kind="tool_role",
                index=index,
            )
        if not isinstance(value["input_schema"], dict):
            raise WorldBundleError(
                "world_bundle_tools_invalid",
                "Tool input_schema must be an object.",
                path=relative_path,
                index=index,
            )
        source_refs = value.get("source_refs", [])
        if (
            not isinstance(source_refs, list)
            or any(not isinstance(item, str) or not item for item in source_refs)
            or len(set(source_refs)) != len(source_refs)
        ):
            raise WorldBundleError(
                "world_bundle_tools_invalid",
                "Tool source_refs must be an array of unique non-empty strings.",
                path=relative_path,
                index=index,
            )
        operation_family = value.get("operation_family")
        if operation_family is not None and (
            not isinstance(operation_family, str) or not operation_family
        ):
            raise WorldBundleError(
                "world_bundle_tools_invalid",
                "Tool operation_family must be a non-empty string when declared.",
                path=relative_path,
                index=index,
            )
        try:
            tool = ToolDefinition(
                id=value["id"],
                description=value["description"],
                list_roles=frozenset(value["list_roles"]),
                invoke_roles=frozenset(value["invoke_roles"]),
                input_schema=value["input_schema"],
                source_refs=tuple(source_refs),
                operation_family=operation_family,
            )
        except (TypeError, ValueError) as exc:
            raise WorldBundleError(
                "world_bundle_tools_invalid",
                f"Invalid tool at index {index}: {exc}.",
                path=relative_path,
                index=index,
            ) from exc
        if tool.id in seen:
            raise WorldBundleError(
                "world_bundle_duplicate_id",
                f"Duplicate tool id {tool.id!r}.",
                kind="tool",
                id=tool.id,
            )
        seen.add(tool.id)
        tools.append(tool)
    return tuple(tools)


def _load_episodes(path: Path, relative_path: str) -> tuple[dict[str, Any], ...]:
    episodes: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise WorldBundleError(
            "world_bundle_episodes_invalid",
            f"Could not read episode file: {exc}.",
            path=relative_path,
        ) from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
        except WorldBundleError:
            raise
        except json.JSONDecodeError as exc:
            raise WorldBundleError(
                "world_bundle_episodes_invalid",
                f"Invalid episode JSON on line {line_number}: {exc}.",
                path=relative_path,
                line=line_number,
            ) from exc
        if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"]:
            raise WorldBundleError(
                "world_bundle_episodes_invalid",
                f"Episode on line {line_number} must contain a non-empty string id.",
                path=relative_path,
                line=line_number,
            )
        if value["id"] in seen:
            raise WorldBundleError(
                "world_bundle_duplicate_id",
                f"Duplicate episode id {value['id']!r}.",
                kind="episode",
                id=value["id"],
            )
        seen.add(value["id"])
        episodes.append(value)
    if not episodes:
        raise WorldBundleError(
            "world_bundle_episodes_invalid",
            "A world bundle must declare at least one episode.",
            path=relative_path,
        )
    return tuple(episodes)


def _load_sources(
    path: Path, relative_path: str
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    raw = _require_object(_load_json(path), path=relative_path)
    if (
        "sources" not in raw
        or not set(raw).issubset({"sources", "grounding_gaps"})
        or not isinstance(raw["sources"], list)
        or not isinstance(raw.get("grounding_gaps", []), list)
    ):
        raise WorldBundleError(
            "world_bundle_sources_invalid",
            "sources.json must contain 'sources' and may contain 'grounding_gaps' arrays.",
            path=relative_path,
        )
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(raw["sources"]):
        if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"]:
            raise WorldBundleError(
                "world_bundle_sources_invalid",
                "Each source must contain a non-empty string id.",
                path=relative_path,
                index=index,
            )
        if value["id"] in seen:
            raise WorldBundleError(
                "world_bundle_duplicate_id",
                f"Duplicate source id {value['id']!r}.",
                kind="source",
                id=value["id"],
            )
        seen.add(value["id"])
        sources.append(value)
    grounding_gaps: list[dict[str, Any]] = []
    for index, value in enumerate(raw.get("grounding_gaps", [])):
        if not isinstance(value, dict):
            raise WorldBundleError(
                "world_bundle_sources_invalid",
                "Each grounding gap must be an object.",
                path=relative_path,
                index=index,
            )
        grounding_gaps.append(value)
    return tuple(sources), tuple(grounding_gaps)


def validate_world_bundle(
    bundle_dir: Path,
    *,
    supported_capabilities: frozenset[str] = SUPPORTED_RUNTIME_CAPABILITIES,
) -> ValidatedWorldBundle:
    """Validate a bundle without importing or executing bundle code."""

    try:
        root = bundle_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorldBundleError(
            "world_bundle_root_invalid",
            f"Bundle root {str(bundle_dir)!r} does not exist.",
            path=str(bundle_dir),
        ) from exc
    if not root.is_dir():
        raise WorldBundleError(
            "world_bundle_root_invalid",
            f"Bundle root {str(bundle_dir)!r} is not a directory.",
            path=str(bundle_dir),
        )

    manifest_path = _resolve_path(root, _MANIFEST_RELATIVE_PATH)
    manifest = _parse_manifest(_load_json(manifest_path))
    unsupported = sorted(set(manifest.required_runtime_capabilities) - supported_capabilities)
    if unsupported:
        raise WorldBundleError(
            "world_bundle_capability_unsupported",
            f"Bundle requires unsupported runtime capabilities: {', '.join(unsupported)}.",
            capabilities=unsupported,
        )

    resolved_paths = {path: _resolve_path(root, path) for path in manifest.referenced_paths()}
    _validate_hashes(root, manifest)
    for path in manifest.referenced_paths():
        if path not in manifest.content_hashes:
            raise WorldBundleError(
                "world_bundle_hash_missing",
                f"Referenced bundle file {path!r} is missing a content hash.",
                paths=[path],
            )

    roles = _load_roles(resolved_paths[manifest.roles_path], manifest.roles_path)
    tools = _load_tools(resolved_paths[manifest.tools_path], manifest.tools_path)
    episodes = _load_episodes(resolved_paths[manifest.episodes_path], manifest.episodes_path)
    sources, grounding_gaps = _load_sources(
        resolved_paths[manifest.sources_path], manifest.sources_path
    )
    _load_json(resolved_paths[manifest.verifier_path])

    role_ids = {role.id for role in roles}
    if manifest.default_actor_role not in role_ids:
        raise WorldBundleError(
            "world_bundle_reference_invalid",
            f"default_actor_role {manifest.default_actor_role!r} is not declared in roles.json.",
            field="default_actor_role",
            role=manifest.default_actor_role,
        )
    for tool in tools:
        unknown_roles = (tool.list_roles | tool.invoke_roles) - role_ids
        if unknown_roles:
            raise WorldBundleError(
                "world_bundle_reference_invalid",
                f"Tool {tool.id!r} references undeclared roles: {', '.join(sorted(unknown_roles))}.",
                tool_id=tool.id,
                roles=sorted(unknown_roles),
            )
        unknown_sources = set(tool.source_refs) - {source["id"] for source in sources}
        if unknown_sources:
            raise WorldBundleError(
                "world_bundle_reference_invalid",
                f"Tool {tool.id!r} references undeclared sources: "
                f"{', '.join(sorted(unknown_sources))}.",
                tool_id=tool.id,
                source_refs=sorted(unknown_sources),
            )

    return ValidatedWorldBundle(
        root=root,
        manifest=manifest,
        roles=roles,
        tools=tools,
        episodes=episodes,
        sources=sources,
        grounding_gaps=grounding_gaps,
    )


def _import_implementation(bundle: ValidatedWorldBundle) -> WorldImplementationV1:
    for relative_path, expected_digest in sorted(bundle.manifest.content_hashes.items()):
        if PurePosixPath(relative_path).suffix != ".py":
            continue
        actual_digest = _sha256(_resolve_path(bundle.root, relative_path))
        if actual_digest != expected_digest:
            raise WorldBundleError(
                "world_bundle_hash_mismatch",
                f"Executable content hash mismatch for {relative_path!r} immediately before import.",
                path=relative_path,
                expected=expected_digest,
                actual=actual_digest,
            )
    relative_path, factory_name = split_implementation_entrypoint(bundle.manifest.implementation)
    implementation_path = _resolve_path(bundle.root, relative_path)
    bundle_digest = hashlib.sha256(
        (
            bundle.manifest.world_id
            + "\0"
            + bundle.manifest.bundle_version
            + "\0"
            + bundle.manifest.content_hashes[relative_path]
        ).encode("utf-8")
    ).hexdigest()[:20]
    package_name = f"_datalox_world_{bundle.manifest.world_id}_{bundle_digest}"
    module_name = f"{package_name}.{implementation_path.stem}"

    if module_name in sys.modules:
        module = sys.modules[module_name]
    else:
        package = types.ModuleType(package_name)
        package.__path__ = [str(implementation_path.parent)]  # type: ignore[attr-defined]
        package.__package__ = package_name
        sys.modules[package_name] = package
        spec = importlib.util.spec_from_file_location(module_name, implementation_path)
        if spec is None or spec.loader is None:
            sys.modules.pop(package_name, None)
            raise WorldBundleError(
                "world_bundle_import_failed",
                f"Could not create an import spec for {relative_path!r}.",
                path=relative_path,
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            sys.modules.pop(module_name, None)
            sys.modules.pop(package_name, None)
            raise WorldBundleError(
                "world_bundle_import_failed",
                f"World implementation import failed: {type(exc).__name__}: {exc}.",
                path=relative_path,
            ) from exc

    factory = getattr(module, factory_name, None)
    if factory is None or not callable(factory):
        raise WorldBundleError(
            "world_bundle_factory_missing",
            f"World implementation does not define callable factory {factory_name!r}.",
            path=relative_path,
            factory=factory_name,
        )
    try:
        implementation = factory()
    except Exception as exc:
        raise WorldBundleError(
            "world_bundle_factory_failed",
            f"World factory failed: {type(exc).__name__}: {exc}.",
            path=relative_path,
            factory=factory_name,
        ) from exc
    if not isinstance(implementation, WorldImplementationV1):
        raise WorldBundleError(
            "world_bundle_protocol_invalid",
            "World factory must return an instance of WorldImplementationV1.",
            path=relative_path,
            factory=factory_name,
            actual_type=type(implementation).__name__,
        )
    return implementation


def instantiate_validated_world_bundle(
    validated: ValidatedWorldBundle,
) -> LoadedWorldBundle:
    """Instantiate code from a previously validated or runtime-persisted bundle."""

    return LoadedWorldBundle(
        validated=validated,
        implementation=_import_implementation(validated),
    )


def load_world_bundle(
    bundle_dir: Path,
    *,
    supported_capabilities: frozenset[str] = SUPPORTED_RUNTIME_CAPABILITIES,
) -> LoadedWorldBundle:
    validated = validate_world_bundle(
        bundle_dir,
        supported_capabilities=supported_capabilities,
    )
    return instantiate_validated_world_bundle(validated)
