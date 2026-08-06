from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

from datalox_gated_runtime.models import CallRequest, TaskBrief
from datalox_gated_runtime.world_backend import WorldResponse, WorldVerifierResult
from datalox_gated_runtime.world_v1.bundle import (
    LoadedWorldBundle,
    ValidatedWorldBundle,
    WorldBundleManifest,
    instantiate_validated_world_bundle,
    validate_world_bundle,
)
from datalox_gated_runtime.world_v1.contracts import (
    ActorContext,
    RoleDefinition,
    ToolDefinition,
    resolve_actor_context,
)
from datalox_gated_runtime.world_v1.errors import (
    WorldAuthorizationError,
    WorldBundleError,
    WorldSessionError,
)
from datalox_gated_runtime.world_v1.session import WorldSession

RUNTIME_BUNDLE_DIRECTORY = ".world_v1_code"
RUNTIME_STATE_DATABASE = "world_v1.sqlite3"
_RUNTIME_BUNDLE_TABLE = "datalox_world_bundle_runtime"
_RUNTIME_DATA_DECLARATION = "world/v1/runtime_data.json"


def _runtime_files(validated: ValidatedWorldBundle) -> tuple[Path, ...]:
    root = validated.root.resolve()
    files = {
        path.resolve() for path in validated.root.rglob("*.py") if "__pycache__" not in path.parts
    }
    declaration = validated.root / _RUNTIME_DATA_DECLARATION
    if declaration.is_file():
        try:
            raw = json.loads(declaration.read_text(encoding="utf-8"))
            declared_paths = raw["paths"]
            if (
                not isinstance(declared_paths, list)
                or not declared_paths
                or not all(
                    isinstance(path, str) and path and path.strip() == path
                    for path in declared_paths
                )
            ):
                raise ValueError("paths must be a non-empty array of non-empty canonical strings")
            if len(set(declared_paths)) != len(declared_paths):
                raise ValueError("paths must not contain duplicates")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise WorldBundleError(
                "world_runtime_data_declaration_invalid",
                f"Runtime data declaration is invalid: {exc}.",
                path=_RUNTIME_DATA_DECLARATION,
            ) from exc
        files.add(declaration.resolve())
        resolved_data_paths: set[Path] = set()
        for relative_path in declared_paths:
            pure = PurePosixPath(relative_path)
            if pure.is_absolute() or ".." in pure.parts:
                raise WorldBundleError(
                    "world_runtime_data_path_invalid",
                    "Runtime data paths must be canonical relative bundle paths.",
                    path=relative_path,
                )
            candidate = (validated.root / relative_path).resolve()
            try:
                candidate.relative_to(root)
            except ValueError as exc:
                raise WorldBundleError(
                    "world_runtime_data_path_invalid",
                    "Runtime data paths must remain inside the world bundle.",
                    path=relative_path,
                ) from exc
            if not candidate.is_file():
                raise WorldBundleError(
                    "world_runtime_data_missing",
                    "Declared runtime data file does not exist.",
                    path=relative_path,
                )
            if candidate in resolved_data_paths:
                raise WorldBundleError(
                    "world_runtime_data_declaration_invalid",
                    "Runtime data paths must not resolve to the same file.",
                    path=relative_path,
                )
            resolved_data_paths.add(candidate)
            files.add(candidate)
    for path in files:
        relative = path.relative_to(root).as_posix()
        if relative not in validated.manifest.content_hashes:
            raise WorldBundleError(
                "world_runtime_data_hash_missing",
                "Every runtime file must have a bundle content hash.",
                path=relative,
            )
    return tuple(sorted(files))


def _runtime_payload(
    validated: ValidatedWorldBundle,
    episode_id: str,
    *,
    manifest_digest: str,
) -> dict[str, Any]:
    episode = validated.episode(episode_id)
    manifest = validated.manifest
    executable_hashes = {
        path.relative_to(validated.root.resolve()).as_posix(): manifest.content_hashes[
            path.relative_to(validated.root.resolve()).as_posix()
        ]
        for path in _runtime_files(validated)
    }
    return {
        "bundle_ref": {
            "schema_version": "datalox_world_bundle_ref_v1",
            "world_id": manifest.world_id,
            "bundle_version": manifest.bundle_version,
            "episode_id": episode_id,
            "manifest_digest": manifest_digest,
        },
        "manifest": {
            "schema_version": manifest.schema_version,
            "world_id": manifest.world_id,
            "bundle_version": manifest.bundle_version,
            "implementation": manifest.implementation,
            "episodes_path": "runtime:selected_episode",
            "roles_path": "runtime:roles",
            "tools_path": "runtime:tools",
            "verifier_path": "runtime:verifier",
            "sources_path": "runtime:sources",
            "default_actor_role": manifest.default_actor_role,
            "required_runtime_capabilities": list(manifest.required_runtime_capabilities),
            "trajectory_paths": [],
            "content_hashes": executable_hashes,
        },
        "roles": [{"id": role.id, "description": role.description} for role in validated.roles],
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
            for tool in validated.tools
        ],
        "episode": episode,
    }


def install_world_bundle(*, source_bundle_dir: Path, run_dir: Path, episode_id: str) -> Path:
    """Persist runtime-only code and selected metadata without exposing hidden inputs."""

    validated = validate_world_bundle(source_bundle_dir)
    code_destination = run_dir / RUNTIME_BUNDLE_DIRECTORY
    state_database = run_dir / RUNTIME_STATE_DATABASE
    if code_destination.exists() or state_database.exists():
        raise WorldBundleError(
            "world_bundle_runtime_copy_exists",
            "Run-private world bundle storage already exists.",
            code_path=str(code_destination),
            database_path=str(state_database),
        )
    run_dir.mkdir(parents=True, exist_ok=True)
    code_destination.mkdir(parents=True)
    runtime_files = _runtime_files(validated)
    implementation_path = validated.manifest.implementation.split(":", 1)[0]
    if (validated.root / implementation_path).resolve() not in runtime_files:
        raise WorldBundleError(
            "world_bundle_entrypoint_invalid",
            "Validated implementation entrypoint is not a Python source file.",
            path=implementation_path,
        )
    for source in runtime_files:
        relative = source.relative_to(validated.root.resolve())
        destination = code_destination / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    connection = sqlite3.connect(str(state_database))
    try:
        connection.execute(
            f"CREATE TABLE {_RUNTIME_BUNDLE_TABLE} (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), payload_json TEXT NOT NULL)"
        )
        connection.execute(
            f"INSERT INTO {_RUNTIME_BUNDLE_TABLE}(singleton, payload_json) VALUES (1, ?)",
            (
                json.dumps(
                    _runtime_payload(
                        validated,
                        episode_id,
                        manifest_digest=_sha256_file(validated.root / "world" / "manifest.json"),
                    ),
                    sort_keys=True,
                ),
            ),
        )
        connection.commit()
    finally:
        connection.close()
    return code_destination


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _load_runtime_payload(run_dir: Path) -> dict[str, Any]:
    state_database = run_dir / RUNTIME_STATE_DATABASE
    connection = sqlite3.connect(str(state_database))
    try:
        row = connection.execute(
            f"SELECT payload_json FROM {_RUNTIME_BUNDLE_TABLE} WHERE singleton = 1"
        ).fetchone()
    except sqlite3.Error as exc:
        raise WorldBundleError(
            "world_bundle_runtime_metadata_missing",
            "Run-private world bundle metadata is missing or invalid.",
            path=str(state_database),
        ) from exc
    finally:
        connection.close()
    if row is None:
        raise WorldBundleError(
            "world_bundle_runtime_metadata_missing",
            "Run-private world bundle metadata is missing.",
            path=str(state_database),
        )
    try:
        payload = json.loads(row[0])
        if not isinstance(payload, dict):
            raise TypeError("runtime payload must be an object")
        return payload
    except (TypeError, ValueError) as exc:
        raise WorldBundleError(
            "world_bundle_runtime_metadata_invalid",
            f"Run-private world bundle metadata is invalid: {exc}.",
            path=str(state_database),
        ) from exc


def installed_world_bundle_ref(run_dir: Path) -> dict[str, str]:
    payload = _load_runtime_payload(run_dir)
    raw = payload.get("bundle_ref")
    required = {
        "schema_version",
        "world_id",
        "bundle_version",
        "episode_id",
        "manifest_digest",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise WorldBundleError(
            "world_bundle_runtime_metadata_invalid",
            "Run-private world bundle reference is missing or invalid.",
            path=str(run_dir / RUNTIME_STATE_DATABASE),
        )
    if any(not isinstance(raw[field], str) or not raw[field] for field in required):
        raise WorldBundleError(
            "world_bundle_runtime_metadata_invalid",
            "Run-private world bundle reference fields must be non-empty strings.",
            path=str(run_dir / RUNTIME_STATE_DATABASE),
        )
    return {field: raw[field] for field in sorted(required)}


def _load_installed_world_bundle(run_dir: Path) -> LoadedWorldBundle:
    state_database = run_dir / RUNTIME_STATE_DATABASE
    try:
        payload = _load_runtime_payload(run_dir)
        raw_manifest = payload["manifest"]
        manifest = WorldBundleManifest(
            schema_version=raw_manifest["schema_version"],
            world_id=raw_manifest["world_id"],
            bundle_version=raw_manifest["bundle_version"],
            implementation=raw_manifest["implementation"],
            episodes_path=raw_manifest["episodes_path"],
            roles_path=raw_manifest["roles_path"],
            tools_path=raw_manifest["tools_path"],
            verifier_path=raw_manifest["verifier_path"],
            sources_path=raw_manifest["sources_path"],
            default_actor_role=raw_manifest["default_actor_role"],
            required_runtime_capabilities=tuple(raw_manifest["required_runtime_capabilities"]),
            trajectory_paths=(),
            content_hashes=raw_manifest["content_hashes"],
        )
        roles = tuple(RoleDefinition(**role) for role in payload["roles"])
        tools = tuple(
            ToolDefinition(
                id=tool["id"],
                description=tool["description"],
                list_roles=frozenset(tool["list_roles"]),
                invoke_roles=frozenset(tool["invoke_roles"]),
                input_schema=tool["input_schema"],
                source_refs=tuple(tool["source_refs"]),
                operation_family=tool["operation_family"],
            )
            for tool in payload["tools"]
        )
        validated = ValidatedWorldBundle(
            root=(run_dir / RUNTIME_BUNDLE_DIRECTORY).resolve(strict=True),
            manifest=manifest,
            roles=roles,
            tools=tools,
            episodes=(payload["episode"],),
            sources=(),
            grounding_gaps=(),
        )
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise WorldBundleError(
            "world_bundle_runtime_metadata_invalid",
            f"Run-private world bundle metadata is invalid: {exc}.",
            path=str(state_database),
        ) from exc
    _verify_runtime_code(validated)
    return instantiate_validated_world_bundle(validated)


def _verify_runtime_code(validated: ValidatedWorldBundle) -> None:
    expected = dict(validated.manifest.content_hashes)
    actual_paths = {
        path.relative_to(validated.root).as_posix()
        for path in validated.root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    if actual_paths != set(expected):
        raise WorldBundleError(
            "world_bundle_runtime_code_set_mismatch",
            "Run-private executable files do not match the installed bundle.",
            missing_paths=sorted(set(expected) - actual_paths),
            extra_paths=sorted(actual_paths - set(expected)),
        )
    for relative_path, expected_digest in sorted(expected.items()):
        digest = hashlib.sha256()
        with (validated.root / relative_path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        actual_digest = f"sha256:{digest.hexdigest()}"
        if actual_digest != expected_digest:
            raise WorldBundleError(
                "world_bundle_runtime_code_hash_mismatch",
                f"Run-private executable hash mismatch for {relative_path!r}.",
                path=relative_path,
                expected=expected_digest,
                actual=actual_digest,
            )


def initialize_world_bundle_session(
    *,
    source_bundle_dir: Path,
    run_dir: Path,
    episode_id: str,
) -> None:
    install_world_bundle(
        source_bundle_dir=source_bundle_dir,
        run_dir=run_dir,
        episode_id=episode_id,
    )
    bundle = _load_installed_world_bundle(run_dir)
    episode = bundle.episode(episode_id)
    with WorldSession(run_dir / RUNTIME_STATE_DATABASE) as session:
        bundle.implementation.initialize_episode(session=session, episode=episode)
        if not session.is_initialized or session.episode_id != episode_id:
            raise WorldSessionError(
                "world_episode_initialization_invalid",
                "World implementation did not reset the session to the selected episode.",
                expected_episode_id=episode_id,
                actual_episode_id=session.episode_id if session.is_initialized else None,
            )


class WorldBundleBackend:
    """Run-bound adapter exposing the existing HTTP/MCP backend method shape."""

    def __init__(
        self,
        *,
        run_dir: Path,
        configured_actor: ActorContext | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.bundle: LoadedWorldBundle = _load_installed_world_bundle(run_dir)
        self.session = WorldSession(run_dir / RUNTIME_STATE_DATABASE)
        if not self.session.is_initialized:
            self.session.close()
            raise WorldSessionError(
                "world_session_not_initialized",
                "Run-private world session has not been initialized.",
                run_dir=str(run_dir),
            )
        self.configured_actor = configured_actor
        self.world_id = self.bundle.manifest.world_id

    def close(self) -> None:
        self.session.close()

    def _default_actor(self) -> ActorContext:
        return self.configured_actor or ActorContext(
            actor_id="agent",
            role=self.bundle.manifest.default_actor_role,
        )

    def _actor_for_request(self, request: CallRequest) -> ActorContext:
        return resolve_actor_context(
            request,
            declared_roles=self.bundle.tool_catalog.role_ids,
            default_role=self.bundle.manifest.default_actor_role,
            configured_actor=self.configured_actor,
        )

    def handle(self, request: CallRequest) -> WorldResponse | None:
        tool_id = self.bundle.implementation.tool_for_request(request)
        try:
            actor = self._actor_for_request(request)
        except WorldAuthorizationError as exc:
            actor = self._actor_for_denial(request)
            self._record_denial(request=request, actor=actor, tool_id=tool_id, error=exc)
            return self._denial_response(request=request, error=exc, tool_id=tool_id)
        if tool_id is not None:
            try:
                self.bundle.tool_catalog.require_invocation(actor, tool_id)
            except WorldAuthorizationError as exc:
                self._record_denial(request=request, actor=actor, tool_id=tool_id, error=exc)
                return self._denial_response(request=request, error=exc, tool_id=tool_id)
        operation_id = request.operation_id or tool_id or "unmapped_operation"
        with self.session.transaction(
            operation_id=operation_id,
            actor=actor,
            tool_name=tool_id,
            request=self._request_evidence(request),
        ):
            self.session.append_event(
                "world_operation_started",
                {
                    "operation_id": operation_id,
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                    "tool_id": tool_id,
                    "tool_name": tool_id,
                    "request": self._request_evidence(request),
                },
            )
            response = self.bundle.implementation.handle(
                request,
                actor=actor,
                session=self.session,
            )
            if response is not None:
                self.session.record_response_digest(
                    actor=actor,
                    operation_id=operation_id,
                    tool_id=tool_id,
                    request=self._request_evidence(request),
                    status_code=response.status_code,
                    body=response.body,
                )
            return response

    def _actor_for_denial(self, request: CallRequest) -> ActorContext:
        headers = {key.lower(): value for key, value in request.headers.items()}
        configured = self._default_actor()
        actor_id = headers.get("x-datalox-actor-id") or configured.actor_id
        actor_role = headers.get("x-datalox-actor-role") or configured.role
        try:
            return ActorContext(actor_id=actor_id, role=actor_role)
        except ValueError:
            return configured

    @staticmethod
    def _request_evidence(request: CallRequest) -> dict[str, Any]:
        return {
            "method": request.normalized_method(),
            "path": request.path,
            "query": dict(request.query),
            "body": request.body,
        }

    def _record_denial(
        self,
        *,
        request: CallRequest,
        actor: ActorContext,
        tool_id: str | None,
        error: WorldAuthorizationError,
    ) -> None:
        with self.session.transaction(
            operation_id=request.operation_id or tool_id or "world.denied",
            actor=actor,
            tool_name=tool_id,
            request=self._request_evidence(request),
        ):
            self.session.record_denied_tool_attempt(
                actor=actor,
                tool_id=tool_id or request.operation_id or "unmapped_operation",
                arguments=request.body if isinstance(request.body, dict) else {},
                reason_code=error.code,
                request=self._request_evidence(request),
                within_transaction=True,
            )
            self.session.record_response_digest(
                actor=actor,
                operation_id=request.operation_id or tool_id or "unmapped_operation",
                tool_id=tool_id,
                request=self._request_evidence(request),
                status_code=403,
                body={"error": error.to_dict()},
            )

    def _denial_response(
        self,
        *,
        request: CallRequest,
        error: WorldAuthorizationError,
        tool_id: str | None,
    ) -> WorldResponse:
        return WorldResponse(
            status_code=403,
            body={"error": error.to_dict()},
            is_mutation=False,
            world_id=self.world_id,
            operation_id=request.operation_id or tool_id or "unmapped_operation",
            decision_kind="deny",
            reason_code=error.code,
            message=error.message,
        )

    def tool_schemas(self, actor: ActorContext | None = None) -> dict[str, dict[str, Any]]:
        resolved_actor = actor or self._default_actor()
        visible_tools = self.bundle.tool_catalog.list_for(resolved_actor)
        visible_tool_ids = {tool.id for tool in visible_tools}
        schemas = self.bundle.implementation.tool_schemas(actor=resolved_actor)
        if set(schemas) != visible_tool_ids:
            raise WorldBundleError(
                "world_bundle_protocol_invalid",
                "World implementation tool schemas must exactly match role-visible declared tools.",
                missing_tool_ids=sorted(visible_tool_ids - set(schemas)),
                extra_tool_ids=sorted(set(schemas) - visible_tool_ids),
                actor_role=resolved_actor.role,
            )
        result: dict[str, dict[str, Any]] = {}
        for tool in visible_tools:
            declared_schema = dict(tool.input_schema)
            implementation_entry = schemas[tool.id]
            if not isinstance(implementation_entry, Mapping):
                raise WorldBundleError(
                    "world_bundle_protocol_invalid",
                    "World implementation tool schema must be an object.",
                    tool_id=tool.id,
                    actor_role=resolved_actor.role,
                )
            implementation_schema = implementation_entry.get("inputSchema", implementation_entry)
            if implementation_schema != declared_schema:
                raise WorldBundleError(
                    "world_bundle_protocol_invalid",
                    "World implementation tool schema differs from tools.json.",
                    tool_id=tool.id,
                    actor_role=resolved_actor.role,
                )
            result[tool.id] = {
                "description": tool.description,
                "inputSchema": deepcopy(declared_schema),
            }
        return result

    def request_for_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        actor: ActorContext | None = None,
    ) -> CallRequest:
        resolved_actor = actor or self._default_actor()
        try:
            self.bundle.tool_catalog.require_invocation(resolved_actor, tool_name)
        except WorldAuthorizationError as exc:
            self.session.record_denied_tool_attempt(
                actor=resolved_actor,
                tool_id=tool_name,
                arguments=arguments,
                reason_code=exc.code,
                request={"arguments": dict(arguments)},
            )
            raise
        request = self.bundle.implementation.request_for_tool(
            tool_name,
            arguments,
            actor=resolved_actor,
        )
        operation_id = self.bundle.implementation.operation_for_tool(tool_name)
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower()
            not in {
                "x-datalox-actor-id",
                "x-datalox-actor-role",
                "x-datalox-tool-name",
            }
        }
        headers.update(
            {
                "x-datalox-actor-id": resolved_actor.actor_id,
                "x-datalox-actor-role": resolved_actor.role,
                "x-datalox-tool-name": tool_name,
            }
        )
        return CallRequest(
            method=request.method,
            path=request.path,
            query=dict(request.query),
            body=request.body,
            headers=headers,
            operation_id=operation_id or request.operation_id,
        )

    def operation_for_tool(self, tool_name: str) -> str | None:
        return self.bundle.implementation.operation_for_tool(tool_name)

    def verify(self) -> WorldVerifierResult:
        return self.bundle.implementation.verify(
            session=self.session,
            episode=self.bundle.episode(self.session.episode_id),
        )

    def task(self) -> TaskBrief | None:
        return self.bundle.implementation.task(episode=self.bundle.episode(self.session.episode_id))
