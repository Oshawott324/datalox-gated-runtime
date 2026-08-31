from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import socket
import sys
import tempfile
from collections.abc import Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path, PurePosixPath

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from datalox_gated_runtime.mcp_server import build_server
from datalox_gated_runtime.session import finalize_session
from datalox_gated_runtime.world_package.builder import resolve_package_file
from datalox_gated_runtime.world_package.contracts import (
    WORLD_PACKAGE_MANIFEST,
    WORLD_PACKAGE_PORT,
    WORLD_PACKAGE_RUNS_ROOT,
    WORLD_PACKAGE_SCHEMA_VERSION,
    WORLD_PACKAGE_VERDICT_SCHEMA_VERSION,
    WorldPackageError,
)
from datalox_gated_runtime.world_v1.backend import installed_world_bundle_ref
from datalox_gated_runtime.world_v1.contracts import ActorContext

_ACTORS_ENV = "DATALOX_WORLD_PACKAGE_ACTORS"
_ACTOR_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def create_packaged_world_app(
    *,
    package_root: Path,
    environ: Mapping[str, str] | None = None,
    run_dir: Path | None = None,
) -> FastAPI:
    """Materialize and serve the package's single fixed gated MCP episode."""

    environment = os.environ if environ is None else environ
    root = package_root.resolve(strict=True)
    manifest = _load_and_verify_manifest(root)
    world = manifest["world"]
    template = _resolve_package_directory(root, world["episode_template_path"])
    target_run = Path(WORLD_PACKAGE_RUNS_ROOT) if run_dir is None else run_dir
    _materialize_episode(template=template, run_dir=target_run)
    installed = installed_world_bundle_ref(target_run)
    if installed["world_id"] != world["id"]:
        raise WorldPackageError("installed world_id does not match package metadata")
    if installed["bundle_version"] != world["bundle_version"]:
        raise WorldPackageError("installed bundle_version does not match package metadata")
    if installed["episode_id"] != world["episode_id"]:
        raise WorldPackageError("installed episode_id does not match package metadata")

    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_allowed_hosts(environment),
        allowed_origins=_csv(environment.get("DATALOX_ALLOWED_ORIGINS", "")),
    )
    default_server = build_server(
        target_run,
        transport_security=transport_security,
        include_session_manifest_tool=False,
        host="0.0.0.0",
        port=_positive_int(environment, "DATALOX_PORT", default=WORLD_PACKAGE_PORT),
    )
    if not isinstance(default_server, FastMCP):
        raise WorldPackageError("packaged worlds must expose the FastMCP world surface")
    actor_servers: list[tuple[ActorContext, FastMCP]] = []
    for actor in _configured_actors(environment):
        server = build_server(
            target_run,
            actor_context=actor,
            transport_security=transport_security,
            include_session_manifest_tool=False,
            host="0.0.0.0",
            port=_positive_int(environment, "DATALOX_PORT", default=WORLD_PACKAGE_PORT),
        )
        if not isinstance(server, FastMCP):
            raise WorldPackageError("packaged actor endpoints must expose FastMCP")
        actor_servers.append((actor, server))

    default_mcp_app = default_server.streamable_http_app()
    actor_mcp_apps = [(actor, server.streamable_http_app()) for actor, server in actor_servers]

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(
                default_mcp_app.router.lifespan_context(default_mcp_app)
            )
            for _, mcp_app in actor_mcp_apps:
                await stack.enter_async_context(mcp_app.router.lifespan_context(mcp_app))
            yield

    app = FastAPI(
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    async def health() -> dict[str, object]:
        return {
            "ok": True,
            "service": "datalox_world_package",
            "world_id": world["id"],
            "episode_id": world["episode_id"],
            "live_mode": False,
        }

    for actor, mcp_app in actor_mcp_apps:
        app.mount(f"/actors/{actor.role}", mcp_app)
    app.mount("/", default_mcp_app)
    return app


def _configured_actors(environment: Mapping[str, str]) -> tuple[ActorContext, ...]:
    raw = environment.get(_ACTORS_ENV)
    if raw is None or not raw.strip():
        return ()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WorldPackageError(f"{_ACTORS_ENV} must be valid JSON") from exc
    if not isinstance(payload, list) or not payload:
        raise WorldPackageError(f"{_ACTORS_ENV} must be a non-empty JSON array")

    actors: list[ActorContext] = []
    seen_roles: set[str] = set()
    for index, item in enumerate(payload):
        if not isinstance(item, dict) or set(item) != {"actor_id", "role"}:
            raise WorldPackageError(
                f"{_ACTORS_ENV}[{index}] must contain exactly actor_id and role"
            )
        actor_id = item["actor_id"]
        role = item["role"]
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise WorldPackageError(f"{_ACTORS_ENV}[{index}].actor_id must be non-empty")
        if not isinstance(role, str) or not _ACTOR_PATH_COMPONENT.fullmatch(role):
            raise WorldPackageError(f"{_ACTORS_ENV}[{index}].role must be a URL-safe role id")
        if role in seen_roles:
            raise WorldPackageError(f"{_ACTORS_ENV} contains duplicate role {role!r}")
        seen_roles.add(role)
        actors.append(ActorContext(actor_id=actor_id, role=role))
    return tuple(actors)


def finalize_packaged_world(
    *,
    package_root: Path,
    run_dir: Path,
    out_path: Path,
) -> dict[str, object]:
    """Finalize a run out-of-band and atomically write a package-bound verdict."""

    root = package_root.resolve(strict=True)
    manifest = _load_and_verify_manifest(root)
    run = run_dir.resolve(strict=True)
    world = manifest["world"]
    installed = installed_world_bundle_ref(run)
    expected_identity = {
        "world_id": world["id"],
        "bundle_version": world["bundle_version"],
        "episode_id": world["episode_id"],
        "manifest_digest": world["source_manifest_sha256"],
    }
    for field, expected in expected_identity.items():
        if installed[field] != expected:
            raise WorldPackageError(f"run {field} does not match package metadata")
    task = _load_json_object(run / "task.json", description="run task")
    if task.get("task_id") != manifest["task"]["task_id"]:
        raise WorldPackageError("run task_id does not match package metadata")
    for artifact_name in ("audit.json", "run_export.json"):
        if (run / artifact_name).exists():
            raise WorldPackageError("run has already been finalized")

    output = out_path.resolve()
    if output in {run / "audit.json", run / "run_export.json"}:
        raise WorldPackageError("verdict output must not replace a run finalization artifact")
    if output.exists():
        raise WorldPackageError(f"verdict output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=str(output.parent),
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        audit = finalize_session(run)
        passed = audit.get("passed")
        if not isinstance(passed, bool):
            raise WorldPackageError("finalized audit has no boolean passed verdict")
        reward, reward_source = _audit_reward(audit, passed=passed)
        failure_codes = audit.get("failure_codes")
        if not isinstance(failure_codes, list) or any(
            not isinstance(code, str) for code in failure_codes
        ):
            raise WorldPackageError("finalized audit has invalid failure_codes")
        payload: dict[str, object] = {
            "schema_version": WORLD_PACKAGE_VERDICT_SCHEMA_VERSION,
            "package_content_sha256": manifest["package_content_sha256"],
            "source_manifest_sha256": world["source_manifest_sha256"],
            "world_id": world["id"],
            "bundle_version": world["bundle_version"],
            "episode_id": world["episode_id"],
            "task_id": manifest["task"]["task_id"],
            "audit": {
                "passed": passed,
                "reward": reward,
                "reward_source": reward_source,
                "failure_codes": failure_codes,
                "sha256": _sha256(run / "audit.json"),
            },
            "run_export_sha256": _sha256(run / "run_export.json"),
        }
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        return payload
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        if arguments[0] != "finalize":
            raise SystemExit(f"unsupported world package command: {arguments[0]}")
        parser = argparse.ArgumentParser(description="Finalize one packaged Datalox world.")
        parser.add_argument("command", choices=["finalize"])
        parser.add_argument("--package-root", required=True)
        parser.add_argument("--run", required=True)
        parser.add_argument("--out", required=True)
        parsed = parser.parse_args(arguments)
        payload = finalize_packaged_world(
            package_root=Path(parsed.package_root),
            run_dir=Path(parsed.run),
            out_path=Path(parsed.out),
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    import uvicorn

    package_root = Path(os.environ.get("DATALOX_WORLD_PACKAGE_ROOT", "/opt/datalox"))
    app = create_packaged_world_app(package_root=package_root)
    uvicorn.run(
        app,
        host=os.environ.get("DATALOX_HOST", "0.0.0.0"),
        port=_positive_int(os.environ, "DATALOX_PORT", default=WORLD_PACKAGE_PORT),
    )


def _audit_reward(audit: dict, *, passed: bool) -> tuple[float, str]:
    verifiers = audit.get("verifiers")
    world = verifiers.get("world") if isinstance(verifiers, dict) else None
    reward = world.get("reward") if isinstance(world, dict) else None
    if reward is None:
        return (1.0 if passed else 0.0), "binary_audit"
    if isinstance(reward, bool) or not isinstance(reward, (int, float)):
        raise WorldPackageError("world verifier reward must be numeric")
    normalized = float(reward)
    if not math.isfinite(normalized) or not 0.0 <= normalized <= 1.0:
        raise WorldPackageError("world verifier reward must be between 0 and 1")
    return normalized, "world_verifier"


def _load_json_object(path: Path, *, description: str) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorldPackageError(f"invalid {description}: {path}") from exc
    if not isinstance(payload, dict):
        raise WorldPackageError(f"{description} must be a JSON object")
    return payload


def _materialize_episode(*, template: Path, run_dir: Path) -> None:
    target = run_dir.resolve()
    if target.exists() and any(target.iterdir()):
        raise WorldPackageError(f"run directory must be empty: {target}")
    target.mkdir(parents=True, exist_ok=True)
    for source in sorted(template.iterdir()):
        destination = target / source.name
        if source.is_dir():
            shutil.copytree(source, destination)
        elif source.is_file() and not source.is_symlink():
            # Package templates are immutable in the image.  The materialized
            # run is the writable state boundary, so copying template modes
            # would leave SQLite and other run artifacts read-only.
            shutil.copyfile(source, destination)
            destination.chmod(0o600)
        else:
            raise WorldPackageError(f"episode template contains unsupported entry: {source.name}")


def _load_and_verify_manifest(root: Path) -> dict:
    manifest_path = root / WORLD_PACKAGE_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise WorldPackageError("package manifest must be a regular file")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorldPackageError(f"invalid package manifest: {manifest_path}") from exc
    if not isinstance(payload, dict):
        raise WorldPackageError("package manifest must be a JSON object")
    if payload.get("schema_version") != WORLD_PACKAGE_SCHEMA_VERSION:
        raise WorldPackageError("unsupported world package schema")
    declared_package_digest = payload.get("package_content_sha256")
    digest_payload = dict(payload)
    digest_payload.pop("package_content_sha256", None)
    if declared_package_digest != _canonical_digest(digest_payload):
        raise WorldPackageError("package manifest content digest mismatch")
    files = payload.get("files")
    if not isinstance(files, dict) or not files:
        raise WorldPackageError("package manifest must declare content hashes")
    actual_files = _package_file_set(root)
    declared_files = set(files)
    if actual_files != declared_files:
        undeclared = sorted(actual_files - declared_files)
        missing = sorted(declared_files - actual_files)
        details = []
        if undeclared:
            details.append("undeclared package files: " + ", ".join(undeclared))
        if missing:
            details.append("missing package files: " + ", ".join(missing))
        raise WorldPackageError("; ".join(details))
    for relative_path, expected in sorted(files.items()):
        if not isinstance(relative_path, str) or not isinstance(expected, str):
            raise WorldPackageError("package content hashes must map paths to digests")
        actual = _sha256(resolve_package_file(root, relative_path))
        if actual != expected:
            raise WorldPackageError(f"package content hash mismatch: {relative_path}")
    world = payload.get("world")
    if not isinstance(world, dict):
        raise WorldPackageError("package manifest has no world metadata")
    required = {
        "id",
        "bundle_version",
        "environment_name",
        "episode_id",
        "episode_template_path",
        "source_manifest_sha256",
    }
    if any(not isinstance(world.get(field), str) or not world[field] for field in required):
        raise WorldPackageError("package world metadata is incomplete")
    task = payload.get("task")
    if (
        not isinstance(task, dict)
        or not isinstance(task.get("task_id"), str)
        or not task["task_id"]
    ):
        raise WorldPackageError("package task metadata is incomplete")
    return payload


def _package_file_set(root: Path) -> set[str]:
    files: set[str] = set()
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in tuple(directory_names) + tuple(file_names):
            path = directory_path / name
            if path.is_symlink():
                relative = path.relative_to(root).as_posix()
                raise WorldPackageError(f"package entries must not be symlinks: {relative}")
        for name in file_names:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            if not path.is_file():
                raise WorldPackageError(f"package entry must be a regular file: {relative}")
            if relative != WORLD_PACKAGE_MANIFEST:
                files.add(relative)
    return files


def _resolve_package_directory(root: Path, relative_path: str) -> Path:
    parsed = PurePosixPath(relative_path)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise WorldPackageError("episode_template_path must be package-relative")
    resolved = (root / Path(*parsed.parts)).resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise WorldPackageError("episode_template_path escapes the package root") from exc
    if not resolved.is_dir() or resolved.is_symlink():
        raise WorldPackageError("episode_template_path is not a regular directory")
    return resolved


def _allowed_hosts(environment: Mapping[str, str]) -> list[str]:
    configured = _csv(environment.get("DATALOX_ALLOWED_HOSTS", ""))
    if configured:
        return configured
    hostname = socket.gethostname()
    return [f"{hostname}:*", "world:*", "127.0.0.1:*", "localhost:*"]


def _csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _positive_int(environment: Mapping[str, str], name: str, *, default: int) -> int:
    raw = environment.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise WorldPackageError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise WorldPackageError(f"{name} must be a positive integer")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


if __name__ == "__main__":
    main()
