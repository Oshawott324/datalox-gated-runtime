from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import tomllib
from typing import Any

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.world_package.contracts import (
    PYTHON_BASE_IMAGE,
    WORLD_PACKAGE_MANIFEST,
    WORLD_PACKAGE_PORT,
    WORLD_PACKAGE_RUNS_ROOT,
    WORLD_PACKAGE_SCHEMA_VERSION,
    WorldPackageError,
)
from datalox_gated_runtime.world_v1.bundle import ValidatedWorldBundle, validate_world_bundle
from datalox_gated_runtime.world_v1.backend import initialize_world_bundle_session

_ADMISSION_SCHEMA_VERSION = "datalox_world_admission_v1"
_UV_VERSION = "0.12.1"


def build_world_package(
    *,
    env_dir: Path,
    out_dir: Path,
    episode_id: str | None = None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Create one fresh, atomic OCI build context for one admitted world episode.

    The result contains a runtime-only compiled episode and the locked Datalox
    runtime. It intentionally contains no authoring evidence, agent, provider
    credential, or harness dependency.
    """

    bundle = validate_world_bundle(env_dir)
    episode = bundle.episodes[0] if episode_id is None else bundle.episode(episode_id)
    admission = _validate_admission(bundle)
    repository = (
        project_root.resolve() if project_root is not None else Path(__file__).resolve().parents[3]
    )
    _validate_runtime_lock(repository)

    destination = out_dir.resolve()
    if destination.exists():
        raise WorldPackageError(f"output directory already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=str(destination.parent)))
    try:
        episode_template = _write_episode_template(bundle, episode, temporary)
        _copy_runtime(repository, temporary)
        _write_docker_context(temporary)
        manifest = _write_package_manifest(
            bundle=bundle,
            episode=episode,
            admission=admission,
            episode_template=episode_template,
            destination=temporary,
        )
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {**manifest, "out_dir": str(destination)}


def _validate_admission(bundle: ValidatedWorldBundle) -> dict[str, Any]:
    path = bundle.root / "world_admission.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorldPackageError(
            f"admitted world required; admission artifact is missing: {path}"
        ) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorldPackageError(f"invalid world admission artifact: {path}") from exc
    if not isinstance(payload, dict):
        raise WorldPackageError("world admission artifact must be a JSON object")
    if payload.get("schema_version") != _ADMISSION_SCHEMA_VERSION:
        raise WorldPackageError("unsupported world admission schema")
    if payload.get("admitted") is not True:
        raise WorldPackageError("world admission artifact does not admit this world")
    if payload.get("world_id") != bundle.manifest.world_id:
        raise WorldPackageError("world admission artifact has a different world_id")
    if payload.get("bundle_version") != bundle.manifest.bundle_version:
        raise WorldPackageError("world admission artifact has a different bundle_version")
    if payload.get("artifact_hashes") != bundle.manifest.content_hashes:
        raise WorldPackageError("world admission artifact is stale for this bundle")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or not checks:
        raise WorldPackageError("world admission artifact has no executed checks")
    if any(
        not isinstance(check, dict)
        or check.get("executed") is not True
        or check.get("passed") is not True
        for check in checks.values()
    ):
        raise WorldPackageError("world admission artifact contains an incomplete or failed check")
    return payload


def _validate_runtime_lock(repository: Path) -> None:
    project = repository / "pyproject.toml"
    lock = repository / "uv.lock"
    if not project.is_file() or not lock.is_file():
        raise WorldPackageError("project_root must contain pyproject.toml and uv.lock")
    try:
        project_data = tomllib.loads(project.read_text(encoding="utf-8"))
        lock_data = tomllib.loads(lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise WorldPackageError("project runtime lock files are invalid") from exc
    required_version = project_data.get("tool", {}).get("uv", {}).get("required-version")
    if required_version != f"=={_UV_VERSION}":
        raise WorldPackageError(f"pyproject.toml must pin uv=={_UV_VERSION}")
    packages = lock_data.get("package")
    if not isinstance(packages, list) or not any(
        isinstance(package, dict) and package.get("name") == "datalox-gated-runtime"
        for package in packages
    ):
        raise WorldPackageError("uv.lock does not contain the Datalox runtime project")


def _write_episode_template(
    bundle: ValidatedWorldBundle,
    episode: dict[str, Any],
    destination: Path,
) -> Path:
    template = destination / "episode_template"
    initialize_world_bundle_session(
        source_bundle_dir=bundle.root,
        run_dir=template,
        episode_id=episode["id"],
    )
    _remove_python_caches(template)
    config = {
        "config_id": f"world_package_{bundle.manifest.world_id}_{bundle.manifest.bundle_version}",
        "response_cases": [],
        "audit_rules": [],
        "metadata": {"runtime_only_world_package": True},
        "world": {"kind": "world_bundle_v1", "seed": bundle.episodes.index(episode)},
    }
    (template / "gate_config.json").write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    load_gate_config(template / "gate_config.json")
    task = episode.get("task")
    if not isinstance(task, dict):
        raise WorldPackageError("the selected world episode has no task metadata")
    (template / "task.json").write_text(
        json.dumps(task, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return template


def _remove_python_caches(root: Path) -> None:
    for directory in sorted(root.rglob("__pycache__"), reverse=True):
        shutil.rmtree(directory)
    for path in root.rglob("*.py[co]"):
        path.unlink()


def _copy_runtime(repository: Path, destination: Path) -> None:
    runtime = destination / "runtime"
    runtime.mkdir(parents=True)
    shutil.copyfile(repository / "pyproject.toml", runtime / "pyproject.toml")
    shutil.copyfile(repository / "uv.lock", runtime / "uv.lock")
    shutil.copytree(
        repository / "src" / "datalox_gated_runtime",
        runtime / "src" / "datalox_gated_runtime",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def _write_docker_context(destination: Path) -> None:
    (destination / ".dockerignore").write_text(
        """**/__pycache__
**/*.pyc
**/*.pyo
.git
""",
        encoding="utf-8",
    )
    (destination / "Dockerfile").write_text(
        f'''FROM {PYTHON_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    UV_PROJECT_ENVIRONMENT=/opt/datalox-venv

WORKDIR /opt/datalox
RUN python -m pip install --no-cache-dir uv=={_UV_VERSION}
COPY runtime/pyproject.toml runtime/uv.lock /opt/datalox/runtime/
RUN uv sync --directory /opt/datalox/runtime --frozen --no-dev --no-install-project --no-managed-python

COPY . /opt/datalox
RUN groupadd --system datalox \\
    && useradd --system --gid datalox --home-dir /nonexistent --shell /usr/sbin/nologin datalox \\
    && mkdir -p {WORLD_PACKAGE_RUNS_ROOT} \\
    && chown -R datalox:datalox /var/lib/datalox \\
    && chmod -R a-w /opt/datalox/episode_template /opt/datalox/runtime /opt/datalox-venv

ENV PATH="/opt/datalox-venv/bin:$PATH" \\
    PYTHONPATH=/opt/datalox/runtime/src \\
    DATALOX_WORLD_PACKAGE_ROOT=/opt/datalox

USER datalox:datalox
VOLUME ["{WORLD_PACKAGE_RUNS_ROOT}"]
EXPOSE {WORLD_PACKAGE_PORT}
HEALTHCHECK --interval=5s --timeout=2s --start-period=10s --retries=12 \\
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:{WORLD_PACKAGE_PORT}/health', timeout=1).read()" || exit 1
ENTRYPOINT ["python", "-m", "datalox_gated_runtime.world_package.entrypoint"]
''',
        encoding="utf-8",
    )


def _write_package_manifest(
    *,
    bundle: ValidatedWorldBundle,
    episode: dict[str, Any],
    admission: dict[str, Any],
    episode_template: Path,
    destination: Path,
) -> dict[str, Any]:
    task = episode.get("task")
    if not isinstance(task, dict):
        raise WorldPackageError("the selected world episode has no task metadata")
    task_id = task.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        raise WorldPackageError("the selected world episode has no task_id")

    files = {
        path.relative_to(destination).as_posix(): _sha256(path)
        for path in sorted(destination.rglob("*"))
        if path.is_file()
    }
    manifest: dict[str, Any] = {
        "schema_version": WORLD_PACKAGE_SCHEMA_VERSION,
        "agent_embedded": False,
        "world": {
            "id": bundle.manifest.world_id,
            "bundle_version": bundle.manifest.bundle_version,
            "environment_name": bundle.root.name,
            "episode_id": episode["id"],
            "episode_template_path": episode_template.relative_to(destination).as_posix(),
            "source_manifest_sha256": _sha256(bundle.root / "world" / "manifest.json"),
            "source_admission_sha256": _sha256(bundle.root / "world_admission.json"),
            "admission_timestamp": admission.get("admission_timestamp"),
        },
        "task": {
            "default_episode_id": episode["id"],
            "task_id": task_id,
            "retrieval": "mcp_get_task",
        },
        "surfaces": {
            "health": {"method": "GET", "path": "/health"},
            "mcp": {
                "transport": "streamable-http",
                "path": "/mcp",
                "authentication": "none",
            },
        },
        "controller": {
            "run_root": WORLD_PACKAGE_RUNS_ROOT,
            "one_episode_per_container": True,
            "network_lifecycle_api": False,
            "finalize_command": [
                "python",
                "-m",
                "datalox_gated_runtime.world_package.entrypoint",
                "finalize",
                "--package-root",
                "/opt/datalox",
                "--run",
                WORLD_PACKAGE_RUNS_ROOT,
                "--out",
                f"{WORLD_PACKAGE_RUNS_ROOT}/verdict.json",
            ],
            "finalize_after_agent": True,
        },
        "container": {
            "port": WORLD_PACKAGE_PORT,
            "python_base_image": PYTHON_BASE_IMAGE,
            "runtime_lock": "runtime/uv.lock",
            "runtime_lock_sha256": _sha256(destination / "runtime" / "uv.lock"),
            "runtime_read_only": True,
            "world_read_only": True,
        },
        "distribution": "inherits_source_bundle_classification",
        "files": files,
    }
    manifest["package_content_sha256"] = _canonical_digest(manifest)
    (destination / WORLD_PACKAGE_MANIFEST).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def resolve_package_file(root: Path, relative_path: str) -> Path:
    """Resolve a declared package file without permitting path traversal."""

    parsed = PurePosixPath(relative_path)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise WorldPackageError(f"invalid package-relative path: {relative_path!r}")
    resolved = (root / Path(*parsed.parts)).resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise WorldPackageError(f"package path escapes package root: {relative_path!r}") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise WorldPackageError(f"package path is not a regular file: {relative_path!r}")
    return resolved
