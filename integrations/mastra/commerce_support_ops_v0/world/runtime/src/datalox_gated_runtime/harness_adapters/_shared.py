from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Iterator

from datalox_gated_runtime.harness_adapters.contracts import (
    ADAPTER_MANIFEST,
    ADAPTER_SCHEMA_VERSION,
    HarnessAdapterError,
)
from datalox_gated_runtime.world_package.contracts import WORLD_PACKAGE_MANIFEST


@contextmanager
def atomic_output(destination: Path) -> Iterator[Path]:
    target = destination.resolve()
    if target.exists():
        raise HarnessAdapterError(f"output directory already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=str(target.parent)))
    try:
        yield temporary
        os.replace(temporary, target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def task_prompt(package_root: Path, package_manifest: dict[str, Any]) -> str:
    world = _object(package_manifest.get("world"), "package world")
    template_path = world.get("episode_template_path")
    if not isinstance(template_path, str) or not template_path:
        raise HarnessAdapterError("package world has no episode_template_path")
    task = _read_object(package_root / template_path / "task.json", "package task")
    title = _text(task.get("title"), "task title")
    instructions = _text(task.get("instructions"), "task instructions")
    criteria = task.get("success_criteria")
    if (
        not isinstance(criteria, list)
        or not criteria
        or any(not isinstance(item, str) or not item.strip() for item in criteria)
    ):
        raise HarnessAdapterError("package task success_criteria must be non-empty strings")
    lines = [f"# {title}", "", instructions, "", "Success criteria:", ""]
    lines.extend(f"- {item}" for item in criteria)
    return "\n".join(lines) + "\n"


def write_adapter_manifest(
    *,
    root: Path,
    harness: str,
    harness_version: str,
    canonical_package_path: str,
    package_manifest: dict[str, Any],
) -> dict[str, Any]:
    package_root = root if canonical_package_path == "." else root / canonical_package_path
    package_manifest_path = package_root / WORLD_PACKAGE_MANIFEST
    world = _object(package_manifest.get("world"), "package world")
    files = {
        path.relative_to(root).as_posix(): sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != ADAPTER_MANIFEST
    }
    payload: dict[str, Any] = {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "harness": {"name": harness, "version": harness_version},
        "canonical_package": {
            "path": canonical_package_path,
            "manifest_sha256": sha256(package_manifest_path),
            "package_content_sha256": package_manifest["package_content_sha256"],
        },
        "world": {
            "id": world["id"],
            "bundle_version": world["bundle_version"],
            "episode_id": world["episode_id"],
        },
        "files": files,
    }
    (root / ADAPTER_MANIFEST).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def public_result(manifest: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    return {**manifest, "out_dir": str(out_dir.resolve())}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _read_object(path: Path, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HarnessAdapterError(f"invalid {description}: {path}") from exc
    return _object(payload, description)


def _object(value: object, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessAdapterError(f"{description} must be a JSON object")
    return value


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HarnessAdapterError(f"{description} must be a non-empty string")
    return value.strip()
