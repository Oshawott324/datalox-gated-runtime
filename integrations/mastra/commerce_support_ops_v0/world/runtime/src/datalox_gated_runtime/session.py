from __future__ import annotations

import json
import os
import shutil
import shlex
from dataclasses import MISSING, asdict, fields
from pathlib import Path
from typing import Any
from uuid import uuid4

from datalox_gated_runtime.audit import run_config_audit
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import load_events, shadow_state_from_events
from datalox_gated_runtime.models import RunExport, SessionManifest
from datalox_gated_runtime.world_backend import (
    export_world,
    initialize_world,
    verify_world,
    world_task,
)


SOURCE_EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples"
RUNTIME_ARTIFACT_NAMES = frozenset(
    {
        "session_manifest.json",
        "ledger.jsonl",
        "run_export.json",
        "audit.json",
    }
)


class SessionCreationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _resolve_example_dir(example: str) -> Path:
    candidate_dirs: list[Path] = []
    env_dir = os.getenv("DATALOX_GATE_EXAMPLES_DIR")
    if env_dir:
        candidate_dirs.append(Path(env_dir))
    candidate_dirs.append(SOURCE_EXAMPLES_DIR)
    candidate_dirs.append(Path.cwd() / "examples")

    for examples_dir in candidate_dirs:
        path = examples_dir / example
        if path.is_dir():
            return path

    raise ValueError(f"Unknown example: {example}")


def create_session(
    *,
    example: str,
    out_dir: Path,
    http_port: int,
    seed: int | None = None,
) -> SessionManifest:
    example_dir = _resolve_example_dir(example)
    task_source = example_dir / "task.json"
    config_source = example_dir / "gate_config.json"
    if not task_source.exists() or not config_source.exists():
        raise ValueError(f"example is incomplete: {example}")
    selected_config = _config_for_session(
        config_source=config_source,
        example_dir=example_dir,
        seed=seed,
    )

    run_dir = out_dir.resolve()
    existing_artifacts = sorted(
        artifact_name
        for artifact_name in RUNTIME_ARTIFACT_NAMES
        if (run_dir / artifact_name).exists()
    )
    if existing_artifacts:
        raise ValueError(
            "output directory already contains runtime artifacts: " + ", ".join(existing_artifacts)
        )

    run_dir.mkdir(parents=True, exist_ok=True)

    task_path = run_dir / "task.json"
    config_path = run_dir / "gate_config.json"
    shutil.copyfile(task_source, task_path)
    if selected_config is None:
        shutil.copyfile(config_source, config_path)
    else:
        config_path.write_text(
            json.dumps(selected_config, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    config = load_gate_config(config_path)
    if config.world is not None:
        initialize_world(run_dir=run_dir, config=config.world, source_dir=example_dir)
        selected_task = world_task(run_dir=run_dir, config=config.world)
        if selected_task is not None:
            task_path.write_text(
                json.dumps(asdict(selected_task), indent=2, sort_keys=True),
                encoding="utf-8",
            )

    run_dir_quoted = shlex.quote(str(run_dir))
    manifest = SessionManifest(
        session_id=f"sess_{uuid4().hex}",
        run_dir=str(run_dir),
        task_path=str(task_path),
        gate_config_path=str(config_path),
        ledger_path=str(run_dir / "ledger.jsonl"),
        run_export_path=str(run_dir / "run_export.json"),
        audit_path=str(run_dir / "audit.json"),
        http_base_url=f"http://127.0.0.1:{http_port}",
        commands={
            "serve": f"datalox-gate serve --run {run_dir_quoted} --port {http_port}",
            "check": f"datalox-gate session check --run {run_dir_quoted} --json",
            "finalize": f"datalox-gate session finalize --run {run_dir_quoted} --json",
            "mcp": f"datalox-gate mcp --run {run_dir_quoted}",
        },
        expected_surfaces=["http", "mcp"],
    )

    (run_dir / "session_manifest.json").write_text(
        json.dumps(asdict(manifest), indent=2),
        encoding="utf-8",
    )
    return manifest


def _config_for_session(
    *,
    config_source: Path,
    example_dir: Path,
    seed: int | None,
) -> dict | None:
    if seed is not None and (type(seed) is not int or seed < 0):
        raise SessionCreationError("invalid_seed", "--seed must be a non-negative integer.")
    bundle_manifest = example_dir / "world" / "manifest.json"
    if seed is None and not bundle_manifest.is_file():
        return None
    try:
        payload = json.loads(config_source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid gate config json") from exc
    if not isinstance(payload, dict):
        raise ValueError("gate config must be an object")

    world = payload.get("world")
    if bundle_manifest.is_file():
        from datalox_gated_runtime.world_v1.bundle import validate_world_bundle

        validate_world_bundle(example_dir)
        selected_seed = seed if seed is not None else 0
        if world is None:
            payload["world"] = {"kind": "world_bundle_v1", "seed": selected_seed}
            return payload
        if not isinstance(world, dict) or world.get("kind") != "world_bundle_v1":
            raise SessionCreationError(
                "world_bundle_config_conflict",
                "An admitted world bundle requires a world_bundle_v1 gate configuration.",
            )
        if seed is None:
            return None
        world["seed"] = selected_seed
        return payload

    if not isinstance(world, dict) or type(world.get("seed")) is not int:
        raise SessionCreationError(
            "seed_not_supported",
            "--seed requires an environment with a world seed.",
        )
    assert seed is not None
    world["seed"] = seed
    return payload


def load_session_manifest(run_dir: Path) -> SessionManifest:
    manifest_path = Path(run_dir) / "session_manifest.json"
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid session manifest json") from exc

    if not isinstance(raw, dict):
        raise ValueError("session manifest must be an object")

    required_fields = [
        field.name
        for field in fields(SessionManifest)
        if field.default is MISSING and field.default_factory is MISSING
    ]
    for field_name in required_fields:
        if field_name not in raw:
            raise ValueError(f"missing required field {field_name}")

    known_fields = {field.name for field in fields(SessionManifest)}
    unknown = [field_name for field_name in raw.keys() if field_name not in known_fields]
    if unknown:
        raise ValueError(f"unknown fields for session manifest: {', '.join(unknown)}")

    return SessionManifest(**raw)


def finalize_session(run_dir: Path) -> dict[str, Any]:
    """Persist run export and post-run audit for one isolated session."""

    run_dir = Path(run_dir)
    gate_config = load_gate_config(run_dir / "gate_config.json")
    events = load_events(run_dir / "ledger.jsonl")
    shadow_state = shadow_state_from_events(events)
    run_export = RunExport.from_parts(events=events, shadow_state=shadow_state)
    run_export_payload = asdict(run_export)
    world_audit = None
    world_id = None

    if gate_config.world is not None:
        world_export = export_world(run_dir=run_dir, config=gate_config.world)
        world_audit = verify_world(run_dir=run_dir, config=gate_config.world)
        if world_export is not None:
            world_id = world_export.get("world_id")
            world_export["verification"] = world_audit.to_dict()
            run_export_payload["world"] = world_export

    (run_dir / "run_export.json").write_text(
        json.dumps(run_export_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    audit_payload: dict[str, Any] = asdict(run_config_audit(run_export, gate_config.audit_rules))
    if gate_config.world is not None:
        if world_audit is None:
            world_audit = verify_world(run_dir=run_dir, config=gate_config.world)
        audit_payload = _combined_audit_payload(
            config_payload=audit_payload,
            world_payload=world_audit.to_dict(),
            world_id=(world_id if isinstance(world_id, str) and world_id else gate_config.world.id),
        )

    (run_dir / "audit.json").write_text(
        json.dumps(audit_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return audit_payload


def _combined_audit_payload(
    *,
    config_payload: dict[str, Any],
    world_payload: dict[str, Any],
    world_id: str,
) -> dict[str, Any]:
    checks = dict(config_payload.get("checks", {}))
    world_checks = world_payload.get("checks", [])
    if not isinstance(world_checks, list):
        world_checks = []
    for check in world_checks:
        if not isinstance(check, dict):
            continue
        check_id = check.get("name", check.get("code"))
        passed = check.get("ok", check.get("passed"))
        if not isinstance(check_id, str) or not check_id or not isinstance(passed, bool):
            continue
        checks[f"world.{world_id}.{check_id}"] = passed

    failure_codes = list(config_payload.get("failure_codes", []))
    for check in world_checks:
        if not isinstance(check, dict):
            continue
        check_id = check.get("name", check.get("code"))
        passed = check.get("ok", check.get("passed"))
        if isinstance(check_id, str) and passed is False:
            failure_codes.append(f"world.{world_id}.{check_id}")

    return {
        "passed": bool(config_payload.get("passed")) and bool(world_payload.get("passed")),
        "verifier_type": "combined_post_run_audit",
        "checks": checks,
        "failure_codes": failure_codes,
        "verifiers": {
            "config": config_payload,
            "world": world_payload,
        },
    }
