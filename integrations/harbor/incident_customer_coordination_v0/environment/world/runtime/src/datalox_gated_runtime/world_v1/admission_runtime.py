from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.world_v1.admission import (
    AdmissionCallbacks,
    ParityOutcome,
    TrajectoryOutcome,
)
from datalox_gated_runtime.world_v1.backend import (
    WorldBundleBackend,
    initialize_world_bundle_session,
)
from datalox_gated_runtime.world_v1.bundle import validate_world_bundle
from datalox_gated_runtime.world_v1.contracts import ActorContext


def runtime_admission_callbacks() -> AdmissionCallbacks:
    """Return the concrete local runtime checks used by the admission CLI."""

    return AdmissionCallbacks(
        reset_fingerprint=_reset_fingerprint,
        run_trajectory=_run_trajectory,
        run_parity=_run_parity,
        export_session=_export_session,
    )


def _reset_fingerprint(bundle_root: Path, episode_id: str) -> str:
    with _fresh_backend(bundle_root, episode_id) as backend:
        return _fingerprint(backend.session.export())


def _run_trajectory(
    bundle_root: Path,
    trajectory: Mapping[str, Any],
) -> TrajectoryOutcome:
    episode_id = _required_string(trajectory, "episode_id")
    steps = trajectory.get("steps")
    if not isinstance(steps, list):
        raise ValueError("trajectory.steps must be a list")
    for index, step in enumerate(steps):
        if not isinstance(step, Mapping):
            raise ValueError(f"trajectory.steps[{index}] must be an object")
        _validate_step(step, name=f"trajectory.steps[{index}]")
    with _fresh_backend(bundle_root, episode_id) as backend:
        for step in steps:
            _execute_step(backend, step)
        result = backend.verify()
        payload = result.to_dict()
        if not isinstance(result.passed, bool):
            raise ValueError("world verifier passed must be a boolean")
        if not isinstance(payload, Mapping) or payload.get("passed") is not result.passed:
            raise ValueError("world verifier to_dict() must contain the same boolean passed value")
        failure_codes = payload.get("failure_codes", [])
        if not isinstance(failure_codes, list) or not all(
            isinstance(code, str) and code for code in failure_codes
        ):
            raise ValueError("world verifier failure_codes must be a list of strings")
        if len(set(failure_codes)) != len(failure_codes):
            raise ValueError("world verifier failure_codes must not contain duplicates")
        return TrajectoryOutcome(
            passed=bool(result.passed),
            failure_codes=tuple(failure_codes),
        )


def _run_parity(
    bundle_root: Path,
    parity_case: Mapping[str, Any],
) -> ParityOutcome:
    episode_id = _required_string(parity_case, "episode_id")
    http_step = parity_case.get("http_step")
    mcp_step = parity_case.get("mcp_step")
    if not isinstance(http_step, Mapping) or not isinstance(mcp_step, Mapping):
        raise ValueError("parity case requires http_step and mcp_step objects")
    _validate_step(http_step, name="parity.http_step", expected_surface="http")
    _validate_step(mcp_step, name="parity.mcp_step", expected_surface="mcp")

    with _fresh_backend(bundle_root, episode_id) as http_backend:
        http_response, http_operation = _execute_step_with_operation(http_backend, http_step)
        http_fingerprint = _surface_fingerprint(
            http_backend,
            http_response,
            operation_id=http_operation,
        )
    with _fresh_backend(bundle_root, episode_id) as mcp_backend:
        mcp_response, mcp_operation = _execute_step_with_operation(mcp_backend, mcp_step)
        mcp_fingerprint = _surface_fingerprint(
            mcp_backend,
            mcp_response,
            operation_id=mcp_operation,
        )
    return ParityOutcome(
        matched=http_fingerprint == mcp_fingerprint,
        http_fingerprint=http_fingerprint,
        mcp_fingerprint=mcp_fingerprint,
    )


def _export_session(bundle_root: Path) -> Mapping[str, Any]:
    bundle = validate_world_bundle(bundle_root)
    episode_id = bundle.episodes[0]["id"]
    with _fresh_backend(bundle_root, episode_id) as backend:
        payload = backend.session.export()
        required = {
            "episode_id",
            "simulation_time",
            "state",
            "events",
            "verifier_events",
            "artifacts",
            "scheduled_events",
            "conversations",
            "handoffs",
        }
        return {
            "ok": required.issubset(payload),
            "world_id": backend.world_id,
            "export_fingerprint": _fingerprint(payload),
        }


class _fresh_backend:
    def __init__(self, bundle_root: Path, episode_id: str) -> None:
        self.bundle_root = bundle_root
        self.episode_id = episode_id
        self._temporary: TemporaryDirectory[str] | None = None
        self._backend: WorldBundleBackend | None = None

    def __enter__(self) -> WorldBundleBackend:
        self._temporary = TemporaryDirectory(prefix="datalox-world-admission-")
        run_dir = Path(self._temporary.name)
        try:
            initialize_world_bundle_session(
                source_bundle_dir=self.bundle_root,
                run_dir=run_dir,
                episode_id=self.episode_id,
            )
            self._backend = WorldBundleBackend(run_dir=run_dir)
            return self._backend
        except BaseException:
            self._temporary.cleanup()
            self._temporary = None
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._backend is not None:
            self._backend.close()
        if self._temporary is not None:
            self._temporary.cleanup()


def _execute_step(
    backend: WorldBundleBackend,
    step: Mapping[str, Any],
):
    response, _ = _execute_step_with_operation(backend, step)
    return response


def _execute_step_with_operation(
    backend: WorldBundleBackend,
    step: Mapping[str, Any],
) -> tuple[Any, str | None]:
    surface = _required_string(step, "surface")
    actor_role = _required_string(step, "actor_role")
    actor = ActorContext(
        actor_id=str(step.get("actor_id") or f"admission-{actor_role}"),
        role=actor_role,
    )
    if surface == "http":
        request = CallRequest(
            method=_required_string(step, "method"),
            path=_required_string(step, "path"),
            query=_string_mapping(step.get("query", {}), "query"),
            body=step.get("body"),
            headers={
                "x-datalox-actor-id": actor.actor_id,
                "x-datalox-actor-role": actor.role,
            },
        )
    elif surface == "mcp":
        tool_name = _required_string(step, "tool_name")
        arguments = step.get("arguments", {})
        if not isinstance(arguments, Mapping):
            raise ValueError("MCP step arguments must be an object")
        request = backend.request_for_tool(tool_name, dict(arguments), actor=actor)
    else:
        raise ValueError(f"unsupported trajectory surface: {surface}")
    response = backend.handle(request)
    if response is None:
        raise ValueError(
            f"world did not handle trajectory request: {request.normalized_method()} {request.path}"
        )
    operation_id = backend.bundle.implementation.tool_for_request(request)
    if operation_id is None:
        operation_id = response.operation_id
    return response, operation_id


def _validate_step(
    step: Mapping[str, Any],
    *,
    name: str,
    expected_surface: str | None = None,
) -> None:
    surface = _required_string(step, "surface")
    if surface not in {"http", "mcp"}:
        raise ValueError(f"{name}.surface is unsupported: {surface}")
    if expected_surface is not None and surface != expected_surface:
        raise ValueError(f"{name}.surface must be {expected_surface}")
    _required_string(step, "actor_role")
    if "actor_id" in step:
        _required_string(step, "actor_id")
    if surface == "http":
        _required_string(step, "method")
        _required_string(step, "path")
        _string_mapping(step.get("query", {}), f"{name}.query")
        _validate_json_value(step.get("body"), f"{name}.body")
        return
    _required_string(step, "tool_name")
    arguments = step.get("arguments", {})
    if not isinstance(arguments, Mapping):
        raise ValueError(f"{name}.arguments must be an object")
    _validate_json_value(dict(arguments), f"{name}.arguments")


def _surface_fingerprint(
    backend: WorldBundleBackend,
    response: Any,
    *,
    operation_id: str | None,
) -> str:
    export = backend.session.export()
    return _fingerprint(
        {
            "response": {
                "status_code": response.status_code,
                "body": response.body,
                "decision_kind": response.decision_kind,
                "reason_code": response.reason_code,
                "operation_id": operation_id,
            },
            "state": export["state"],
            "artifacts": export["artifacts"],
            "scheduled_events": export["scheduled_events"],
            "conversations": export["conversations"],
            "handoffs": export["handoffs"],
        }
    )


def _fingerprint(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _required_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _string_mapping(value: Any, name: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise ValueError(f"{name} must be an object of string values")
    return dict(value)


def _validate_json_value(value: Any, name: str) -> None:
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite JSON value: {exc}") from exc
