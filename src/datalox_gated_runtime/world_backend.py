from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import (
    CallRequest,
    ResponseCaseStateWorldConfig,
    TaskBrief,
    WorldBundleV1Config,
    WorldConfig,
    WorldConfigValue,
)


@dataclass(frozen=True)
class WorldResponse:
    status_code: int
    body: dict[str, Any] | list[Any] | str | None
    is_mutation: bool
    world_id: str = ""
    operation_id: str | None = None
    decision_kind: Literal["replay", "shadow_write", "deny", "miss"] | None = None
    reason_code: str | None = None
    message: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


class WorldBackend(Protocol):
    world_id: str

    def handle(self, request: CallRequest) -> WorldResponse | None: ...


class WorldVerifierResult(Protocol):
    passed: bool

    def to_dict(self) -> dict[str, Any]: ...


def create_world_backend(
    *,
    run_dir: Path,
    config: WorldConfigValue | None,
    actor_context: object | None = None,
) -> WorldBackend | None:
    if config is None:
        return None
    if isinstance(config, WorldConfig):
        from datalox_gated_runtime.worlds.billing_support_v0 import BillingSupportWorldBackend

        return BillingSupportWorldBackend(run_dir=run_dir, config=config)
    if isinstance(config, ResponseCaseStateWorldConfig):
        from datalox_gated_runtime.worlds.response_case_state_v0 import (
            ResponseCaseStateWorldBackend,
        )

        return ResponseCaseStateWorldBackend(run_dir=run_dir, config=config)
    if isinstance(config, WorldBundleV1Config):
        from datalox_gated_runtime.world_v1.backend import WorldBundleBackend
        from datalox_gated_runtime.world_v1.contracts import ActorContext

        if actor_context is not None and not isinstance(actor_context, ActorContext):
            raise TypeError("actor_context must be an ActorContext")
        return WorldBundleBackend(run_dir=run_dir, configured_actor=actor_context)
    raise ValueError(f"unsupported world config: {type(config).__name__}")


def initialize_world(
    *,
    run_dir: Path,
    config: WorldConfigValue,
    source_dir: Path,
) -> None:
    if isinstance(config, WorldConfig):
        from datalox_gated_runtime.worlds.billing_support_v0 import initialize_world_state

        initialize_world_state(run_dir=run_dir, config=config)
        return
    if isinstance(config, ResponseCaseStateWorldConfig):
        from datalox_gated_runtime.worlds.response_case_state_v0 import initialize_world_state

        initialize_world_state(run_dir=run_dir, config=config, source_dir=source_dir)
        return
    if isinstance(config, WorldBundleV1Config):
        from datalox_gated_runtime.world_v1.backend import initialize_world_bundle_session
        from datalox_gated_runtime.world_v1.bundle import validate_world_bundle

        bundle = validate_world_bundle(source_dir)
        episode = bundle.episodes[config.seed % len(bundle.episodes)]
        initialize_world_bundle_session(
            source_bundle_dir=source_dir,
            run_dir=run_dir,
            episode_id=episode["id"],
        )
        return
    raise ValueError(f"unsupported world config: {type(config).__name__}")


def verify_world(
    *,
    run_dir: Path,
    config: WorldConfigValue,
    ledger: SessionLedger | None = None,
) -> WorldVerifierResult:
    if isinstance(config, WorldConfig):
        from datalox_gated_runtime.worlds.billing_support_v0 import verify_run

        return verify_run(run_dir)
    if isinstance(config, ResponseCaseStateWorldConfig):
        from datalox_gated_runtime.worlds.response_case_state_v0 import verify_run

        return verify_run(run_dir, ledger=ledger)
    if isinstance(config, WorldBundleV1Config):
        from datalox_gated_runtime.world_v1.backend import WorldBundleBackend

        backend = WorldBundleBackend(run_dir=run_dir)
        try:
            return backend.verify()
        finally:
            backend.close()
    raise ValueError(f"unsupported world config: {type(config).__name__}")


def world_task(*, run_dir: Path, config: WorldConfigValue) -> TaskBrief | None:
    if isinstance(config, WorldConfig):
        return None
    if isinstance(config, ResponseCaseStateWorldConfig):
        from datalox_gated_runtime.worlds.response_case_state_v0.state import load_selected_task

        return load_selected_task(run_dir)
    if isinstance(config, WorldBundleV1Config):
        from datalox_gated_runtime.world_v1.backend import WorldBundleBackend

        backend = WorldBundleBackend(run_dir=run_dir)
        try:
            return backend.task()
        finally:
            backend.close()
    raise ValueError(f"unsupported world config: {type(config).__name__}")


def export_world(*, run_dir: Path, config: WorldConfigValue) -> dict[str, Any] | None:
    if not isinstance(config, WorldBundleV1Config):
        return None
    from datalox_gated_runtime.world_v1.backend import (
        WorldBundleBackend,
        installed_world_bundle_ref,
    )

    backend = WorldBundleBackend(run_dir=run_dir)
    try:
        return {
            "schema_version": "datalox_world_run_v1",
            "world_id": backend.world_id,
            "bundle": installed_world_bundle_ref(run_dir),
            **backend.session.export(),
        }
    finally:
        backend.close()
