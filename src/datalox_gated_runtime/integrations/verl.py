"""Current-veRL ``ToolAgentLoop`` integration for isolated provider rollouts."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from datalox_gated_runtime.rollout.pool import RemoteRolloutLease, RolloutPoolClient
from datalox_gated_runtime.rollout.verl import (
    VerlRolloutContractError,
    VerlRolloutExecution,
    _bind_verl_rollout_execution,
    _reset_verl_rollout_execution,
    extract_verl_rollout_identity,
)

try:
    from verl.experimental.agent_loop.agent_loop import AgentLoopOutput
    from verl.experimental.agent_loop.tool_agent_loop import ToolAgentLoop
except ModuleNotFoundError as exc:  # pragma: no cover - exercised in an isolated import test
    if exc.name == "verl" or (exc.name and exc.name.startswith("verl.")):
        raise ModuleNotFoundError(
            "datalox_gated_runtime.integrations.verl requires the veRL training environment; "
            "veRL is intentionally not a Datalox core dependency"
        ) from exc
    raise


class DataloxToolAgentLoop(ToolAgentLoop):
    """Keep one Datalox rollout lease around the complete veRL tool loop."""

    def __init__(
        self,
        *args: Any,
        pool_socket_path: str,
        pool_token_path: str,
        task_image: str,
        **kwargs: Any,
    ) -> None:
        self._pool_socket_path = _absolute_path(pool_socket_path, "pool_socket_path")
        self._pool_token_path = _absolute_path(pool_token_path, "pool_token_path")
        self._task_image = _task_image(task_image)
        super().__init__(*args, **kwargs)

    async def run(self, sampling_params: dict[str, Any], **dataset_fields: Any) -> AgentLoopOutput:
        """Acquire per ``(uid, session_id)`` state and return veRL output unchanged."""

        identity = extract_verl_rollout_identity(dataset_fields)
        client = RolloutPoolClient(
            socket_path=self._pool_socket_path,
            token_path=self._pool_token_path,
        )
        lease: RemoteRolloutLease | None = None
        try:
            lease = await _acquire_lease(
                client,
                uid=identity.uid,
                session_id=identity.session_id,
                environment_seed=identity.environment_seed,
            )
            execution = VerlRolloutExecution(lease, self._task_image)
            context_token = _bind_verl_rollout_execution(execution)
            try:
                output = await super().run(sampling_params, **dataset_fields)
            finally:
                _reset_verl_rollout_execution(context_token)

            try:
                await _finalize_lease(lease)
            except BaseException:
                if lease.state == "active":
                    await _cancel_lease(lease)
                raise
            return output
        except BaseException:
            if lease is not None and lease.state == "active":
                await _cancel_lease(lease)
            raise
        finally:
            await client.aclose()


async def _cancel_lease(lease: RemoteRolloutLease) -> None:
    cleanup = asyncio.create_task(lease.cancel())
    try:
        await asyncio.shield(cleanup)
    except asyncio.CancelledError:
        await cleanup


async def _acquire_lease(
    client: RolloutPoolClient, *, uid: str, session_id: int, environment_seed: int
) -> RemoteRolloutLease:
    lease, cancellation = await _settle_if_cancelled(
        client.acquire(
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
        )
    )
    if cancellation is not None:
        await _cancel_lease(lease)
        raise cancellation
    return lease


async def _finalize_lease(lease: RemoteRolloutLease) -> None:
    _, cancellation = await _settle_if_cancelled(lease.finalize())
    if cancellation is not None:
        raise cancellation


async def _settle_if_cancelled(awaitable: Any) -> tuple[Any, asyncio.CancelledError | None]:
    """Keep ownership of a lifecycle request until its remote result is known."""

    operation = asyncio.create_task(awaitable)
    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            result = await asyncio.shield(operation)
            return result, cancellation
        except asyncio.CancelledError as exc:
            cancellation = cancellation or exc
            continue
        except BaseException:
            if cancellation is not None:
                raise cancellation
            raise


def _absolute_path(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise VerlRolloutContractError(
            f"verl_{field}_invalid", f"{field} must be a non-empty trimmed string"
        )
    path = Path(value)
    if not path.is_absolute():
        raise VerlRolloutContractError(f"verl_{field}_invalid", f"{field} must be an absolute path")
    return path


def _task_image(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(character.isspace() for character in value)
    ):
        raise VerlRolloutContractError(
            "verl_task_image_invalid", "task_image must be a non-empty Docker image reference"
        )
    return value


__all__ = ["DataloxToolAgentLoop"]
