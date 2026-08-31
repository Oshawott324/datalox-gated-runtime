"""veRL rollout identity and context-local provider execution.

This module deliberately has no dependency on :mod:`verl`.  The concrete
``ToolAgentLoop`` adapter lives in ``datalox_gated_runtime.integrations.verl``.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any

from datalox_gated_runtime.rollout.pool import RemoteRolloutLease, RolloutExecResult


@dataclass
class VerlRolloutContractError(ValueError):
    """Stable failure for malformed veRL dataset fields or missing context."""

    code: str
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class VerlRolloutIdentity:
    """Exact identity supplied by current veRL to ``AgentLoopBase.run``."""

    uid: str
    session_id: int
    environment_seed: int


@dataclass(frozen=True)
class VerlRolloutExecution:
    """Context-local execution handle with a trusted, fixed task image."""

    _lease: RemoteRolloutLease
    _task_image: str

    async def exec(self, command: tuple[str, ...]) -> RolloutExecResult:
        """Execute argv inside the current rollout's isolated task container."""

        if not isinstance(command, tuple) or not command:
            raise VerlRolloutContractError(
                "verl_command_invalid", "command must be a non-empty tuple of argv strings"
            )
        if any(not isinstance(item, str) or not item or "\x00" in item for item in command):
            raise VerlRolloutContractError(
                "verl_command_invalid",
                "every command item must be a non-empty string without NUL bytes",
            )
        return await self._lease.exec(task_image=self._task_image, command=command)


_CURRENT_EXECUTION: ContextVar[VerlRolloutExecution | None] = ContextVar(
    "datalox_verl_rollout_execution", default=None
)


def extract_verl_rollout_identity(dataset_fields: dict[str, Any]) -> VerlRolloutIdentity:
    """Read the current veRL V1 identity without deriving or repairing values."""

    if not isinstance(dataset_fields, dict):
        raise VerlRolloutContractError(
            "verl_dataset_fields_invalid", "AgentLoopBase.run keyword fields must be a dictionary"
        )

    uid = dataset_fields.get("uid")
    if not isinstance(uid, str) or not uid or uid.strip() != uid or len(uid) > 256:
        raise VerlRolloutContractError(
            "verl_uid_invalid", "uid must be a non-empty trimmed string of at most 256 characters"
        )

    session_id = dataset_fields.get("session_id")
    if not _is_non_negative_int(session_id):
        raise VerlRolloutContractError(
            "verl_session_id_invalid", "session_id must be a non-negative integer"
        )

    extra_info = dataset_fields.get("extra_info")
    if not isinstance(extra_info, dict):
        raise VerlRolloutContractError("verl_extra_info_invalid", "extra_info must be a dictionary")
    datalox = extra_info.get("datalox")
    if not isinstance(datalox, dict):
        raise VerlRolloutContractError(
            "verl_datalox_metadata_invalid", "extra_info.datalox must be a dictionary"
        )
    if not all(isinstance(key, str) for key in datalox):
        raise VerlRolloutContractError(
            "verl_datalox_metadata_invalid",
            "extra_info.datalox field names must be strings",
        )
    if set(datalox) != {"seed"}:
        missing = sorted({"seed"} - set(datalox))
        unknown = sorted(set(datalox) - {"seed"})
        raise VerlRolloutContractError(
            "verl_datalox_metadata_invalid",
            f"extra_info.datalox fields are invalid; missing={missing!r}, unknown={unknown!r}",
        )
    seed = datalox["seed"]
    if not _is_non_negative_int(seed):
        raise VerlRolloutContractError(
            "verl_environment_seed_invalid",
            "extra_info.datalox.seed must be a non-negative integer",
        )

    return VerlRolloutIdentity(
        uid=uid,
        session_id=session_id,
        environment_seed=seed,
    )


def current_verl_rollout_execution() -> VerlRolloutExecution:
    """Return the execution handle inherited by child asyncio tool tasks."""

    execution = _CURRENT_EXECUTION.get()
    if execution is None:
        raise VerlRolloutContractError(
            "verl_rollout_context_missing",
            "provider tool execution is outside an active Datalox veRL rollout",
        )
    return execution


def _bind_verl_rollout_execution(execution: VerlRolloutExecution) -> Token:
    return _CURRENT_EXECUTION.set(execution)


def _reset_verl_rollout_execution(token: Token) -> None:
    _CURRENT_EXECUTION.reset(token)


def _is_non_negative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


__all__ = [
    "VerlRolloutContractError",
    "VerlRolloutExecution",
    "VerlRolloutIdentity",
    "current_verl_rollout_execution",
    "extract_verl_rollout_identity",
]
