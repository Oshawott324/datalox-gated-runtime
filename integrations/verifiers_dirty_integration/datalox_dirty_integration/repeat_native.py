"""One repeated-experiment slot executed by the pinned native Verifiers loop.

The programmatic evaluator is intentional: Verifiers 0.3.1's ``vf-eval`` CLI
does not expose its model client's retry and request-timeout settings. This
adapter configures that same evaluator directly instead of replacing its loop.
Its native Responses client preserves reasoning output items across stateless
tool turns, so GPT-5.6 Sol keeps the requested reasoning effort.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datalox_dirty_integration.repeat_contract import ExperimentConfig, RolloutSlot


VERIFIERS_VERSION = "0.3.1"
NATIVE_STATE_COLUMNS = (
    "trajectory_id",
    "trajectory",
    "sampling_args",
    "timed_out",
    "prompt_too_long",
)


def native_sampling_args(config: ExperimentConfig) -> dict[str, Any]:
    """Return API-supported controls; unset controls stay absent on the wire."""

    sampling: dict[str, Any] = {
        "reasoning": {"effort": config.model.reasoning_effort},
        "max_output_tokens": config.model.max_completion_tokens,
        "parallel_tool_calls": config.model.parallel_tool_calls,
        "store": False,
        "include": ["reasoning.encrypted_content"],
        "service_tier": "default",
    }
    if config.model.temperature is not None:
        sampling["temperature"] = config.model.temperature
    return sampling


def run_native_slot(
    config: ExperimentConfig,
    slot: RolloutSlot,
    output: Path,
) -> None:
    """Run one real model-selected trajectory and retain native output bytes.

    The caller owns experiment validation, credential checks, scheduling, spend
    reservations and artifact review. This function neither retries a slot nor
    substitutes a scripted trajectory. A failed call keeps any native partial
    output and controller cleanup evidence for the caller to classify.
    """

    if importlib.metadata.version("verifiers") != VERIFIERS_VERSION:
        raise RuntimeError(f"repeat experiments require verifiers=={VERIFIERS_VERSION}")

    import verifiers as vf
    from verifiers.legacy.types import ClientConfig

    from datalox_dirty_integration.repeat_budget import BudgetedOpenAIResponsesClient

    native_dir = output / "native"
    evidence_dir = output / "evidence"
    if native_dir.exists() or evidence_dir.exists():
        raise FileExistsError("native slot output must be fresh")
    output.mkdir(parents=True, exist_ok=True)
    native_dir.mkdir()
    evidence_dir.mkdir()

    client_config = ClientConfig(
        client_type="openai_responses",
        api_base_url=config.model.endpoint,
        api_key_var=config.model.api_key_env,
        max_retries=config.client_retries,
        timeout=config.model.request_timeout_seconds,
        connect_timeout=config.model.connect_timeout_seconds,
        max_connections=1,
        max_keepalive_connections=1,
        extra_headers={},
        extra_headers_from_state={},
        endpoint_configs=[],
    )
    environment_args = {
        "profile": slot.profile,
        "intervention_seed": slot.seed,
        "intervention_enabled": True,
        "evidence_dir": str(evidence_dir.resolve()),
        "num_tasks": 1,
        "max_turns": config.max_turns,
        "timeout_seconds": config.per_rollout_timeout_seconds,
    }
    environment = vf.load_environment("datalox-dirty-integration", **environment_args)
    sampling = native_sampling_args(config)
    effective_sampling = {**environment.sampling_args, **sampling}
    execution = {
        "schema_version": "datalox_verifiers_native_execution_v1",
        "verifiers_version": VERIFIERS_VERSION,
        "entry_point": "verifiers.legacy.envs.environment.Environment.evaluate",
        "model": config.model.model,
        "client": client_config.model_dump(mode="json"),
        "sampling_args": effective_sampling,
        "environment_args": environment_args,
        "state_columns": list(NATIVE_STATE_COLUMNS),
        "num_examples": 1,
        "rollouts_per_example": 1,
        "max_concurrent": config.concurrency,
        "max_retries": config.evaluator_retries,
        "shuffle": False,
        "save_results": True,
        "push_to_hf_hub": False,
        "backend_fingerprint_availability": "not_retained_by_verifiers_0.3.1_responses_client",
        "native_metadata_base_url_availability": "not_retained_for_caller_owned_client",
    }
    with (native_dir / "execution.json").open("x", encoding="utf-8") as handle:
        json.dump(execution, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")

    # Verifiers saves results.jsonl and metadata.json itself. Do not serialize,
    # normalize, reorder, repair, or replace the returned rollout object here.
    async def evaluate() -> None:
        client = BudgetedOpenAIResponsesClient(
            client_config,
            budget_usd=config.per_rollout_reservation_usd,
            ledger_path=native_dir / "budget.json",
        )
        try:
            await environment.evaluate(
                client=client,
                model=config.model.model,
                sampling_args=sampling,
                num_examples=1,
                rollouts_per_example=1,
                max_concurrent=config.concurrency,
                results_path=native_dir,
                state_columns=list(NATIVE_STATE_COLUMNS),
                save_results=True,
                push_to_hf_hub=False,
                max_retries=config.evaluator_retries,
                shuffle=False,
            )
        finally:
            # Native evaluate closes clients created from ClientConfig; passed
            # clients belong to the caller and close on this same event loop.
            await client.close()

    asyncio.run(evaluate())
