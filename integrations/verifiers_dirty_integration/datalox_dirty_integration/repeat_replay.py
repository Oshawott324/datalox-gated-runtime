"""Replay reviewed actions through the real controller without model inference.

This is a recorded-action counterfactual, not a new agent rollout. An uncapped
replay must first reproduce every original observation and final provider state.
The capped replay dispatches the same requested actions until the controller
rejects one. It never creates, edits, or grades a truncated copy of an old trace.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

import verifiers as vf
from verifiers.legacy.types import RolloutTiming

from datalox_dirty_integration.audit import canonical_sha256
from datalox_dirty_integration.environment import load_environment
from datalox_dirty_integration.episode import sha256_file
from datalox_dirty_integration.repeat_arms import BUDGET_STOP
from datalox_dirty_integration.repeat_contract import write_json_exclusive
from datalox_dirty_integration.repeat_evidence import RepeatEvidenceError, parse_json
from datalox_dirty_integration.repeat_public import verify_public_bundle
from datalox_dirty_integration.scoring import (
    EvaluationOracle,
    request_discipline_report_for_episode,
    verify_task_for_episode,
)


async def replay_actions(row: dict[str, Any], limit: int | None) -> dict[str, Any]:
    """Re-execute a trusted tool projection, with fresh state and original batches."""
    environment = load_environment(
        profile=row["slot"]["profile"],
        intervention_seed=row["slot"]["seed"],
        intervention_enabled=True,
        num_tasks=1,
        call_budget_controller=True,
        provider_call_budget=limit,
    )
    # Tool-only execution still uses the native cleanup lifecycle. There are
    # zero model trajectory steps; timing is required by native cleanup.
    state = {
        "trajectory_id": "recorded-action-replay",
        "stop_condition": "recorded_actions_exhausted",
        "trajectory": [],
        "timing": RolloutTiming(),
    }
    await environment.setup_state(state)
    observations = []
    try:
        for message in row["tool_transcript"]:
            if message["role"] != "assistant" or not message.get("tool_calls"):
                continue
            assistant = vf.AssistantMessage(
                role="assistant",
                tool_calls=[json.loads(call) for call in message["tool_calls"]],
            )
            delivered = await environment.env_response([assistant], state)
            observations.extend(
                {"role": "tool", "tool_call_id": item.tool_call_id, "content": item.content}
                for item in delivered
            )
            if await environment.harness_call_budget_exhausted(state):
                state["stop_condition"] = BUDGET_STOP
                break
        episode = environment._episodes[state["trajectory_id"]]
        exported = episode.export()
        original = row["episode_export"]
        for key in original:
            if (
                key.startswith("provider_")
                or key
                in {
                    "operation_claims_sha256",
                    "operation_contract_sha256",
                    "initial_state_fingerprint",
                }
            ) and exported[key] != original[key]:
                raise RepeatEvidenceError(f"replay provider binding differs: {key}")
        for key in ("policy_id", "policy_version", "policy_sha256", "seed", "enabled"):
            if exported["intervention"][key] != original["intervention"][key]:
                raise RepeatEvidenceError(f"replay intervention binding differs: {key}")
        original_tools = [item for item in row["tool_transcript"] if item["role"] == "tool"]
        if observations != original_tools[: len(observations)]:
            raise RepeatEvidenceError("replayed tool observations differ from the recorded prefix")
        if (
            exported["delivered_calls"]
            != original["delivered_calls"][: len(exported["delivered_calls"])]
        ):
            raise RepeatEvidenceError("replayed provider effects differ from the recorded prefix")
        same_state = (
            exported["provider"]["provider_state"] == original["provider"]["provider_state"]
        )
        # The provider export also contains its event history. Omitting a read
        # changes that history even when the actual carts/catalog are identical.
        same_data = (
            exported["provider"]["provider_state"]["state"]
            == original["provider"]["provider_state"]["state"]
        )
        verification = {
            "task_correctness": verify_task_for_episode(episode, EvaluationOracle()).to_dict(),
            "request_discipline": request_discipline_report_for_episode(
                episode, EvaluationOracle()
            ).to_dict(),
        }
        if limit is None and (
            len(observations) != len(original_tools)
            or not same_state
            or verification != row["verification"]
        ):
            raise RepeatEvidenceError("uncapped replay differs from the original outcome")
        return {
            "limit": limit,
            "executed_provider_calls": len(exported["delivered_calls"]),
            "verification": verification,
            "call_budget": environment._controller_evidence(state, exported),
            "same_final_provider_state_as_original": same_state,
            "same_final_provider_data_as_original": same_data,
            "provider_data_sha256": canonical_sha256(
                exported["provider"]["provider_state"]["state"]
            ),
            "provider_state_sha256": canonical_sha256(exported["provider"]["provider_state"]),
            "delivered_calls_sha256": canonical_sha256(exported["delivered_calls"]),
            "recorded_observation_prefix_matches": True,
        }
    finally:
        await environment.cleanup(state)


async def replay_bundle(source: Path, limit: int) -> dict[str, Any]:
    verified = verify_public_bundle(source)
    rows = [parse_json(line) for line in (source / "rollouts.jsonl").read_text().splitlines()]
    results = []
    for row in rows:
        baseline = await replay_actions(row, None)
        capped = await replay_actions(row, limit)
        results.append({"slot": row["slot"], "uncapped": baseline, "capped": capped})
    return {
        "schema_version": "datalox_recorded_action_counterfactual_v1",
        "scope": "recorded actions re-executed locally; no new model decisions or inference",
        "source_verification": verified,
        "source_rows_sha256": sha256_file(source / "rollouts.jsonl"),
        "provider_call_limit": limit,
        "runs": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, required=True, help="Reviewed public evidence bundle"
    )
    parser.add_argument("--limit", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.limit <= 0:
        parser.error("limit must be a positive integer")
    report = asyncio.run(replay_bundle(args.source, args.limit))
    write_json_exclusive(args.output, report)
    print(json.dumps({"replayed": len(report["runs"]), "model_requests": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
