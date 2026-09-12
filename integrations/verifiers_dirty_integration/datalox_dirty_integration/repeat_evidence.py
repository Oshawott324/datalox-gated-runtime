"""Join native Verifiers outputs to controller evidence without changing either."""

from __future__ import annotations

import asyncio
import hashlib
import json
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from datalox_dirty_integration.audit import audit_episode_export, canonical_sha256
from datalox_dirty_integration.contract import (
    ADD_LINE_ITEM_OPERATION,
    CREATE_CART_OPERATION,
    DELETE_LINE_ITEM_OPERATION,
    LIST_PRODUCTS_OPERATION,
    RETRIEVE_CART_OPERATION,
    UPDATE_LINE_ITEM_OPERATION,
)
from datalox_dirty_integration.episode import sha256_file


class RepeatEvidenceError(ValueError):
    """A slot cannot be used as audited model-rollout evidence."""


_TOOL_ARGUMENTS = {
    "list_products": ("offset", "limit"),
    "create_cart": ("email", "region_id"),
    "get_cart": ("cart_id",),
    "add_line_item": ("cart_id", "variant_id", "quantity"),
    "update_line_item": ("cart_id", "line_item_id", "quantity"),
    "delete_line_item": ("cart_id", "line_item_id"),
}


def _provably_invalid_tool_call(tool: dict[str, Any]) -> bool:
    name = tool["name"]
    if name not in _TOOL_ARGUMENTS:
        return True
    try:
        args = parse_json(tool["arguments"])
    except json.JSONDecodeError:
        return True
    if not isinstance(args, dict):
        return True
    fields = set(_TOOL_ARGUMENTS[name])
    if set(args) - fields or (name != "list_products" and fields - set(args)):
        return True
    return any(
        type(value) is not (int if key in {"offset", "limit", "quantity"} else str)
        for key, value in args.items()
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RepeatEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text: str) -> Any:
    def invalid(value: str) -> None:
        raise RepeatEvidenceError(f"nonfinite JSON: {value}")

    return json.loads(text, object_pairs_hook=_pairs, parse_constant=invalid)


def read_json(path: Path) -> Any:
    if path.is_symlink():
        raise RepeatEvidenceError(f"symlink is outside the evidence contract: {path.name}")
    return parse_json(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def _equal(left: Any, right: Any, label: str) -> None:
    if canonical_sha256(left) != canonical_sha256(right):
        raise RepeatEvidenceError(f"{label} mismatch")


def _audit_provider_calls(
    provider: dict[str, Any], intervention: dict[str, Any], calls: list[dict[str, Any]]
) -> None:
    ledger = provider["call_evidence"]["events"]
    index = 0
    for call in calls:
        read_index = call["intervention_logical_request_index"]
        event = intervention["events"][read_index - 1] if read_index is not None else None
        if event is not None and not event["base"]["invoked"]:
            continue
        if index >= len(ledger):
            raise RepeatEvidenceError("provider call has no base ledger entry")
        base = ledger[index]
        if event is not None:
            _equal(base["event_id"], event["base"]["event_id"], "ordered base receipt")
        _equal(call["operation_id"], base["request"]["operation_id"], "base operation")
        _equal(
            call["request"], {key: base["request"][key] for key in call["request"]}, "base request"
        )
        if event is None:
            _equal(
                call["observation"],
                {
                    "status_code": base["response_status_code"],
                    "headers": {},
                    "body": base["response_body"],
                },
                "direct provider response",
            )
        index += 1
    if index != len(ledger):
        raise RepeatEvidenceError("base ledger contains unaccounted provider calls")


def _audit_native_trajectory(native: dict[str, Any]) -> None:
    # These are the pinned framework's own serialization operations. They affect
    # model-message encoding only; provider observations are compared separately.
    from verifiers.legacy.types import Response
    from verifiers.legacy.utils.message_utils import (
        sanitize_tool_calls,
        serialize_messages_for_output,
    )
    from verifiers.legacy.utils.response_utils import parse_response_message

    def saved(messages: list[dict[str, Any]]) -> Any:
        return sanitize_tool_calls(serialize_messages_for_output(messages))

    trajectory = native["trajectory"]
    previous: list[dict[str, Any]] = native["prompt"]
    if not isinstance(trajectory, list):
        raise RepeatEvidenceError("native trajectory must be an array")

    async def projected_completions() -> list[list[dict[str, Any]]]:
        return [
            [
                message.model_dump(exclude_none=True)
                for message in await parse_response_message(
                    Response.model_validate(step["response"])
                )
            ]
            for step in trajectory
        ]

    expected_completions = asyncio.run(projected_completions())
    for step, expected_completion in zip(trajectory, expected_completions, strict=True):
        _equal(native["trajectory_id"], step["trajectory_id"], "trajectory step identity")
        # Raw Responses output includes encrypted reasoning and the original
        # function-call items. The native display serializer drops those extras
        # from tool-calling assistant messages, so compare raw causal history
        # before checking the flattened display projection.
        prompt = step["prompt"]
        _equal(previous, prompt[: len(previous)], "trajectory prefix")
        if any(message["role"] != "tool" for message in prompt[len(previous) :]):
            raise RepeatEvidenceError("trajectory added a noncausal model input")
        message = step["response"]["message"]
        raw_output = message.get("openai_responses_output")
        if not isinstance(raw_output, list):
            raise RepeatEvidenceError("native Responses output items are missing")
        raw_calls = [
            {"id": item["call_id"], "name": item["name"], "arguments": item["arguments"]}
            for item in raw_output
            if item["type"] == "function_call"
        ]
        _equal(raw_calls, message.get("tool_calls") or [], "Responses function-call projection")
        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        for item in raw_output:
            if item["type"] == "message":
                for part in item.get("content") or []:
                    key = {"output_text": "text", "refusal": "refusal"}.get(part["type"])
                    if key is not None and isinstance(part.get(key), str):
                        content_parts.append(part[key])
            elif item["type"] == "reasoning":
                for part in [*(item.get("summary") or []), *(item.get("content") or [])]:
                    if isinstance(part.get("text"), str):
                        reasoning_parts.append(part["text"])
        content = "".join(content_parts) or None
        reasoning_content = "\n".join(reasoning_parts) or None
        if not raw_output and step["response"]["usage"]["reasoning_tokens"] > 0:
            content = ""
        _equal(content, message.get("content"), "Responses text projection")
        _equal(
            reasoning_content, message.get("reasoning_content"), "Responses reasoning projection"
        )
        _equal(expected_completion, step["completion"], "native response completion")
        previous = [*prompt, *step["completion"]]
    _equal(
        native["completion"],
        saved(previous[len(native["prompt"]) :]),
        "native rendered completion",
    )


def _audit_native_budget(
    ledger: dict[str, Any], native: dict[str, Any], config: Any
) -> dict[str, Any]:
    from datalox_dirty_integration.repeat_budget import TokenBudgetError, audit_budget

    try:
        audited = audit_budget(ledger)
    except TokenBudgetError as error:
        raise RepeatEvidenceError(f"token budget audit failed: {error}") from error
    _equal(config.model.model, ledger["model"], "budget model")
    _equal(config.model.endpoint, ledger["authority"], "budget API endpoint")
    if Fraction(audited["limit_usd"]) != Fraction(str(config.per_rollout_reservation_usd)):
        raise RepeatEvidenceError("budget limit differs from the frozen per-slot cap")
    if Fraction(audited["held_usd"]) != 0:
        raise RepeatEvidenceError("completed rollout has an unsettled token charge")
    settled = audited["settled_requests"]
    if len(settled) != len(native["trajectory"]):
        raise RepeatEvidenceError("budget settlements do not cover the exact native trajectory")
    if audited["blocked"]:
        raise RepeatEvidenceError("completed rollout has an unresolved budget block")
    for event in ledger["events"]:
        if event["kind"] == "reserved":
            _equal(
                config.model.max_completion_tokens,
                event["max_output_tokens"],
                "budget output-token limit",
            )
    for settlement, step in zip(settled, native["trajectory"], strict=True):
        response = step["response"]
        _equal(settlement["response_id"], response["id"], "budget response identity")
        _equal(settlement["model"], response["model"], "budget response model")
        usage = settlement["usage"]
        _equal(
            {
                "prompt_tokens": usage["input_tokens"],
                "completion_tokens": usage["output_tokens"],
                "total_tokens": usage["total_tokens"],
                # This is the pinned native Responses client's exact projection.
                "reasoning_tokens": (usage.get("output_tokens_details") or {}).get(
                    "reasoning_tokens", 0
                ),
            },
            response["usage"],
            "budget native usage",
        )
        _equal(
            settlement["status"] == "incomplete",
            response["message"]["is_truncated"],
            "budget native truncation",
        )
    return audited


def _request(name: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """The six existing consumer tools' explicit HTTP projection; no execution."""
    fields = _TOOL_ARGUMENTS
    if name not in fields or set(args) - set(fields[name]):
        raise RepeatEvidenceError("provider observation has an unknown tool or argument")
    request: dict[str, Any] = {
        "method": "GET",
        "authority": "api.medusa.local",
        "path": "",
        "query": {},
        "body": None,
    }
    if name == "list_products":
        operation = LIST_PRODUCTS_OPERATION
        request.update(
            path="/store/products",
            query={
                "limit": str(args.get("limit", 10)),
                "offset": str(args.get("offset", 0)),
            },
        )
    elif name == "create_cart":
        operation = CREATE_CART_OPERATION
        request.update(
            method="POST",
            path="/store/carts",
            body={
                "email": args["email"],
                "region_id": args["region_id"],
            },
        )
    else:
        request["path"] = f"/store/carts/{args['cart_id']}"
        if name == "get_cart":
            operation = RETRIEVE_CART_OPERATION
        elif name == "add_line_item":
            operation = ADD_LINE_ITEM_OPERATION
            request.update(
                method="POST",
                path=request["path"] + "/line-items",
                body={
                    "variant_id": args["variant_id"],
                    "quantity": args["quantity"],
                },
            )
        else:
            request["path"] += f"/line-items/{args['line_item_id']}"
            if name == "update_line_item":
                operation = UPDATE_LINE_ITEM_OPERATION
                request.update(method="POST", body={"quantity": args["quantity"]})
            else:
                operation = DELETE_LINE_ITEM_OPERATION
                request["method"] = "DELETE"
    return operation, request


def join_tool_observations(
    completion: list[dict[str, Any]], calls: list[dict[str, Any]]
) -> dict[str, Any]:
    """Join by native tool_call_id, then require exact ordered provider effects."""
    pending: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    attempts = 0
    non_provider: list[dict[str, Any]] = []
    call_index = 0
    for message in completion:
        role = message.get("role")
        if role == "assistant":
            if pending:
                raise RepeatEvidenceError("assistant continued before tool results")
            for encoded in message.get("tool_calls") or []:
                # Verifiers 0.3.1 saves each native ToolCall as a JSON string.
                if not isinstance(encoded, str):
                    raise RepeatEvidenceError("native tool-call encoding changed")
                tool = parse_json(encoded)
                identity = tool.get("id")
                if not isinstance(identity, str) or not identity or identity in seen:
                    raise RepeatEvidenceError("missing or duplicate tool-call identity")
                seen.add(identity)
                pending[identity] = tool
                attempts += 1
        elif role == "tool":
            identity = message.get("tool_call_id")
            if not pending or identity != next(iter(pending)):
                raise RepeatEvidenceError("native tool results are missing, repeated, or reordered")
            tool = pending.pop(identity)
            content = message.get("content")
            if not isinstance(content, str):
                raise RepeatEvidenceError("text tool observation encoding changed")
            try:
                observation = parse_json(content)
            except json.JSONDecodeError:
                observation = None
            if not isinstance(observation, dict) or set(observation) != {
                "status_code",
                "headers",
                "body",
            }:
                # Native parse/call failures remain visible attempts. Do not invent
                # a provider request or grade an error string as a provider response.
                if not _provably_invalid_tool_call(tool):
                    raise RepeatEvidenceError("valid declared tool returned a native tool failure")
                non_provider.append({"tool_call_id": identity, "tool": tool, "content": content})
                continue
            if call_index >= len(calls):
                raise RepeatEvidenceError("native observation has no provider evidence")
            args = parse_json(tool["arguments"])
            if not isinstance(args, dict):
                raise RepeatEvidenceError("provider observation has invalid tool arguments")
            operation, request = _request(tool["name"], args)
            call = calls[call_index]
            _equal(operation, call["operation_id"], "tool operation")
            _equal(request, call["request"], "tool request")
            _equal(observation, call["observation"], "native delivered observation")
            call_index += 1
    if call_index != len(calls):
        raise RepeatEvidenceError("provider observations are absent from the native trajectory")
    # At a native turn cap the last model-selected call may remain unexecuted.
    return {
        "tool_attempts": attempts,
        "invalid_tool_attempts": len(non_provider),
        "non_provider_tool_results": non_provider,
        "unexecuted_tool_attempts": list(pending.values()),
    }


def collect_slot(
    output: Path, config: Any, slot: Any, *, verify_index: bool = False
) -> dict[str, Any]:
    """Audit a single saved native rollout and derive a controller-only row."""
    output = output.resolve()
    native_path = output / "native" / "results.jsonl"
    if native_path.is_symlink():
        raise RepeatEvidenceError("native results must be a regular file")
    lines = native_path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise RepeatEvidenceError("each slot requires exactly one native rollout")
    native = parse_json(lines[0])
    required_native = {
        "trajectory_id",
        "prompt",
        "completion",
        "tool_defs",
        "trajectory",
        "sampling_args",
        "error",
        "is_completed",
        "is_truncated",
        "stop_condition",
        "timing",
        "reward_task_correctness",
        "reward_request_discipline",
    }
    if not required_native.issubset(native):
        raise RepeatEvidenceError("required native rollout fields are missing")
    execution = read_json(output / "native" / "execution.json")
    metadata = read_json(output / "native" / "metadata.json")
    for field, expected in {
        "schema_version": "datalox_verifiers_native_execution_v1",
        "verifiers_version": "0.3.1",
        "entry_point": "verifiers.legacy.envs.environment.Environment.evaluate",
        "native_metadata_base_url_availability": "not_retained_for_caller_owned_client",
        "model": config.model.model,
        "num_examples": 1,
        "rollouts_per_example": 1,
        "max_concurrent": 1,
        "max_retries": 0,
        "shuffle": False,
        "save_results": True,
        "push_to_hf_hub": False,
    }.items():
        if field not in execution:
            raise RepeatEvidenceError(f"native execution setting missing: {field}")
        _equal(expected, execution[field], f"native execution {field}")
    for field, expected in {
        "client_type": "openai_responses",
        "api_base_url": config.model.endpoint,
        "api_key_var": config.model.api_key_env,
        "max_retries": 0,
        "timeout": config.model.request_timeout_seconds,
        "connect_timeout": config.model.connect_timeout_seconds,
        "max_connections": 1,
        "max_keepalive_connections": 1,
        "extra_headers": {},
        "extra_headers_from_state": {},
        "endpoint_configs": [],
    }.items():
        _equal(expected, execution["client"][field], f"native client {field}")
    environment_args = {
        "profile": slot.profile,
        "intervention_seed": slot.seed,
        "intervention_enabled": True,
        "num_tasks": 1,
        "max_turns": config.max_turns,
        "timeout_seconds": config.per_rollout_timeout_seconds,
    }
    for field, expected in environment_args.items():
        _equal(expected, execution["environment_args"][field], f"native environment {field}")
        _equal(expected, metadata["env_args"][field], f"native metadata environment {field}")
    for field, expected in {
        "model": config.model.model,
        # Pinned Verifiers only extracts this from ClientConfig or a direct
        # base_url attribute; its native Client wrapper exposes neither. The
        # execution contract and metering ledger bind the actual SDK endpoint.
        "base_url": "",
        "num_examples": 1,
        "rollouts_per_example": 1,
        "shuffle": False,
    }.items():
        _equal(expected, metadata[field], f"native metadata {field}")
    for label, settings in (
        ("execution", execution["sampling_args"]),
        ("result", native["sampling_args"]),
        ("metadata", metadata["sampling_args"]),
    ):
        _equal(config.bindings["native.sampling"], canonical_sha256(settings), f"{label} sampling")
    identity = native.get("trajectory_id")
    if not isinstance(identity, str) or not identity:
        raise RepeatEvidenceError("native trajectory identity is missing")
    identity_digest = "sha256:" + hashlib.sha256(identity.encode()).hexdigest()
    evidence_root = output / "evidence"
    directories = list(evidence_root.iterdir())
    if len(directories) != 1 or not directories[0].is_dir() or directories[0].is_symlink():
        raise RepeatEvidenceError("each native rollout requires exactly one evidence directory")
    evidence = directories[0]
    manifest = read_json(evidence / "manifest.json")
    _equal(identity_digest, manifest["trajectory_id_sha256"], "trajectory identity")
    _equal(slot.profile, manifest["profile"], "profile")
    _equal(slot.seed, manifest["intervention"]["seed"], "policy seed")
    _equal(True, manifest["intervention"]["enabled"], "intervention enabled")
    _equal(
        config.bindings[f"policy.{slot.profile}"],
        manifest["intervention"]["policy_sha256"],
        "policy digest",
    )
    provider_fields = {
        "release_digest",
        "release_version",
        "profile_id",
        "bundle_version",
        "initial_state_fingerprint",
        "grounding_sha256",
        "runtime_sha256",
        "admission_sha256",
        "operation_claims_sha256",
        "operation_contract_sha256",
    }
    if set(manifest["provider"]) != provider_fields:
        raise RepeatEvidenceError("provider binding inventory changed")
    for name, value in manifest["provider"].items():
        if name in {"release_version", "profile_id", "bundle_version"}:
            continue
        _equal(config.bindings[f"provider.{name}"], value, f"provider {name}")
    expected_artifacts = {
        "provider-export.json",
        "intervention-trace.json",
        "delivered-observations.json",
        "verification.json",
    }
    if set(manifest["artifacts"]) != expected_artifacts:
        raise RepeatEvidenceError("evidence artifact inventory changed")
    artifacts = {}
    for name, digest in manifest["artifacts"].items():
        path = evidence / name
        artifacts[name] = read_json(path)
        _equal(digest, sha256_file(path), f"artifact {name}")
    provider = artifacts["provider-export.json"]
    intervention = artifacts["intervention-trace.json"]
    for field in ("policy_id", "policy_version", "policy_sha256", "seed", "enabled"):
        _equal(manifest["intervention"][field], intervention[field], f"intervention {field}")
    calls = artifacts["delivered-observations.json"]["calls"]
    audit = audit_episode_export(
        {"provider": provider, "intervention": intervention, "delivered_calls": calls}
    )
    _audit_provider_calls(provider, intervention, calls)
    verification = artifacts["verification.json"]
    if native.get("error") is not None:
        raise RepeatEvidenceError("native rollout contains an infrastructure/model error")
    if native.get("timed_out") is True:
        raise RepeatEvidenceError("native rollout hit the collection timeout")
    if native.get("is_completed") is not True:
        raise RepeatEvidenceError("native rollout has no terminal completion")
    _audit_native_trajectory(native)
    token_budget = _audit_native_budget(
        read_json(output / "native" / "budget.json"), native, config
    )
    _equal(
        config.bindings["task.prompt"], canonical_sha256(native["prompt"]), "initial task prompt"
    )
    _equal(
        config.bindings["task.tools"],
        canonical_sha256(native["tool_defs"]),
        "model-facing tool schemas",
    )
    _equal(
        native["reward_task_correctness"],
        verification["task_correctness"]["score"],
        "task component",
    )
    _equal(
        native["reward_request_discipline"],
        verification["request_discipline"]["score"],
        "discipline component",
    )
    from datalox_dirty_integration.scoring import (
        EvaluationOracle,
        request_discipline_report_for_episode,
        verify_task_for_episode,
    )

    episode_view = SimpleNamespace(
        provider=SimpleNamespace(export=lambda: provider),
        delivered_calls=calls,
        failed_calls=sum(not 200 <= call["observation"]["status_code"] < 300 for call in calls),
    )
    _equal(
        verification["task_correctness"],
        verify_task_for_episode(episode_view, EvaluationOracle()).to_dict(),
        "recomputed task verification",
    )
    _equal(
        verification["request_discipline"],
        request_discipline_report_for_episode(episode_view, EvaluationOracle()).to_dict(),
        "recomputed discipline",
    )
    joined = join_tool_observations(native["completion"], calls)
    if joined["unexecuted_tool_attempts"] and native["stop_condition"] != "max_turns_reached":
        raise RepeatEvidenceError("unexecuted calls require the native turn cap")
    responses = [
        step["response"] for step in native["trajectory"] if step.get("response") is not None
    ]
    models = sorted({response["model"] for response in responses})
    base_events = {event["event_id"]: event for event in provider["call_evidence"]["events"]}
    bases = {}
    for event in intervention["events"]:
        if event["base"]["invoked"]:
            base = base_events[event["base"]["event_id"]]
            bases[str(event["logical_request_index"])] = {
                "status_code": base["response_status_code"],
                "headers": {},
                "body": base["response_body"],
            }
    row = {
        "slot_id": slot.slot_id,
        "profile": slot.profile,
        "seed": slot.seed,
        "repetition": slot.repetition,
        "status": "completed",
        "task_correctness": verification["task_correctness"],
        "request_discipline": verification["request_discipline"],
        "provider_calls": calls,
        "interventions": intervention["events"],
        **joined,
        "base_responses": bases,
        "audit": audit,
        "native": {
            "termination_reason": native.get("stop_condition"),
            "is_truncated": native["is_truncated"],
            "is_completed": native["is_completed"],
            "model": models[0] if len(models) == 1 else None,
            "returned_models": models,
            "backend_fingerprint": None,
            "backend_fingerprint_availability": "not_retained_by_verifiers_0_3_1",
            "usage": native.get("token_usage"),
            "token_budget": token_budget,
            "duration_seconds": native["timing"]["total"],
            "agent_messages": [
                message for message in native["completion"] if message["role"] == "assistant"
            ],
        },
    }
    files = {
        str(path.relative_to(output)): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file() and path != output / "index.json"
    }
    if any(path.is_symlink() for path in output.rglob("*")):
        raise RepeatEvidenceError("slot evidence contains a symlink")
    index = {
        "schema_version": "datalox_repeat_slot_index_v1",
        "slot_id": slot.slot_id,
        "experiment_sha256": canonical_sha256(config.model_dump(mode="json")),
        "trajectory_id_sha256": identity_digest,
        "files": files,
        "row_sha256": canonical_sha256(row),
    }
    if verify_index:
        _equal(read_json(output / "index.json"), index, "slot index")
    else:
        write_json(output / "index.json", index)
    return row
