"""Tamper tests for repeat collection, using model-free fixtures only.

Native tests run the real pinned evaluator and its controller evidence writer
against an in-memory inference transport. These trajectories are test inputs,
never experiment results.
"""

from __future__ import annotations

import importlib
import json
import shutil
import sys
from copy import deepcopy
from functools import wraps
from pathlib import Path
from typing import Any

import pytest
from test_verifiers_repeat_native import _call, _response

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "integrations" / "verifiers_dirty_integration"))
evidence = importlib.import_module("datalox_dirty_integration.repeat_evidence")
contract = importlib.import_module("datalox_dirty_integration.contract")
repeat_contract = importlib.import_module("datalox_dirty_integration.repeat_contract")
episode_module = importlib.import_module("datalox_dirty_integration.episode")
policy = importlib.import_module("datalox_dirty_integration.policy")


def _message_pair(
    identity: str, name: str, arguments: Any, observation: Any
) -> list[dict[str, Any]]:
    return [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                json.dumps({"id": identity, "name": name, "arguments": json.dumps(arguments)})
            ],
        },
        {"role": "tool", "tool_call_id": identity, "content": json.dumps(observation)},
    ]


@pytest.fixture
def provider_transcript() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Provider calls for pure join tests; no Verifiers or model dependency."""
    completion: list[dict[str, Any]] = []
    with episode_module.CommerceEpisode(
        provider_grounding=contract.provider_grounding_path(),
        provider_admission=contract.provider_admission_path(),
        provider_runtime_bundle=contract.provider_runtime_bundle_path(),
        provider_release=contract.provider_release_path(),
        policy=policy.SeededCommercePolicy(policy.load_profile("clean")),
        intervention_seed="1",
        intervention_enabled=True,
    ) as episode:
        page = episode.list_products(offset=0, limit=10)
        completion += _message_pair(
            "read",
            "list_products",
            {"offset": 0, "limit": 10},
            episode.delivered_calls[-1]["observation"],
        )
        created = episode.create_cart(email=contract.TASK_EMAIL, region_id=contract.TASK_REGION_ID)
        cart_id = created.body["cart"]["id"]
        completion += _message_pair(
            "create",
            "create_cart",
            {"email": contract.TASK_EMAIL, "region_id": contract.TASK_REGION_ID},
            episode.delivered_calls[-1]["observation"],
        )
        arguments = {
            "cart_id": cart_id,
            "variant_id": page.body["products"][0]["variants"][0]["id"],
            "quantity": 1,
        }
        added = episode.add_line_item(**arguments)
        line_item_id = added.body["cart"]["items"][0]["id"]
        completion += _message_pair(
            "add", "add_line_item", arguments, episode.delivered_calls[-1]["observation"]
        )
        episode.get_cart(cart_id=cart_id)
        completion += _message_pair(
            "get", "get_cart", {"cart_id": cart_id}, episode.delivered_calls[-1]["observation"]
        )
        arguments = {"cart_id": cart_id, "line_item_id": line_item_id, "quantity": 3}
        episode.update_line_item(**arguments)
        completion += _message_pair(
            "update", "update_line_item", arguments, episode.delivered_calls[-1]["observation"]
        )
        arguments = {"cart_id": cart_id, "line_item_id": line_item_id}
        episode.delete_line_item(**arguments)
        completion += _message_pair(
            "delete", "delete_line_item", arguments, episode.delivered_calls[-1]["observation"]
        )
        return completion, deepcopy(episode.delivered_calls)


def test_pure_join_preserves_ordered_provider_observations(provider_transcript: Any) -> None:
    completion, calls = provider_transcript
    saved = deepcopy((completion, calls))
    result = evidence.join_tool_observations(completion, calls)
    assert result["tool_attempts"] == 6
    assert result["invalid_tool_attempts"] == 0
    assert result["unexecuted_tool_attempts"] == []
    assert (completion, calls) == saved


@pytest.mark.parametrize("value", [50.0, "50", True])
def test_native_observation_comparison_retains_value_types(
    provider_transcript: Any, value: Any
) -> None:
    completion, calls = provider_transcript
    observation = json.loads(completion[1]["content"])
    observation["body"]["count"] = value
    completion[1]["content"] = json.dumps(observation)
    with pytest.raises(evidence.RepeatEvidenceError, match="observation"):
        evidence.join_tool_observations(completion, calls)


@pytest.mark.parametrize("value", [1.0, True, "1"])
def test_native_argument_comparison_retains_integer_float_boolean_types(
    provider_transcript: Any, value: Any
) -> None:
    completion, calls = provider_transcript
    tool = json.loads(completion[4]["tool_calls"][0])
    arguments = json.loads(tool["arguments"])
    arguments["quantity"] = value
    tool["arguments"] = json.dumps(arguments)
    completion[4]["tool_calls"][0] = json.dumps(tool)
    with pytest.raises(evidence.RepeatEvidenceError, match="request"):
        evidence.join_tool_observations(completion, calls)


@pytest.mark.parametrize(
    "change",
    [
        "reordered_calls",
        "duplicate_id",
        "missing_observation",
        "foreign_tool_id",
        "object_encoding",
    ],
)
def test_pure_join_rejects_identity_and_order_corruption(
    provider_transcript: Any, change: str
) -> None:
    completion, calls = provider_transcript
    if change == "reordered_calls":
        calls[0], calls[1] = calls[1], calls[0]
    elif change == "duplicate_id":
        tool = json.loads(completion[2]["tool_calls"][0])
        tool["id"] = "read"
        completion[2]["tool_calls"][0] = json.dumps(tool)
    elif change == "missing_observation":
        completion.pop(1)
    elif change == "foreign_tool_id":
        completion[1]["tool_call_id"] = "not-requested"
    else:
        completion[0]["tool_calls"][0] = json.loads(completion[0]["tool_calls"][0])
    with pytest.raises(evidence.RepeatEvidenceError):
        evidence.join_tool_observations(completion, calls)


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("unknown_tool", {}),
        ("list_products", {"unexpected": True}),
        ("create_cart", {"email": contract.TASK_EMAIL}),
        ("list_products", {"offset": True}),
        ("list_products", {"offset": 1.0}),
        ("get_cart", {"cart_id": 123}),
        ("list_products", []),
    ],
)
def test_non_provider_errors_remain_separate_native_attempts(name: str, arguments: Any) -> None:
    completion = _message_pair("bad", name, arguments, {})
    completion[1]["content"] = "Error calling tool: invalid arguments or unknown tool"
    result = evidence.join_tool_observations(completion, [])
    assert result["tool_attempts"] == 1
    assert result["invalid_tool_attempts"] == 1
    assert result["non_provider_tool_results"][0]["content"] == completion[1]["content"]
    assert result["unexecuted_tool_attempts"] == []


def test_malformed_argument_json_is_an_invalid_native_attempt() -> None:
    completion = _message_pair("bad-json", "list_products", {}, {})
    call = json.loads(completion[0]["tool_calls"][0])
    call["arguments"] = '{"offset":'
    completion[0]["tool_calls"][0] = json.dumps(call)
    completion[1]["content"] = "Error parsing tool arguments"
    result = evidence.join_tool_observations(completion, [])
    assert result["tool_attempts"] == result["invalid_tool_attempts"] == 1


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("list_products", {}),
        ("list_products", {"offset": 0, "limit": 10}),
        ("create_cart", {"email": contract.TASK_EMAIL, "region_id": contract.TASK_REGION_ID}),
    ],
)
def test_valid_tool_internal_failure_is_a_collection_error(name: str, arguments: Any) -> None:
    completion = _message_pair("internal-error", name, arguments, {})
    completion[1]["content"] = "Error calling tool: internal provider runtime failure"
    with pytest.raises(evidence.RepeatEvidenceError):
        evidence.join_tool_observations(completion, [])


def test_unexecuted_final_tool_is_reported_for_collection_to_check() -> None:
    completion = _message_pair("capped", "list_products", {"offset": 0}, {})[:1]
    result = evidence.join_tool_observations(completion, [])
    assert result["tool_attempts"] == 1
    assert result["invalid_tool_attempts"] == 0
    assert result["unexecuted_tool_attempts"][0]["id"] == "capped"


@pytest.mark.parametrize("payload", ['{"key": 1, "key": 2}', '{"key": NaN}', '{"key": Infinity}'])
def test_evidence_json_rejects_ambiguous_values(payload: str) -> None:
    with pytest.raises(evidence.RepeatEvidenceError):
        evidence.parse_json(payload)


def _write(path: Path, value: Any) -> None:
    # Test mutations intentionally overwrite test-only artifacts.
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


@pytest.fixture
def native_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> dict[str, Any]:
    pytest.importorskip("verifiers")
    httpx = pytest.importorskip("httpx")
    native = importlib.import_module("datalox_dirty_integration.repeat_native")
    clients = importlib.import_module("verifiers.legacy.utils.client_utils")
    config = repeat_contract.ExperimentConfig(
        experiment_id="evidence-fixture",
        source_revision="a" * 40,
        bindings={"fixture": "sha256:" + "b" * 64},
        model=repeat_contract.ModelConfig(
            max_completion_tokens=4096, request_timeout_seconds=30.0, connect_timeout_seconds=5.0
        ),
        seeds=("1",),
        repetitions=1,
        max_turns=30,
        per_rollout_timeout_seconds=120.0,
        max_total_cost_usd=2.0,
        per_rollout_reservation_usd=1.0,
        schedule=repeat_contract.build_schedule(("1",), 1),
    )
    requests: list[dict[str, Any]] = []
    count_requests: list[dict[str, Any]] = []
    fixture_mode = getattr(request, "param", None)

    def handle(request: Any) -> Any:
        if request.url.path == "/v1/responses/input_tokens":
            count_requests.append(json.loads(request.content))
            return httpx.Response(
                200, json={"object": "response.input_tokens", "input_tokens": 100}
            )
        requests.append(json.loads(request.content))
        number = len(requests)
        tool_calls = None
        if number <= 2:
            tool_calls = [
                _call(f"call-{number}", "list_products", offset=(number - 1) * 10, limit=10)
            ]
        elif number == 3:
            tool_calls = [
                _call(
                    "create-cart",
                    "create_cart",
                    email=contract.TASK_EMAIL,
                    region_id=contract.TASK_REGION_ID,
                )
            ]
        status, response = _response(tool_calls=tool_calls, response_id=f"resp_test_only_{number}")
        if fixture_mode == "incomplete_read" and number == 1:
            response["status"] = "incomplete"
            response["incomplete_details"] = {"reason": "max_output_tokens"}
        return httpx.Response(status, json=response)

    def build_client(client_config: Any, headers: dict[str, str]) -> Any:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handle),
            headers=headers,
            timeout=httpx.Timeout(client_config.timeout, connect=client_config.connect_timeout),
        )

    monkeypatch.setenv("OPENAI_API_KEY", "test-only-not-a-real-key")
    monkeypatch.setattr(clients, "_build_http_client", build_client)
    if fixture_mode in {"list_products", "create_cart"}:
        environment = importlib.import_module("datalox_dirty_integration.environment")
        original = getattr(environment, fixture_mode)

        @wraps(original)
        def fail_before_provider(*args: Any, **kwargs: Any) -> str:
            raise RuntimeError("test-only internal provider runtime failure")

        monkeypatch.setattr(environment, fixture_mode, fail_before_provider)
    slot = config.schedule[0]
    output = tmp_path / slot.slot_id
    native.run_native_slot(config, slot, output)
    native_path = output / "native" / "results.jsonl"
    native_row = evidence.read_json(native_path)
    manifest_path = next((output / "evidence").glob("*/manifest.json"))
    manifest = evidence.read_json(manifest_path)
    bindings = {
        f"provider.{name}": digest
        for name, digest in manifest["provider"].items()
        if name not in {"release_version", "profile_id", "bundle_version"}
    }
    bindings.update(
        {
            "task.prompt": evidence.canonical_sha256(native_row["prompt"]),
            "task.tools": evidence.canonical_sha256(native_row["tool_defs"]),
            "native.sampling": evidence.canonical_sha256(native_row["sampling_args"]),
            "policy.clean": manifest["intervention"]["policy_sha256"],
        }
    )
    config = repeat_contract.ExperimentConfig.model_validate(
        {**config.model_dump(), "bindings": bindings}
    )
    return {
        "config": config,
        "slot": slot,
        "output": output,
        "native": native_path,
        "manifest": manifest_path,
        "requests": requests,
        "count_requests": count_requests,
    }


def test_native_collection_uses_actual_writer_and_is_reauditable(native_slot: Any) -> None:
    item = native_slot
    original_files = {
        path: path.read_bytes() for path in item["output"].rglob("*") if path.is_file()
    }
    row = evidence.collect_slot(item["output"], item["config"], item["slot"])
    assert row["status"] == "completed"
    assert row["tool_attempts"] == 3
    assert row["task_correctness"]["score"] == 0.0  # A task failure is valid evidence.
    assert len(row["provider_calls"]) == 3
    assert row["native"]["termination_reason"] == "no_tools_called"
    assert row["native"]["duration_seconds"] >= 0.0
    budget = row["native"]["token_budget"]
    assert budget["passed"] is True
    assert budget["settled_count"] == len(item["requests"]) == len(item["count_requests"])
    assert budget["held_usd"] == "0"
    assert budget["blocked"] is False
    assert row == evidence.collect_slot(
        item["output"], item["config"], item["slot"], verify_index=True
    )
    assert all(path.read_bytes() == content for path, content in original_files.items())
    with pytest.raises(FileExistsError):
        evidence.collect_slot(item["output"], item["config"], item["slot"])


@pytest.mark.parametrize("native_slot", ["incomplete_read"], indirect=True)
def test_settled_incomplete_response_preserves_native_continuation(native_slot: Any) -> None:
    row = evidence.collect_slot(native_slot["output"], native_slot["config"], native_slot["slot"])
    assert row["status"] == "completed"
    assert len(native_slot["requests"]) == 4
    budget = row["native"]["token_budget"]
    assert budget["settled_requests"][0]["status"] == "incomplete"
    assert all(event["status"] == "completed" for event in budget["settled_requests"][1:])
    assert budget["blocked"] is False
    native = evidence.read_json(native_slot["native"])
    assert native["trajectory"][0]["response"]["message"]["is_truncated"] is True
    assert native["error"] is None


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "authority",
        "limit",
        "response_id",
        "native_usage",
        "spent",
        "rates",
        "settlement_order",
        "truncation",
        "blocked",
        "output_limit",
    ],
)
def test_collection_binds_metered_requests_to_native_trajectory(
    native_slot: Any, change: str
) -> None:
    path = native_slot["output"] / "native" / "budget.json"
    ledger = evidence.read_json(path)
    settled = [event for event in ledger["events"] if event["kind"] == "settled"]
    if change == "missing":
        path.unlink()
    elif change == "authority":
        ledger["authority"] = "https://unrequested.example/v1"
    elif change == "limit":
        ledger["limit_usd"] = "2"
    elif change == "response_id":
        settled[0]["response_id"] = "resp_foreign"
    elif change == "native_usage":
        native = evidence.read_json(native_slot["native"])
        native["trajectory"][0]["response"]["usage"]["prompt_tokens"] += 1
        _write(native_slot["native"], native)
    elif change == "spent":
        ledger["spent_usd"] = "0"
    elif change == "rates":
        ledger["rates_usd_per_million"]["output"] = "1"
    elif change == "settlement_order":
        settled[0]["response_id"], settled[1]["response_id"] = (
            settled[1]["response_id"],
            settled[0]["response_id"],
        )
    elif change == "truncation":
        settled[0]["status"] = "incomplete"
    elif change == "blocked":
        ledger["blocked"] = True
        ledger["events"].append(
            {
                "sequence": len(ledger["events"]) + 1,
                "kind": "blocked",
                "reason_code": "slot_budget_exhausted",
                "request_sha256": None,
            }
        )
    else:
        # Keep the ledger arithmetically valid while changing the frozen cap.
        reserved = next(event for event in ledger["events"] if event["kind"] == "reserved")
        reserved["max_output_tokens"] = 4000
        reserved["hold_usd"] = "161/2000"
    if change != "missing":
        _write(path, ledger)
    with pytest.raises((evidence.RepeatEvidenceError, FileNotFoundError)):
        evidence.collect_slot(native_slot["output"], native_slot["config"], native_slot["slot"])


def test_native_task_and_tools_remain_separate_from_controller_evidence(native_slot: Any) -> None:
    requests = native_slot["requests"]
    prompt = json.dumps(requests[0]["input"])
    tools = json.dumps(requests[0]["tools"])
    assert contract.TASK_INSTRUCTIONS in requests[0]["input"][0]["content"]
    assert "prod_datalox_pagination_001" not in prompt
    assert "variant_datalox_pagination_001" not in prompt
    assert "prod_datalox_pagination_001" in json.dumps(requests[1]["input"])
    for hidden in (
        "intervention_seed",
        "policy_sha256",
        "initial_state_fingerprint",
        str(native_slot["output"]),
    ):
        assert hidden not in prompt
        assert hidden not in tools
    assert "episode" not in tools


@pytest.mark.parametrize("native_slot", ["list_products", "create_cart"], indirect=True)
def test_native_valid_tool_runtime_error_cannot_be_scored_as_an_agent_mistake(
    native_slot: Any,
) -> None:
    native = evidence.read_json(native_slot["native"])
    # Native ToolEnv catches the RuntimeError as a tool-result string. The
    # collection boundary must distinguish it from invalid model arguments.
    assert native["error"] is None
    assert any(
        "test-only internal provider runtime failure" in message["content"]
        for message in native["completion"]
        if message["role"] == "tool"
    )
    with pytest.raises(evidence.RepeatEvidenceError):
        evidence.collect_slot(native_slot["output"], native_slot["config"], native_slot["slot"])
    assert not (native_slot["output"] / "index.json").exists()


@pytest.mark.parametrize(
    "change",
    [
        "identity",
        "profile",
        "seed",
        "enabled",
        "policy",
        "provider_digest",
        "provider_missing",
        "inventory",
        "policy_id",
        "policy_version",
    ],
)
def test_collection_rejects_manifest_binding_changes(native_slot: Any, change: str) -> None:
    manifest = evidence.read_json(native_slot["manifest"])
    if change == "identity":
        manifest["trajectory_id_sha256"] = "sha256:" + "f" * 64
    elif change == "profile":
        manifest["profile"] = "hostile"
    elif change == "seed":
        manifest["intervention"]["seed"] = "23"
    elif change == "enabled":
        manifest["intervention"]["enabled"] = False
    elif change == "policy":
        manifest["intervention"]["policy_sha256"] = "sha256:" + "f" * 64
    elif change == "provider_digest":
        manifest["provider"]["initial_state_fingerprint"] = "sha256:" + "f" * 64
    elif change == "provider_missing":
        del manifest["provider"]["release_digest"]
    elif change == "inventory":
        manifest["artifacts"].pop("verification.json")
    elif change == "policy_id":
        manifest["intervention"]["policy_id"] = "foreign-policy"
    else:
        manifest["intervention"]["policy_version"] = "foreign-version"
    _write(native_slot["manifest"], manifest)
    with pytest.raises(evidence.RepeatEvidenceError):
        evidence.collect_slot(native_slot["output"], native_slot["config"], native_slot["slot"])


@pytest.mark.parametrize(
    "change",
    [
        "identity",
        "duplicate_result",
        "observation",
        "missing_error",
        "error",
        "incomplete",
        "sampling",
        "score",
        "prompt",
        "tools",
        "trajectory_identity",
        "trajectory_prompt",
        "raw_completion_reasoning",
        "raw_prompt_reasoning",
        "raw_response_reasoning",
        "raw_response_call",
        "raw_final_text",
        "raw_reasoning_summary",
        "missing_raw_response",
    ],
)
def test_collection_rejects_native_binding_changes(native_slot: Any, change: str) -> None:
    native = evidence.read_json(native_slot["native"])
    if change == "identity":
        native["trajectory_id"] = "foreign-trajectory"
    elif change == "duplicate_result":
        native_slot["native"].write_text(json.dumps(native) + "\n" + json.dumps(native) + "\n")
    elif change == "observation":
        observation = json.loads(native["completion"][1]["content"])
        observation["body"]["count"] = 50.0
        native["completion"][1]["content"] = json.dumps(observation)
    elif change == "missing_error":
        del native["error"]
    elif change == "error":
        native["error"] = {"error": "ModelError"}
    elif change == "incomplete":
        native["is_completed"] = False
    elif change == "sampling":
        native["sampling_args"]["reasoning"]["effort"] = "high"
    elif change == "score":
        native["reward_request_discipline"] = 0.5
    elif change == "prompt":
        native["prompt"][0]["content"] += " More task input."
    elif change == "tools":
        native["tool_defs"] = []
    elif change == "trajectory_identity":
        native["trajectory"][0]["trajectory_id"] = "foreign-trajectory"
    elif change == "trajectory_prompt":
        native["trajectory"][1]["prompt"][0]["content"] += " Unobserved provider context."
    elif change == "raw_completion_reasoning":
        native["trajectory"][0]["completion"][0]["openai_responses_output"][0][
            "encrypted_content"
        ] = "changed"
    elif change == "raw_prompt_reasoning":
        native["trajectory"][1]["prompt"][1]["openai_responses_output"][0]["encrypted_content"] = (
            "changed"
        )
    elif change == "raw_response_reasoning":
        native["trajectory"][0]["response"]["message"]["openai_responses_output"][0][
            "encrypted_content"
        ] = "changed"
    elif change == "raw_response_call":
        native["trajectory"][0]["response"]["message"]["openai_responses_output"][1][
            "arguments"
        ] = '{"offset":20}'
    elif change == "raw_final_text":
        # Alter all raw copies consistently; the independent native text
        # projection must still reject a changed final assistant message.
        step = native["trajectory"][-1]
        for message in (
            step["response"]["message"],
            step["completion"][0],
            native["completion"][-1],
        ):
            message["openai_responses_output"][1]["content"][0]["text"] = "Changed answer."
    elif change == "raw_reasoning_summary":
        step = native["trajectory"][-1]
        for message in (
            step["response"]["message"],
            step["completion"][0],
            native["completion"][-1],
        ):
            message["openai_responses_output"][0]["summary"] = [
                {"type": "summary_text", "text": "Changed summary."}
            ]
    else:
        del native["trajectory"][0]["response"]["message"]["openai_responses_output"]
    if change != "duplicate_result":
        _write(native_slot["native"], native)
    with pytest.raises(evidence.RepeatEvidenceError):
        evidence.collect_slot(native_slot["output"], native_slot["config"], native_slot["slot"])


@pytest.mark.parametrize("change", ["model", "client_retry", "sampling", "environment_seed"])
def test_collection_rejects_effective_native_execution_changes(
    native_slot: Any, change: str
) -> None:
    path = native_slot["output"] / "native" / "execution.json"
    execution = evidence.read_json(path)
    if change == "model":
        execution["model"] = "gpt-5.6-luna"
    elif change == "client_retry":
        execution["client"]["max_retries"] = 1
    elif change == "sampling":
        execution["sampling_args"]["parallel_tool_calls"] = True
    else:
        execution["environment_args"]["intervention_seed"] = "7"
    _write(path, execution)
    with pytest.raises(evidence.RepeatEvidenceError):
        evidence.collect_slot(native_slot["output"], native_slot["config"], native_slot["slot"])


@pytest.mark.parametrize(
    "change", ["digest", "second_directory", "missing_artifact", "symlink", "indexed_tamper"]
)
def test_collection_rejects_artifact_corruption(native_slot: Any, change: str) -> None:
    output, manifest_path = native_slot["output"], native_slot["manifest"]
    artifact = manifest_path.parent / "verification.json"
    verify_index = False
    if change == "digest":
        verification = evidence.read_json(artifact)
        verification["task_correctness"]["score"] = 1.0
        _write(artifact, verification)
    elif change == "second_directory":
        shutil.copytree(manifest_path.parent, output / "evidence" / "another")
    elif change == "missing_artifact":
        artifact.unlink()
    elif change == "symlink":
        renamed = artifact.with_suffix(".original")
        artifact.rename(renamed)
        artifact.symlink_to(renamed)
    else:
        evidence.collect_slot(output, native_slot["config"], native_slot["slot"])
        (output / "native" / "unindexed.txt").write_text("test-only alteration")
        verify_index = True
    with pytest.raises((evidence.RepeatEvidenceError, FileNotFoundError)):
        evidence.collect_slot(
            output, native_slot["config"], native_slot["slot"], verify_index=verify_index
        )


def test_collection_checks_direct_write_response_against_base_ledger(native_slot: Any) -> None:
    manifest = evidence.read_json(native_slot["manifest"])
    provider_path = native_slot["manifest"].parent / "provider-export.json"
    provider = evidence.read_json(provider_path)
    write = provider["call_evidence"]["events"][-1]
    assert write["request"]["operation_id"] == contract.CREATE_CART_OPERATION
    write["response_body"]["cart"]["email"] = "changed@example.test"
    _write(provider_path, provider)
    # Preserve artifact-level consistency to exercise the separate ledger join.
    manifest["artifacts"]["provider-export.json"] = episode_module.sha256_file(provider_path)
    _write(native_slot["manifest"], manifest)
    with pytest.raises(evidence.RepeatEvidenceError, match="direct provider response"):
        evidence.collect_slot(native_slot["output"], native_slot["config"], native_slot["slot"])
