"""Model-free transport tests of the real pinned Verifiers evaluator.

These fixed responses exercise collection only. They are never pilot data.
"""

from __future__ import annotations

import hashlib
import importlib
import itertools
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "integrations" / "verifiers_dirty_integration"))
native = importlib.import_module("datalox_dirty_integration.repeat_native")
_response_ids = itertools.count(1)


def _config(*, temperature: float | None = None) -> Any:
    return SimpleNamespace(
        model=SimpleNamespace(
            model="gpt-5.6-sol",
            endpoint="https://api.openai.com/v1",
            api_key_env="OPENAI_API_KEY",
            reasoning_effort="medium",
            temperature=temperature,
            model_seed=None,
            parallel_tool_calls=False,
            max_completion_tokens=4096,
            request_timeout_seconds=30.0,
            connect_timeout_seconds=5.0,
        ),
        max_turns=30,
        per_rollout_timeout_seconds=120.0,
        per_rollout_reservation_usd=0.4,
        concurrency=1,
        evaluator_retries=0,
        client_retries=0,
    )


def _slot() -> Any:
    return SimpleNamespace(
        slot_id="clean-seed-7-repeat-1", profile="clean", seed="7", repetition=1, order=0
    )


def test_native_sampling_keeps_unset_controls_off_the_wire() -> None:
    assert native.native_sampling_args(_config()) == {
        "reasoning": {"effort": "medium"},
        "max_output_tokens": 4096,
        "parallel_tool_calls": False,
        "store": False,
        "include": ["reasoning.encrypted_content"],
        "service_tier": "default",
    }
    assert native.native_sampling_args(_config(temperature=0.6))["temperature"] == 0.6


@pytest.fixture
def native_transport(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    pytest.importorskip("verifiers")
    httpx = pytest.importorskip("httpx")
    clients = importlib.import_module("verifiers.legacy.utils.client_utils")
    captured: dict[str, Any] = {
        "requests": [],
        "count_requests": [],
        "configs": [],
        "responses": [],
        "clients": [],
    }

    def handle(request: Any) -> Any:
        recorded = {
            "url": str(request.url),
            "body": json.loads(request.content),
            "timeout": request.extensions["timeout"],
        }
        if request.url.path.endswith("/responses/input_tokens"):
            captured["count_requests"].append(recorded)
            return httpx.Response(
                200, json={"object": "response.input_tokens", "input_tokens": 100}
            )
        captured["requests"].append(recorded)
        response = captured["responses"].pop(0)
        return httpx.Response(response[0], json=response[1])

    def build_client(config: Any, headers: dict[str, str]) -> Any:
        captured["configs"].append(config.model_dump(mode="json"))
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handle),
            timeout=httpx.Timeout(config.timeout, connect=config.connect_timeout),
            headers=headers,
        )
        captured["clients"].append(client)
        return client

    monkeypatch.setenv("OPENAI_API_KEY", "model-free-test-only-not-a-key")
    monkeypatch.setattr(clients, "_build_http_client", build_client)
    return captured


def _response(
    *,
    tool_calls: list[dict[str, Any]] | None = None,
    response_id: str | None = None,
) -> tuple[int, dict[str, Any]]:
    response_id = response_id or f"resp_model_free_test_{next(_response_ids)}"
    reasoning = {
        "id": f"rs_{response_id}",
        "type": "reasoning",
        "summary": [],
        "encrypted_content": f"model-free-encrypted-content-{response_id}",
    }
    output = [reasoning]
    output.extend(
        tool_calls
        or [
            {
                "id": f"msg_{response_id}",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [
                    {"type": "output_text", "text": "Finished fixture.", "annotations": []}
                ],
            }
        ]
    )
    return 200, {
        "id": response_id,
        "object": "response",
        "created_at": 1,
        "model": "gpt-5.6-sol",
        "status": "completed",
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "max_output_tokens": 4096,
        "output": output,
        "parallel_tool_calls": False,
        "tool_choice": "auto",
        "tools": [],
        "temperature": 1.0,
        "top_p": 1.0,
        "store": False,
        "service_tier": "default",
        "metadata": {},
        "usage": {
            "input_tokens": 100,
            "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
            "output_tokens": 30,
            "total_tokens": 130,
            "output_tokens_details": {"reasoning_tokens": 10},
        },
    }


def _call(call_id: str, name: str, **arguments: Any) -> dict[str, Any]:
    return {
        "id": f"fc_{call_id}",
        "type": "function_call",
        "call_id": call_id,
        "name": name,
        "arguments": json.dumps(arguments),
        "status": "completed",
    }


def _single_result(output: Path) -> dict[str, Any]:
    rows = (output / "native" / "results.jsonl").read_text().splitlines()
    assert len(rows) == 1
    return json.loads(rows[0])


def test_native_evaluator_preserves_identity_tools_observations_and_controls(
    tmp_path: Path, native_transport: dict[str, Any]
) -> None:
    native_transport["responses"] = [
        _response(
            tool_calls=[
                _call("call-1", "list_products", offset=0, limit=10),
                _call("call-2", "list_products", offset=10, limit=10),
            ]
        ),
        _response(),
    ]
    output = tmp_path / "slot"
    native.run_native_slot(_config(), _slot(), output)
    row = _single_result(output)
    identity = "sha256:" + hashlib.sha256(row["trajectory_id"].encode()).hexdigest()
    manifest_path = next((output / "evidence").glob("*/manifest.json"))
    manifest = json.loads(manifest_path.read_text())
    delivered = json.loads((manifest_path.parent / "delivered-observations.json").read_text())
    assert manifest["trajectory_id_sha256"] == identity
    assert len(row["trajectory"]) == 2
    assert all(step["trajectory_id"] == row["trajectory_id"] for step in row["trajectory"])
    assert row["stop_condition"] == "no_tools_called"
    assert row["is_completed"] is True
    assert row["error"] is None
    assert row["token_usage"]["input_tokens"] == 200
    assert row["token_usage"]["output_tokens"] == 60
    assert len(delivered["calls"]) == 2
    messages = [message for message in row["completion"] if message["role"] == "tool"]
    assert [message["tool_call_id"] for message in messages] == ["call-1", "call-2"]
    for message, delivered_call in zip(messages, delivered["calls"], strict=True):
        assert json.loads(message["content"]) == delivered_call["observation"]

    for request in native_transport["requests"]:
        assert request["url"] == "https://api.openai.com/v1/responses"
        assert request["body"]["reasoning"] == {"effort": "medium"}
        assert request["body"]["max_output_tokens"] == 4096
        assert request["body"]["parallel_tool_calls"] is False
        assert request["body"]["store"] is False
        assert request["body"]["include"] == ["reasoning.encrypted_content"]
        assert request["body"]["service_tier"] == "default"
        assert "messages" not in request["body"]
        assert "reasoning_effort" not in request["body"]
        assert "max_completion_tokens" not in request["body"]
        assert "max_tokens" not in request["body"]
        assert "n" not in request["body"]
        assert "temperature" not in request["body"]
        assert "seed" not in request["body"]
        assert "previous_response_id" not in request["body"]
        assert request["timeout"] == {"connect": 5.0, "read": 30.0, "write": 30.0, "pool": 30.0}
    assert native_transport["configs"][0]["max_retries"] == 0
    assert native_transport["configs"][0]["client_type"] == "openai_responses"
    assert len(native_transport["count_requests"]) == 2
    for counted, generated in zip(
        native_transport["count_requests"], native_transport["requests"], strict=True
    ):
        for field in ("model", "input", "tools"):
            assert counted["body"][field] == generated["body"][field]
    assert all(client.is_closed for client in native_transport["clients"])
    execution = json.loads((output / "native" / "execution.json").read_text())
    assert execution["entry_point"] == ("verifiers.legacy.envs.environment.Environment.evaluate")
    assert execution["client"] == native_transport["configs"][0]
    assert (output / "native" / "budget.json").is_file()
    assert "intervention_seed" not in json.dumps(native_transport["requests"][0]["body"])
    assert "episode" not in json.dumps(native_transport["requests"][0]["body"]["tools"])
    assert str(output) not in json.dumps(native_transport["requests"])
    assert "model-free-test-only-not-a-key" not in "".join(
        path.read_text() for path in output.rglob("*.json*")
    )


def test_native_responses_replays_encrypted_reasoning_and_exact_tool_outputs(
    tmp_path: Path, native_transport: dict[str, Any]
) -> None:
    first = _response(
        tool_calls=[
            _call("call-first-1", "list_products", offset=0, limit=10),
            _call("call-first-2", "list_products", offset=10, limit=10),
        ],
        response_id="resp_first",
    )
    second = _response(
        tool_calls=[_call("call-second", "list_products", offset=20, limit=10)],
        response_id="resp_second",
    )
    final = _response(response_id="resp_final")
    native_transport["responses"] = [first, second, final]
    output = tmp_path / "stateless-reasoning"
    native.run_native_slot(_config(), _slot(), output)
    row = _single_result(output)
    requests = native_transport["requests"]
    assert len(requests) == 3

    tool_messages = [message for message in row["completion"] if message["role"] == "tool"]
    assert [message["tool_call_id"] for message in tool_messages] == [
        "call-first-1",
        "call-first-2",
        "call-second",
    ]
    first_tool_outputs = [
        {
            "type": "function_call_output",
            "call_id": message["tool_call_id"],
            "output": message["content"],
        }
        for message in tool_messages[:2]
    ]
    second_tool_output = {
        "type": "function_call_output",
        "call_id": tool_messages[2]["tool_call_id"],
        "output": tool_messages[2]["content"],
    }
    initial_task = requests[0]["body"]["input"]
    assert requests[1]["body"]["input"] == [
        *initial_task,
        *first[1]["output"],
        *first_tool_outputs,
    ]
    assert requests[2]["body"]["input"] == [
        *initial_task,
        *first[1]["output"],
        *first_tool_outputs,
        *second[1]["output"],
        second_tool_output,
    ]
    for step, returned in zip(row["trajectory"], (first, second, final), strict=True):
        assert step["response"]["message"]["openai_responses_output"] == returned[1]["output"]
        assert step["completion"][0]["openai_responses_output"] == returned[1]["output"]
        assert step["response"]["usage"]["reasoning_tokens"] == 10
    for request in requests:
        assert request["body"]["store"] is False
        assert "previous_response_id" not in request["body"]
        assert request["body"]["include"] == ["reasoning.encrypted_content"]
        assert request["body"]["reasoning"] == {"effort": "medium"}
    # The initial prompt contains only the task; reasoning arrives from model
    # responses, and provider observations arrive only after selected tool calls.
    assert "model-free-encrypted-content" not in json.dumps(initial_task)
    observations = json.loads(
        next((output / "evidence").glob("*/delivered-observations.json")).read_text()
    )
    for message, call in zip(tool_messages, observations["calls"], strict=True):
        assert json.loads(message["content"]) == call["observation"]


def test_native_invalid_tool_attempt_is_preserved_without_provider_call(
    tmp_path: Path, native_transport: dict[str, Any]
) -> None:
    native_transport["responses"] = [
        _response(tool_calls=[_call("invalid-call", "not_a_provider_tool")]),
        _response(),
    ]
    output = tmp_path / "invalid"
    native.run_native_slot(_config(), _slot(), output)
    row = _single_result(output)
    # The pinned native output encodes tool-call objects as JSON strings.
    assert json.loads(row["completion"][0]["tool_calls"][0])["name"] == "not_a_provider_tool"
    assert row["completion"][1]["tool_call_id"] == "invalid-call"
    observations_path = next((output / "evidence").glob("*/delivered-observations.json"))
    assert json.loads(observations_path.read_text())["calls"] == []


def test_native_model_failure_is_not_retried_or_replaced(
    tmp_path: Path, native_transport: dict[str, Any]
) -> None:
    native_transport["responses"] = [
        (503, {"error": {"message": "model-free unavailable", "type": "server_error"}})
    ]
    output = tmp_path / "failure"
    native.run_native_slot(_config(), _slot(), output)
    row = _single_result(output)
    assert len(native_transport["requests"]) == 1
    assert row["error"]["error"] == "ModelError"
    assert row["stop_condition"] == "has_error"
    assert row["trajectory"] == []
    assert len(list((output / "evidence").glob("*/manifest.json"))) == 1
    assert len(native_transport["count_requests"]) == 1
    assert all(client.is_closed for client in native_transport["clients"])


def test_native_budget_stop_prevents_generation_and_keeps_native_failure(
    tmp_path: Path, native_transport: dict[str, Any]
) -> None:
    config = _config()
    config.per_rollout_reservation_usd = 0.0001
    output = tmp_path / "budget-stop"
    native.run_native_slot(config, _slot(), output)
    row = _single_result(output)
    assert len(native_transport["count_requests"]) == 1
    assert native_transport["requests"] == []
    assert row["error"]["error"] == "ModelError"
    assert row["stop_condition"] == "has_error"
    assert row["trajectory"] == []
    assert all(client.is_closed for client in native_transport["clients"])
    observations_path = next((output / "evidence").glob("*/delivered-observations.json"))
    assert json.loads(observations_path.read_text())["calls"] == []


def test_native_slot_refuses_existing_artifacts(
    tmp_path: Path, native_transport: dict[str, Any]
) -> None:
    output = tmp_path / "existing"
    (output / "evidence").mkdir(parents=True)
    with pytest.raises(FileExistsError, match="fresh"):
        native.run_native_slot(_config(), _slot(), output)
    assert native_transport["requests"] == []


def test_native_turn_cap_preserves_undispatched_tool_attempts(
    tmp_path: Path, native_transport: dict[str, Any]
) -> None:
    native_transport["responses"] = [
        _response(tool_calls=[_call("at-turn-cap", "list_products", offset=0, limit=10)])
    ]
    config = _config()
    config.max_turns = 1
    output = tmp_path / "turn-cap"
    native.run_native_slot(config, _slot(), output)
    row = _single_result(output)
    assert row["stop_condition"] == "max_turns_reached"
    assert row["is_completed"] is True
    assert row["error"] is None
    assert json.loads(row["completion"][0]["tool_calls"][0])["id"] == "at-turn-cap"
    observations_path = next((output / "evidence").glob("*/delivered-observations.json"))
    assert json.loads(observations_path.read_text())["calls"] == []
    assert len(native_transport["requests"]) == 1


def test_native_completion_limit_flag_stays_in_trajectory(
    tmp_path: Path, native_transport: dict[str, Any]
) -> None:
    status, response = _response()
    response["status"] = "incomplete"
    response["incomplete_details"] = {"reason": "max_output_tokens"}
    native_transport["responses"] = [(status, response)]
    output = tmp_path / "completion-cap"
    native.run_native_slot(_config(), _slot(), output)
    row = _single_result(output)
    assert row["trajectory"][0]["is_truncated"] is True
    assert row["trajectory"][0]["response"]["message"]["finish_reason"] == "length"
    # Preserve upstream's rollout and completion-level flags together.
    assert row["is_truncated"] is True
