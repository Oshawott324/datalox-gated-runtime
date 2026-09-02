from __future__ import annotations

import ast
import asyncio
import base64
import importlib.util
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from datalox_gated_runtime.harness_adapters import envfactory

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_AGENT_DATA_ATTRIBUTES = {
    "expected",
    "ground_truth",
    "label",
    "oracle",
    "prompt",
    "reward",
}


def _json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _attribute_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}


def test_every_checked_rollout_adapter_declares_the_three_information_planes() -> None:
    schema = _json(ROOT / "schemas" / "rollout-information-boundary-v1.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)

    rollout_directories = {
        path.parent for path in (ROOT / "integrations").glob("*/launch_fragment.sh")
    }
    rollout_directories.add(ROOT / "integrations" / "verifiers_dirty_integration")
    manifests = sorted((ROOT / "integrations").glob("*/rollout-information-boundary.json"))
    assert {path.parent for path in manifests} == rollout_directories
    assert {path.parent.name for path in manifests} == {
        "slime",
        "verl",
        "verifiers_dirty_integration",
    }

    for path in manifests:
        value = _json(path)
        validator.validate(value)
        assert value["integration_id"] == path.parent.name
        assert value["task_plane"]["agent_visible"] is True
        assert value["observation_plane"]["agent_visible"] is True
        assert value["evaluation_plane"]["agent_visible"] is False


def test_public_product_contract_and_primary_docs_bind_the_information_boundary() -> None:
    contract = _json(ROOT / "product-contract.json")
    assert contract["rollout_agent_input"] == ("task_objectives_and_agent_visible_constraints_only")
    assert contract["rollout_observation_flow"] == (
        "causal_after_agent_or_declared_environment_action"
    )
    assert contract["rollout_evaluation_ground_truth"] == (
        "trusted_generation_oracle_verifier_only"
    )
    assert contract["rollout_information_boundary"] == ("datalox_rollout_information_boundary_v1")

    for relative in (
        "AGENTS.md",
        "README.md",
        "docs/provider-foundry.md",
        "docs/transparent-interception.md",
        "docs/what-we-are-building.md",
        "docs/verl-grpo-rollouts.md",
        "docs/slime-rollouts.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "rollout-information-boundary.md" in text


def test_rollout_pool_wire_contract_defines_no_task_or_evaluation_fields() -> None:
    schema = _json(ROOT / "schemas" / "rollout-pool-api-v1.schema.json")
    validator = jsonschema.Draft202012Validator(schema)
    acquire = {
        "schema_version": "datalox_rollout_pool_acquire_request_v1",
        "uid": "task-1",
        "session_id": "rollout-1",
        "environment_seed": 0,
    }
    validator.validate(acquire)

    for field in ("task", "prompt", "observation", "evaluation_ground_truth", "oracle"):
        with pytest.raises(jsonschema.ValidationError):
            validator.validate({**acquire, field: "forbidden-cross-plane-payload"})

    execute = {
        "schema_version": "datalox_rollout_pool_exec_request_v1",
        "lease_token": "lease-secret",
        "task_image": "consumer/provider-tool@sha256:example",
        "command": ["python3", "/opt/consumer/provider_tool.py"],
    }
    validator.validate(execute)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**execute, "expected": {"status": "complete"}})


def test_verl_checked_row_contains_task_plane_and_identity_only() -> None:
    rows_path = ROOT / "integrations" / "verl" / "agent_loop_rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    row = rows[0]
    assert set(row) == {"agent_name", "extra_info", "raw_prompt", "session_id", "uid"}
    assert set(row["extra_info"]) == {"datalox"}
    assert set(row["extra_info"]["datalox"]) == {"seed"}
    assert row["raw_prompt"] == [
        {
            "content": (
                "Create a provider record named sample-17, then report the provider response."
            ),
            "role": "user",
        }
    ]


def test_checked_rollout_adapters_do_not_read_task_or_evaluation_fields() -> None:
    checked_sources = (
        ROOT / "src" / "datalox_gated_runtime" / "integrations" / "slime.py",
        ROOT / "src" / "datalox_gated_runtime" / "integrations" / "verl.py",
        ROOT / "integrations" / "slime" / "provider_tool.py",
        ROOT / "integrations" / "verl" / "provider_tools.py",
    )
    for path in checked_sources:
        assert FORBIDDEN_AGENT_DATA_ATTRIBUTES.isdisjoint(_attribute_names(path)), path

    slime_tool_source = checked_sources[2].read_text(encoding="utf-8")
    slime_tool_tree = ast.parse(slime_tool_source, filename=str(checked_sources[2]))
    function_names = {
        node.name
        for node in ast.walk(slime_tool_tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    assert function_names == {"get_example_record"}
    assert "slime.rollout" not in slime_tool_source
    assert "datalox_custom_generate" not in slime_tool_source


def test_slime_provider_observation_is_created_only_when_the_tool_is_invoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = ROOT / "integrations" / "slime" / "provider_tool.py"
    spec = importlib.util.spec_from_file_location("datalox_checked_slime_provider_tool", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    calls: list[tuple[str, ...]] = []

    class _Execution:
        async def exec(self, command: tuple[str, ...]) -> SimpleNamespace:
            calls.append(command)
            envelope = {
                "schema_version": "datalox_provider_https_result_v1",
                "transport_ok": True,
                "status_code": 200,
                "headers": [["Content-Type", "application/json"]],
                "body_base64": base64.b64encode(b'{"id":"rec_1"}').decode("ascii"),
                "error": None,
            }
            return SimpleNamespace(
                consumer_exit_code=0,
                stdout=json.dumps(envelope, sort_keys=True, separators=(",", ":")),
                stderr="",
            )

    execution = _Execution()
    monkeypatch.setattr(module, "current_slime_provider_execution", lambda: execution)
    assert calls == []

    observation = asyncio.run(module.get_example_record())

    assert len(calls) == 1
    assert calls[0][:2] == ("python3", "/opt/datalox/provider_call.py")
    assert observation == {
        "status_code": 200,
        "headers": [["Content-Type", "application/json"]],
        "body": '{"id":"rec_1"}',
    }


def test_active_rollout_examples_contain_no_prefetch_prompt_mutation_pattern() -> None:
    active_paths = (
        ROOT / "integrations" / "slime" / "provider_tool.py",
        ROOT / "integrations" / "slime" / "launch_fragment.sh",
        ROOT / "integrations" / "slime" / "README.md",
        ROOT / "docs" / "slime-rollouts.md",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in active_paths)
    assert "sample.prompt =" not in combined
    assert "add it to the task prompt" not in combined
    assert "integrations.slime.user_task" not in combined


def test_environment_runtime_does_not_load_oracle_or_verifier_artifacts() -> None:
    source = inspect.getsource(envfactory._ProjectionRuntime)
    for forbidden in (
        "tests/trajectories",
        "trajectory",
        "oracle",
        "verifier",
        "reference_task",
        "reward",
    ):
        assert forbidden not in source
