from __future__ import annotations

import importlib
import json
import math
import stat
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "integrations" / "verifiers_dirty_integration"))
contract = importlib.import_module("datalox_dirty_integration.repeat_contract")
ExperimentConfig = contract.ExperimentConfig
ModelConfig = contract.ModelConfig
RolloutSlot = contract.RolloutSlot
build_schedule = contract.build_schedule


def _model() -> dict[str, Any]:
    return {
        "max_completion_tokens": 4096,
        "request_timeout_seconds": 120.0,
        "connect_timeout_seconds": 10.0,
    }


def _config() -> dict[str, Any]:
    return {
        "experiment_id": "serhii-noise-floor-001",
        "source_revision": "a" * 40,
        "bindings": {"task": "sha256:" + "b" * 64},
        "model": _model(),
        "per_rollout_timeout_seconds": 900.0,
        "max_total_cost_usd": 60.0,
        "per_rollout_reservation_usd": 1.0,
        "schedule": [slot.model_dump() for slot in build_schedule()],
    }


def test_schedule_has_sixty_unique_counterbalanced_slots() -> None:
    slots = build_schedule()
    assert len(slots) == 60
    assert len({slot.slot_id for slot in slots}) == 60
    assert [slot.order for slot in slots] == list(range(60))
    assert slots == build_schedule()
    assert Counter((slot.profile, slot.seed) for slot in slots) == {
        (profile, seed): 10 for profile in ("clean", "hostile") for seed in ("1", "7", "23")
    }
    first_profiles: dict[str, Counter[str]] = {seed: Counter() for seed in ("1", "7", "23")}
    for index in range(0, len(slots), 2):
        first, second = slots[index : index + 2]
        assert first.seed == second.seed
        assert first.repetition == second.repetition
        assert {first.profile, second.profile} == {"clean", "hostile"}
        first_profiles[first.seed][first.profile] += 1
    assert all(counts == {"clean": 5, "hostile": 5} for counts in first_profiles.values())


def test_schedule_seed_labels_remain_exact_and_cannot_become_paths() -> None:
    slots = build_schedule(("a/b", "a-b", "α"), 2)
    assert {slot.seed for slot in slots} == {"a/b", "a-b", "α"}
    assert all("/" not in slot.slot_id for slot in slots)
    assert len({slot.slot_id for slot in slots}) == 12


@pytest.mark.parametrize(
    ("seeds", "repetitions"),
    [
        (("1", "1"), 10),
        ((), 10),
        (("",), 10),
        ((1,), 10),
        (["1"], 10),
        (("1",), 0),
        (("1",), -1),
        (("1",), True),
        (("1",), 1.0),
        (("1",), "1"),
    ],
)
def test_schedule_rejects_invalid_inputs(seeds: Any, repetitions: Any) -> None:
    with pytest.raises(ValidationError):
        build_schedule(seeds, repetitions)


def test_defaults_freeze_requested_model_and_native_controls() -> None:
    config = ExperimentConfig.model_validate(_config())
    assert config.model.model == "gpt-5.6-sol"
    assert config.model.reasoning_effort == "medium"
    assert config.model.endpoint == "https://api.openai.com/v1"
    assert config.model.api_key_env == "OPENAI_API_KEY"
    assert config.model.temperature is None
    assert config.model.model_seed is None
    assert config.model.parallel_tool_calls is False
    assert config.max_turns == 30
    assert config.concurrency == 1
    assert config.evaluator_retries == config.client_retries == 0
    assert ExperimentConfig.model_validate_json(config.model_dump_json()) == config


@pytest.mark.parametrize("model", ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"])
def test_explicit_gpt56_family_choice(model: str) -> None:
    assert ModelConfig(**_model(), model=model).model == model


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model", "gpt-4.1-mini"),
        ("model", "gpt-5.6"),
        ("model", "gpt-5.6-sol "),
        ("model", "gpt-5.6-*"),
        ("model", 56),
        ("max_completion_tokens", True),
        ("max_completion_tokens", 4.0),
        ("max_completion_tokens", "4096"),
        ("max_completion_tokens", 0),
        ("request_timeout_seconds", False),
        ("request_timeout_seconds", 0.0),
        ("request_timeout_seconds", "120"),
        ("request_timeout_seconds", math.inf),
        ("connect_timeout_seconds", 121.0),
        ("connect_timeout_seconds", -1.0),
        ("temperature", True),
        ("temperature", "0.6"),
        ("temperature", -0.1),
        ("temperature", 2.1),
        ("temperature", math.nan),
        ("model_seed", 7),
        ("parallel_tool_calls", True),
        ("parallel_tool_calls", 0),
        ("reasoning_effort", "adaptive"),
        ("api_key_env", "OPENAI_API_KEY=secret"),
        ("api_key_env", "sk-not-an-environment-name"),
        ("api_key", "secret"),
        ("fallback_model", "gpt-5.6-luna"),
    ],
)
def test_model_rejects_unfrozen_or_malformed_settings(field: str, value: Any) -> None:
    data = _model()
    data[field] = value
    with pytest.raises(ValidationError):
        ModelConfig.model_validate(data)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://api.openai.com/v1",
        "https://user:secret@api.openai.com/v1",
        "https://user@api.openai.com/v1",
        "https://api.openai.com/v1?api_key=secret",
        "https://api.openai.com/v1?",
        "https://api.openai.com/v1#secret",
        "https://api.openai.com/v1#",
        " https://api.openai.com/v1",
        "https://api.openai.com/\nv1",
        "https://api.openai.com\\evil/v1",
        "https://api.openai.com:99999/v1",
        "https://api.openai.com:0/v1",
        "https://api.openai.com%2fevil/v1",
        "https:///v1",
        "api.openai.com/v1",
    ],
)
def test_endpoint_is_credential_free_https(endpoint: str) -> None:
    with pytest.raises(ValidationError):
        ModelConfig(**_model(), endpoint=endpoint)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "datalox_repeat_experiment_v2"),
        ("experiment_id", "../pilot"),
        ("source_revision", "abcdef"),
        ("source_revision", "G" * 40),
        ("bindings", {}),
        ("bindings", {"task": "b" * 64}),
        ("bindings", {"task": "sha256:" + "B" * 64}),
        ("bindings", {"task": "sha256:" + "b" * 63}),
        ("bindings", {"": "sha256:" + "b" * 64}),
        ("seeds", ("1", "1")),
        ("seeds", ()),
        ("repetitions", True),
        ("repetitions", 10.0),
        ("max_turns", True),
        ("max_turns", "30"),
        ("max_turns", 0),
        ("per_rollout_timeout_seconds", False),
        ("per_rollout_timeout_seconds", 0),
        ("max_total_cost_usd", math.inf),
        ("max_total_cost_usd", 0.0),
        ("per_rollout_reservation_usd", 61.0),
        ("per_rollout_reservation_usd", False),
        ("concurrency", True),
        ("concurrency", 1.0),
        ("concurrency", 2),
        ("evaluator_retries", False),
        ("evaluator_retries", 1),
        ("client_retries", False),
        ("client_retries", 0.0),
        ("client_retries", 1),
        ("unexpected", "ignored?"),
    ],
)
def test_experiment_rejects_invalid_or_unfrozen_configuration(field: str, value: Any) -> None:
    data = _config()
    data[field] = value
    with pytest.raises(ValidationError):
        ExperimentConfig.model_validate(data)


@pytest.mark.parametrize("change", ["duplicate", "reorder", "missing", "seed", "order", "extra"])
def test_experiment_requires_the_exact_saved_schedule(change: str) -> None:
    data = _config()
    schedule = data["schedule"]
    if change == "duplicate":
        schedule[1] = deepcopy(schedule[0])
    elif change == "reorder":
        schedule[0], schedule[1] = schedule[1], schedule[0]
    elif change == "missing":
        schedule.pop()
    elif change == "seed":
        schedule[0]["seed"] = "different"
    elif change == "order":
        schedule[0]["order"] = 1
    else:
        schedule[0]["extra"] = "unknown"
    with pytest.raises(ValidationError):
        ExperimentConfig.model_validate(data)


@pytest.mark.parametrize(("field", "value"), [("order", False), ("repetition", True)])
def test_slot_integer_controls_reject_booleans(field: str, value: Any) -> None:
    slot = build_schedule()[0].model_dump()
    slot[field] = value
    with pytest.raises(ValidationError):
        RolloutSlot.model_validate(slot)


def test_custom_schedule_requires_explicit_matching_parameters() -> None:
    data = _config()
    data.update(seeds=("7",), repetitions=2, schedule=build_schedule(("7",), 2))
    config = ExperimentConfig.model_validate(data)
    assert len(config.schedule) == 4
    assert ExperimentConfig.model_validate_json(config.model_dump_json()) == config


def test_json_schema_is_generated_from_executable_contract() -> None:
    schema = contract.experiment_json_schema()
    assert schema == ExperimentConfig.model_json_schema()
    Draft202012Validator.check_schema(schema)
    value = ExperimentConfig.model_validate(_config()).model_dump(mode="json")
    Draft202012Validator(schema).validate(value)
    value["unknown"] = 1
    assert list(Draft202012Validator(schema).iter_errors(value))
    assert all(
        item.get("additionalProperties") is False
        for item in schema["$defs"].values()
        if item.get("type") == "object"
    )


def test_json_artifact_creation_is_private_exclusive_and_canonical(tmp_path: Path) -> None:
    path = tmp_path / "experiment.json"
    value = ExperimentConfig.model_validate(_config()).model_dump(mode="json")
    contract.write_json_exclusive(path, value)
    assert json.loads(path.read_text()) == value
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert contract.canonical_sha256(json.loads(path.read_text())) == contract.canonical_sha256(
        value
    )
    with pytest.raises(FileExistsError):
        contract.write_json_exclusive(path, {"overwritten": True})
    assert json.loads(path.read_text()) == value
    invalid = tmp_path / "invalid.json"
    with pytest.raises(ValueError):
        contract.write_json_exclusive(invalid, {"value": math.nan})
    assert not invalid.exists()
