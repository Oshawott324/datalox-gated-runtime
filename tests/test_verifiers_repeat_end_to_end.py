"""Join native model-free transport, evidence, cohort and analysis contracts.

Only inference transport and subprocess isolation are replaced here. Fixed model
responses are collection test fixtures, never pilot or model-performance data.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest
import test_verifiers_repeat_native as native_fixtures
from test_verifiers_repeat_native import _call, _response

native_transport = native_fixtures.native_transport

driver = importlib.import_module("datalox_dirty_integration.repeats")
contract = importlib.import_module("datalox_dirty_integration.repeat_contract")
native = importlib.import_module("datalox_dirty_integration.repeat_native")
evidence = importlib.import_module("datalox_dirty_integration.repeat_evidence")
analysis = importlib.import_module("datalox_dirty_integration.repeat_analysis")


def _config(*, max_turns: int = 30) -> Any:
    model = contract.ModelConfig(
        max_completion_tokens=4096,
        request_timeout_seconds=30.0,
        connect_timeout_seconds=5.0,
    )
    return contract.ExperimentConfig(
        experiment_id="model-free-native-cohort",
        source_revision="a" * 40,
        bindings=driver.capture_bindings(model),
        model=model,
        seeds=("7",),
        repetitions=1,
        max_turns=max_turns,
        per_rollout_timeout_seconds=120.0,
        max_total_cost_usd=2.0,
        per_rollout_reservation_usd=1.0,
        schedule=contract.build_schedule(("7",), 1),
    )


@pytest.fixture
def native_launch(
    monkeypatch: pytest.MonkeyPatch, native_transport: dict[str, Any]
) -> dict[str, Any]:
    launches: list[str] = []

    def launch(config: Any, slot: Any, output: Path, manifest: Path) -> None:
        launches.append(slot.slot_id)
        native.run_native_slot(config, slot, output)

    monkeypatch.setattr(driver, "_launch_slot", launch)
    native_transport["launches"] = launches
    return native_transport


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (path / "rollouts.jsonl").read_text().splitlines()]


def test_native_clean_hostile_cohort_audits_and_reanalyzes_byte_identically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_launch: dict[str, Any]
) -> None:
    native_launch["responses"] = [
        _response(
            tool_calls=[_call("clean-read", "list_products", offset=0, limit=10)],
            response_id="resp_clean_read",
        ),
        _response(response_id="resp_clean_final"),
        _response(
            tool_calls=[_call("hostile-read", "list_products", offset=0, limit=10)],
            response_id="resp_hostile_read",
        ),
        _response(response_id="resp_hostile_final"),
    ]
    config = _config()
    source = tmp_path / "cohort"
    collection = driver.run_experiment(config, source, spend_approved=True)
    assert collection["status"] == "completed", collection
    assert native_launch["launches"] == [slot.slot_id for slot in config.schedule]
    assert len(native_launch["requests"]) == 4
    assert [slot["status"] for slot in collection["slots"]] == ["completed", "completed"]

    monkeypatch.delenv("OPENAI_API_KEY")
    first, second = tmp_path / "analysis-first", tmp_path / "analysis-second"
    result = driver.analyze_experiment(source, first)
    assert driver.analyze_experiment(source, second) == result
    for name in ("summary.json", "summary.md", "rollouts.jsonl"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    rows = _rows(first)
    assert len(rows) == 2
    assert {row["profile"] for row in rows} == {"clean", "hostile"}
    assert all(row["audit"]["passed"] is True for row in rows)
    assert all(row["task_correctness"]["passed"] is False for row in rows)
    assert all(row["native"]["termination_reason"] == "no_tools_called" for row in rows)
    assert all(len(row["provider_calls"]) == 1 for row in rows)
    assert (
        analysis.analyze_rows(rows, [slot.model_dump(mode="json") for slot in config.schedule])
        == result
    )
    assert len(native_launch["requests"]) == 4


def test_native_turn_cap_pending_attempts_survive_collection_and_analysis(
    tmp_path: Path, native_launch: dict[str, Any]
) -> None:
    native_launch["responses"] = [
        _response(
            tool_calls=[_call("clean-pending", "list_products", offset=0, limit=10)],
            response_id="resp_clean_pending",
        ),
        _response(
            tool_calls=[_call("hostile-pending", "list_products", offset=0, limit=10)],
            response_id="resp_hostile_pending",
        ),
    ]
    config = _config(max_turns=1)
    source = tmp_path / "turn-capped"
    collection = driver.run_experiment(config, source, spend_approved=True)
    assert collection["status"] == "completed", collection
    destination = tmp_path / "analysis"
    driver.analyze_experiment(source, destination)
    rows = _rows(destination)
    for row, slot in zip(rows, config.schedule, strict=True):
        assert row["native"]["termination_reason"] == "max_turns_reached"
        assert row["provider_calls"] == []
        assert row["tool_attempts"] == 1
        assert row["invalid_tool_attempts"] == 0
        assert len(row["unexecuted_tool_attempts"]) == 1
        assert (
            evidence.collect_slot(source / "slots" / slot.slot_id, config, slot, verify_index=True)
            == row
        )
    assert len(native_launch["requests"]) == 2


def test_native_api_failure_stops_without_replacement_and_analyzes_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_launch: dict[str, Any]
) -> None:
    native_launch["responses"] = [
        (503, {"error": {"message": "model-free unavailable", "type": "server_error"}})
    ]
    config = _config()
    source = tmp_path / "api-failed"
    collection = driver.run_experiment(config, source, spend_approved=True)
    assert collection["status"] == "incomplete"
    assert [slot["status"] for slot in collection["slots"]] == ["collection_error", "unstarted"]
    assert native_launch["launches"] == [config.schedule[0].slot_id]
    assert len(native_launch["requests"]) == 1
    native_row = json.loads(
        (source / "slots" / config.schedule[0].slot_id / "native" / "results.jsonl").read_text()
    )
    assert native_row["error"]["error"] == "ModelError"
    assert not (source / "slots" / config.schedule[1].slot_id).exists()
    monkeypatch.delenv("OPENAI_API_KEY")
    destination = tmp_path / "analysis"
    driver.analyze_experiment(source, destination)
    rows = _rows(destination)
    assert [row["status"] for row in rows] == ["collection_error", "unstarted"]
    assert len(native_launch["requests"]) == 1
