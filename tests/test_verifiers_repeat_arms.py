"""Offline native-loop fixtures for the V2 controller, never model evidence."""

from collections import Counter
from copy import deepcopy
import hashlib
import json

import pytest
import test_verifiers_repeat_native as fixtures

from datalox_dirty_integration.repeat_arms import (
    ARMS,
    ArmExperimentConfig,
    BUDGET_STOP,
    build_arm_schedule,
    parse_experiment,
)
from datalox_dirty_integration.repeat_contract import ModelConfig
from datalox_dirty_integration.repeat_evidence import collect_slot, RepeatEvidenceError
from datalox_dirty_integration.repeat_native import run_native_slot
from datalox_dirty_integration.repeats import capture_bindings
from datalox_dirty_integration.repeat_public import project_slot, check_row

native_transport = fixtures.native_transport


def config():
    model = ModelConfig(
        max_completion_tokens=4096, request_timeout_seconds=30.0, connect_timeout_seconds=5.0
    )
    return ArmExperimentConfig(
        experiment_id="offline-three-arm-fixture",
        source_revision="a" * 40,
        bindings=capture_bindings(model),
        model=model,
        per_rollout_timeout_seconds=120.0,
        max_total_cost_usd=7.0,
        per_rollout_reservation_usd=0.4,
        schedule=build_arm_schedule(),
    )


def test_schedule_is_fixed_and_balanced():
    schedule = build_arm_schedule()
    assert len(schedule) == 90
    assert Counter(slot.arm for slot in schedule) == dict.fromkeys(ARMS, 30)
    orders = Counter(tuple(slot.arm for slot in schedule[i : i + 3]) for i in range(0, 90, 3))
    assert len(orders) == 6 and set(orders.values()) == {5}
    for profile in ("clean", "hostile"):
        for seed in ("1", "7", "23"):
            for arm in ARMS:
                positions = Counter(
                    slot.order % 3
                    for slot in schedule
                    if (slot.profile, slot.seed, slot.arm) == (profile, seed, arm)
                )
                assert sorted(positions.values()) == [1, 2, 2]


def test_frozen_native_configs_admit_v1_and_v2(native_transport):
    from test_verifiers_repeat_end_to_end import _config

    frozen = config()
    assert parse_experiment(frozen.model_dump(mode="json")) == frozen
    old = _config()
    assert parse_experiment(old.model_dump(mode="json")) == old
    value = frozen.model_dump(mode="json")
    value["schedule"][0]["arm"] = "budget12"
    with pytest.raises(ValueError):
        parse_experiment(value)


@pytest.mark.parametrize(
    "requested",
    [
        ("list_products", {"offset": 0, "limit": 10}),
        ("list_products", {"offset": "0", "limit": 10}),
        ("create_cart", {"email": "fixture@example.test", "region_id": "reg_01"}),
        ("create_cart", {"email": 123, "region_id": "reg_01"}),
    ],
)
@pytest.mark.parametrize("same_batch", [False, True])
def test_call_13_stops_before_read_or_write_and_exports_native_evidence(
    tmp_path,
    native_transport,
    requested,
    same_batch,
):
    frozen = config()
    slot = next(
        slot for slot in frozen.schedule if slot.arm == "budget12" and slot.profile == "hostile"
    )
    calls = [fixtures._call(f"call-{i}", "list_products", offset=0, limit=10) for i in range(1, 13)]
    rejected = fixtures._call("call-13", requested[0], **requested[1])
    if same_batch:
        responses = [
            fixtures._response(tool_calls=calls[:11]),
            fixtures._response(tool_calls=[calls[11], rejected]),
        ]
    else:
        responses = [
            fixtures._response(tool_calls=calls),
            fixtures._response(tool_calls=[rejected]),
        ]
    native_transport["responses"] = responses
    run_native_slot(frozen, slot, tmp_path)
    native = fixtures._single_result(tmp_path)
    assert native["stop_condition"] == BUDGET_STOP
    assert native["error"] is None and native["is_completed"] is True
    assert len(native_transport["requests"]) == 2
    row = collect_slot(tmp_path, frozen, slot)
    assert len(row["provider_calls"]) == 12
    assert len(row["interventions"]) == 12
    assert row["call_budget"]["executed_provider_calls"] == 12
    assert row["unexecuted_tool_attempts"][0]["id"] == "call-13"
    tools = [message for message in native["completion"] if message["role"] == "tool"]
    assert len(tools) == 12 and tools[-1]["tool_call_id"] == "call-12"
    assert not any(message["tool_call_id"] == "call-13" for message in tools)
    assert row == collect_slot(tmp_path, frozen, slot, verify_index=True)
    public = project_slot(tmp_path, frozen, slot)
    assert "Finished fixture" not in json.dumps(public)
    assert "encrypted_content" not in json.dumps(public)
    for field, value in (
        ("limit", None),
        ("executed_provider_calls", 13),
        ("termination_reason", "no_tools_called"),
    ):
        tampered = deepcopy(public)
        tampered["call_budget"][field] = value

        def digest(value):
            payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
            return "sha256:" + hashlib.sha256(payload).hexdigest()

        tampered["episode_manifest"]["artifacts"]["call-budget.json"] = digest(
            tampered["call_budget"]
        )
        tampered["source_sha256"]["episode_manifest"] = digest(tampered["episode_manifest"])
        with pytest.raises(RepeatEvidenceError):
            check_row(tampered, frozen, slot)

    execution_path = tmp_path / "native" / "execution.json"
    execution = json.loads(execution_path.read_text())
    original = deepcopy(execution)
    execution["experiment_arm"]["arm"] = "baseline"
    execution_path.write_text(json.dumps(execution))
    with pytest.raises(RepeatEvidenceError, match="experiment arm"):
        collect_slot(tmp_path, frozen, slot)
    execution_path.write_text(json.dumps(original))

    # Forging a different native termination must fail even when the controller
    # receipt is rewritten consistently and its manifest digest is refreshed.
    native["stop_condition"] = "max_turns_reached"
    native["final_env_response"] = None
    (tmp_path / "native" / "results.jsonl").write_text(json.dumps(native) + "\n")
    with pytest.raises(RepeatEvidenceError, match="actual turns"):
        collect_slot(tmp_path, frozen, slot)


def test_call_12_runs_and_final_answer_remains_available(tmp_path, native_transport):
    frozen = config()
    slot = next(slot for slot in frozen.schedule if slot.arm == "budget12")
    native_transport["responses"] = [
        fixtures._response(
            tool_calls=[
                fixtures._call(f"call-{i}", "list_products", offset=0, limit=10)
                for i in range(1, 12)
            ]
        ),
        fixtures._response(
            tool_calls=[
                fixtures._call(
                    "call-12-write",
                    "create_cart",
                    email="fixture@example.test",
                    region_id="region_datalox_us",
                )
            ]
        ),
        fixtures._response(),
    ]
    run_native_slot(frozen, slot, tmp_path)
    row = collect_slot(tmp_path, frozen, slot)
    assert row["native"]["termination_reason"] == "no_tools_called"
    assert len(row["provider_calls"]) == 12
    assert row["provider_calls"][-1]["request"]["method"] == "POST"
    assert row["provider_calls"][-1]["observation"]["status_code"] < 300
    assert row["call_budget"]["rejection"] is None
    assert len(native_transport["requests"]) == 3


def test_inert_label_never_enters_model_requests_or_environment_inputs(tmp_path, native_transport):
    frozen = config()
    requests = []
    effects = []
    for arm in ("baseline", "inert-reporting-label"):
        slot = next(slot for slot in frozen.schedule if slot.arm == arm and slot.profile == "clean")
        native_transport["responses"] = [
            fixtures._response(
                response_id="resp_read_identical",
                tool_calls=[
                    fixtures._call("read-identical", "list_products", offset=0, limit=10),
                    fixtures._call("read-next", "list_products", offset=10, limit=10),
                ],
            ),
            fixtures._response(
                response_id="resp_write_identical",
                tool_calls=[
                    fixtures._call(
                        "write-identical",
                        "create_cart",
                        email="fixture@example.test",
                        region_id="region_datalox_us",
                    )
                ],
            ),
            fixtures._response(response_id="resp_identical"),
        ]
        output = tmp_path / arm
        run_native_slot(frozen, slot, output)
        row = collect_slot(output, frozen, slot)
        # Controller receipt IDs differ across fresh leases. Compare the exact
        # provider calls/observations and policy decisions, not receipt identity.
        effects.append(
            (
                row["provider_calls"],
                [
                    {
                        key: event[key]
                        for key in (
                            "logical_request_index",
                            "decision",
                            "applied",
                            "observation_changed",
                            "delivered",
                        )
                    }
                    for event in row["interventions"]
                ],
            )
        )
        requests.append([request["body"] for request in native_transport["requests"][-3:]])
        execution = json.loads((output / "native" / "execution.json").read_text())
        assert "inert-reporting-label" not in json.dumps(execution["environment_args"]).replace(
            str(output), ""
        )
        evidence = next((output / "evidence").glob("*/manifest.json"))
        assert "inert-reporting-label" not in evidence.read_text()
        assert "inert-reporting-label" not in json.dumps(requests[-1])
    assert requests[0] == requests[1]
    assert effects[0] == effects[1]


def test_v2_budget_outcome_is_collected_and_all_90_runs_are_analyzed(
    tmp_path,
    monkeypatch,
    native_transport,
):
    from datalox_dirty_integration import repeats

    frozen = config()
    for slot in frozen.schedule:
        if slot.order == 1:
            native_transport["responses"].extend(
                [
                    fixtures._response(
                        tool_calls=[
                            fixtures._call(
                                f"call-{i}",
                                "list_products",
                                offset=0,
                                limit=10,
                            )
                            for i in range(1, 14)
                        ]
                    ),
                ]
            )
        else:
            native_transport["responses"].append(fixtures._response())
    monkeypatch.setattr(
        repeats, "_launch_slot", lambda cfg, slot, out, manifest: run_native_slot(cfg, slot, out)
    )
    source = tmp_path / "collection"
    collection = repeats.run_experiment(frozen, source, spend_approved=True)
    assert collection["status"] == "completed"
    assert len(collection["slots"]) == 90
    report = repeats.analyze_experiment(source, tmp_path / "analysis")
    assert report["cohort_complete"] is True
    assert report["counts"]["completed"] == 90
    assert len(report["within_profile_seed_repetition"]) == 30
    comparison = report["within_profile_seed_repetition"][0]["arms"]
    assert comparison["budget12"]["budget_terminated"] is True
    assert comparison["budget12"]["provider_calls"] == 12
    assert comparison["baseline"]["provider_calls"] == 0
    assert set(report["arms"]) == set(ARMS)
    from datalox_dirty_integration.repeat_analysis import analyze_rows

    rows = [
        json.loads(line)
        for line in (tmp_path / "analysis" / "rollouts.jsonl").read_text().splitlines()
    ]
    incomplete = rows[:2] + [
        {**slot.model_dump(mode="json"), "status": "unstarted"} for slot in frozen.schedule[2:]
    ]
    partial = analyze_rows(incomplete, [slot.model_dump(mode="json") for slot in frozen.schedule])
    assert partial["cohort_complete"] is False
    assert partial["counts"]["completed"] == 2
    assert partial["counts"]["unstarted"] == 88
