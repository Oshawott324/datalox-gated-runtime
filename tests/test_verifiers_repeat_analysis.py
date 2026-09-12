"""Model-free fixtures for analysis logic, never reported as model rollouts."""

from __future__ import annotations

import importlib
import json
import math
import sys
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "integrations" / "verifiers_dirty_integration"))
analysis = importlib.import_module("datalox_dirty_integration.repeat_analysis")
contract = importlib.import_module("datalox_dirty_integration.contract")


def _call(operation=contract.LIST_PRODUCTS_OPERATION, *, index=1, offset=0, status=200, body=None):
    return {
        "operation_id": operation,
        "intervention_logical_request_index": index
        if operation == contract.LIST_PRODUCTS_OPERATION
        else None,
        "request": {
            "method": "GET" if operation == contract.LIST_PRODUCTS_OPERATION else "POST",
            "authority": "provider.example.test",
            "path": "/store/products",
            "query": [["offset", offset], ["limit", 10]],
            "body": None,
        },
        "observation": {
            "status_code": status,
            "headers": {},
            "body": {"products": [{"id": f"product_{offset}"}], "count": 20}
            if body is None
            else body,
        },
    }


def _row(
    slot="one",
    *,
    repetition=0,
    profile="clean",
    seed="7",
    calls=None,
    passed=True,
    score=1.0,
    invalid=0,
):
    calls = [_call()] if calls is None else deepcopy(calls)
    events, bases = [], {}
    for call in calls:
        index = call["intervention_logical_request_index"]
        if index is None:
            continue
        response = deepcopy(call["observation"])
        quota = response["status_code"] == 429
        digest = None if quota else analysis._digest(response)
        events.append(
            {
                "logical_request_index": index,
                "operation_id": contract.LIST_PRODUCTS_OPERATION,
                "applied": quota,
                "observation_changed": quota,
                "outcome": "delivered",
                "decision": {"kind": "quota_response" if quota else "none"},
                "base": {
                    "invoked": not quota,
                    "event_id": None if quota else f"local_{slot}_{index}",
                    "response_sha256": digest,
                },
                "delivered": {"response": response},
            }
        )
        if not quota:
            bases[str(index)] = response
    failed = sum(call["observation"]["status_code"] >= 300 for call in calls)
    return {
        "slot_id": slot,
        "profile": profile,
        "seed": seed,
        "repetition": repetition,
        "status": "completed",
        "provider_calls": calls,
        "interventions": events,
        "base_responses": bases,
        "tool_attempts": len(calls) + invalid,
        "invalid_tool_attempts": invalid,
        "task_correctness": {
            "passed": passed,
            "score": float(passed),
            "failed_check_ids": [] if passed else ["fixture_goal"],
            "checks": [{"check_id": "fixture_goal", "passed": passed, "evidence": {}}],
        },
        "request_discipline": {
            "score": score,
            "minimum_call_count": 1,
            "actual_call_count": len(calls),
            "failed_call_count": failed,
            "efficiency": score,
            "failure_factor": 1 / (1 + failed),
            "reason_codes": [],
        },
        "audit": {
            "passed": True,
            "event_count": len(events),
            "applied_count": sum(e["applied"] for e in events),
            "observation_changed_count": sum(e["observation_changed"] for e in events),
            "observational_noop_count": 0,
        },
        "native": {
            "termination_reason": "no_tools_called",
            "model": "synthetic-test-fixture",
            "backend_fingerprint": None,
            "usage": {"input_tokens": 2, "output_tokens": 3},
            "duration_seconds": 1.0,
            "agent_messages": [{"role": "assistant", "content": "done"}],
            "is_completed": True,
            "is_truncated": False,
        },
    }


def _schedule(rows):
    return [{key: row[key] for key in analysis.IDENTITY_FIELDS} for row in rows]


def _run(rows):
    return analysis.analyze_rows(rows, _schedule(rows))


def test_identical_rollouts_have_zero_observed_variation_and_exact_denominators():
    rows = [_row(), _row("two", repetition=1)]
    summary = _run(rows)
    assert summary["counts"] == {
        "scheduled": 2,
        "attempted": 2,
        "completed": 2,
        "audited": 2,
        "collection_errors": 0,
        "unstarted": 0,
    }
    group = summary["groups"][0]
    assert group["all_completed"]["metrics"]["provider_calls"]["sample_sd"] == 0
    assert group["all_completed"]["distinct_provider_traces"] == 1
    assert group["all_completed"]["distinct_observation_traces"] == 1
    assert group["task_success"]["n"] == 2
    assert group["task_success"]["wilson_95"]["low"] == pytest.approx(0.3423802275)
    assert len(summary["pairwise_divergences"]) == 1
    pair = summary["pairwise_divergences"][0]
    assert pair["request"] is pair["observation"] is None
    assert summary["divergence_example"] is None
    assert summary["identical_provider_pair"] == pair
    assert summary["groups"][1]["scope"] == "schedule_mixture"


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ([1], [True]),
        ([1], ["1"]),
        ([1], [1.0]),
        ([None], []),
        ([{"query": [["x", "1"], ["x", "2"]]}], [{"query": [["x", "2"], ["x", "1"]]}]),
        ([{"id": "provider_1"}], [{"id": "provider_2"}]),
    ],
)
def test_first_divergence_preserves_types_order_presence_and_provider_ids(left, right):
    result = analysis.first_divergence(left, right)
    assert result["index"] == 0 and result["position"] == 1
    assert result["left_present"] is True
    assert result["right_present"] is bool(right)


def test_dictionary_order_is_not_observable_json_semantics():
    assert analysis.first_divergence([{"a": 1, "b": 2}], [{"b": 2, "a": 1}]) is None


def test_inserted_read_has_exact_first_divergence_without_realigning():
    original = [_call(index=1, offset=0), _call(index=2, offset=10), _call(index=3, offset=20)]
    extra = [
        _call(index=1, offset=0),
        _call(index=2, offset=0),
        _call(index=3, offset=10),
        _call(index=4, offset=20),
    ]
    summary = _run([_row(calls=original), _row("two", repetition=1, calls=extra)])
    pair = summary["pairwise_divergences"][0]
    assert pair["request"]["position"] == pair["observation"]["position"] == 2
    assert pair["left_context"]["logical_request_index"] == 2
    assert pair["right_context"]["logical_request_index"] == 2
    assert pair["left_context"]["request"]["query"][0] == ["offset", 10]
    assert pair["right_context"]["request"]["query"][0] == ["offset", 0]
    assert pair["left_context"]["base_response"] == original[1]["observation"]
    assert pair["left_context"]["base_receipt"]["response_sha256"] == analysis._digest(
        original[1]["observation"]
    )


def test_extra_write_does_not_advance_index_and_invalid_attempt_is_separate():
    calls = [_call(), _call(contract.CREATE_CART_OPERATION), _call(index=2, offset=10)]
    summary = _run([_row(calls=calls, invalid=1)])
    metrics = summary["rollouts"][0]["metrics"]
    assert metrics["provider_calls"] == 3
    assert metrics["tool_attempts"] == 4
    assert metrics["invalid_tool_attempts"] == 1
    assert metrics["indexed_reads"] == 2
    assert metrics["write_calls"] == 1


def test_turn_cap_preserves_unexecuted_attempts_as_valid_completed_data():
    row = _row(calls=[], passed=False, score=0.0)
    pending = {"id": "call-at-turn-cap", "name": "list_products", "arguments": '{"offset":0}'}
    row["unexecuted_tool_attempts"] = [pending]
    row["tool_attempts"] = 1
    row["native"]["agent_messages"] = [{"role": "assistant", "tool_calls": [json.dumps(pending)]}]
    row["native"].update(
        termination_reason="max_turns_reached", is_completed=True, is_truncated=True
    )
    summary = _run([row])
    report = summary["rollouts"][0]
    assert summary["cohort_complete"] is True
    assert summary["counts"]["completed"] == 1
    assert report["unexecuted_tool_attempts"] == [pending]
    assert report["metrics"]["tool_attempts"] == 1
    assert report["metrics"]["unexecuted_tool_attempts"] == 1
    assert report["metrics"]["invalid_tool_attempts"] == 0
    assert report["metrics"]["provider_calls"] == 0
    assert summary["groups"][0]["task_success"]["n"] == 1
    assert summary["groups"][0]["all_completed"]["metrics"]["unexecuted_tool_attempts"]["max"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_stop",
        "not_completed",
        "duplicate_id",
        "missing_arguments",
        "wrong_count",
        "native_mismatch",
    ],
)
def test_unexecuted_attempts_require_native_cap_identity_and_full_accounting(mutation):
    row = _row(calls=[], passed=False, score=0.0)
    row["tool_attempts"] = 1
    row["unexecuted_tool_attempts"] = [
        {"id": "pending", "name": "list_products", "arguments": "{}"}
    ]
    row["native"]["agent_messages"] = [
        {"role": "assistant", "tool_calls": [json.dumps(row["unexecuted_tool_attempts"][0])]}
    ]
    row["native"].update(termination_reason="max_turns_reached", is_completed=True)
    if mutation == "wrong_stop":
        row["native"]["termination_reason"] = "no_tools_called"
    elif mutation == "not_completed":
        row["native"]["is_completed"] = False
    elif mutation == "duplicate_id":
        row["unexecuted_tool_attempts"] *= 2
        row["tool_attempts"] = 2
    elif mutation == "missing_arguments":
        row["unexecuted_tool_attempts"][0].pop("arguments")
    elif mutation == "native_mismatch":
        row["native"]["agent_messages"][0]["tool_calls"] = []
    else:
        row["tool_attempts"] = 0
    with pytest.raises(analysis.RepeatAnalysisError):
        _run([row])


def test_quota_and_truncation_remain_visible_with_success_only_separate():
    calls = [
        _call(),
        _call(index=2, status=429),
        _call(contract.CREATE_CART_OPERATION),
        _call(contract.UPDATE_LINE_ITEM_OPERATION),
        _call(index=3, status=429),
    ]
    failed = _row("fail", repetition=1, profile="hostile", calls=calls, passed=False, score=0.2)
    failed["native"]["is_truncated"] = True
    failed["native"]["termination_reason"] = "max_turns_reached"
    summary = _run([_row(profile="hostile"), failed])
    group = summary["groups"][0]
    assert group["task_success"]["proportion"] == 0.5
    assert group["all_completed"]["n"] == 2
    assert group["success_only"]["n"] == 1
    assert group["success_only"]["metrics"]["discipline_score"]["min"] == 1.0
    assert group["all_completed"]["native_truncated_runs"] == 1
    assert group["all_completed"]["task_incomplete_after_quota_runs"] == 1
    assert group["all_completed"]["ended_on_quota_response_runs"] == 1
    metrics = summary["rollouts"][1]["metrics"]
    assert metrics["writes_after_first_quota"] == 2
    assert metrics["quota_responses"] == 2
    assert metrics["applied_interventions"] == metrics["changed_observations"] == 2
    assert group["all_completed"]["task_failure_check_counts"] == {"fixture_goal": 1}


def test_applied_noop_is_separate_from_changed_observation():
    row = _row(profile="hostile")
    row["interventions"][0]["applied"] = True
    row["interventions"][0]["decision"]["kind"] = "repeat_page"
    row["audit"].update(applied_count=1, observational_noop_count=1)
    metrics = _run([row])["rollouts"][0]["metrics"]
    assert metrics["applied_interventions"] == 1
    assert metrics["changed_observations"] == 0
    assert metrics["observational_noops"] == 1


def test_incomplete_cohort_accounts_for_every_slot_without_zero_scoring_errors():
    rows = [_row()]
    for slot, status, rep in (("broken", "collection_error", 1), ("waiting", "unstarted", 2)):
        rows.append(
            {"slot_id": slot, "profile": "clean", "seed": "7", "repetition": rep, "status": status}
        )
    summary = _run(rows)
    assert summary["counts"] == {
        "scheduled": 3,
        "attempted": 2,
        "completed": 1,
        "audited": 1,
        "collection_errors": 1,
        "unstarted": 1,
    }
    assert summary["cohort_complete"] is False
    assert summary["groups"][0]["task_success"]["n"] == 1
    assert summary["groups"][0]["all_completed"]["metrics"]["provider_calls"]["sample_sd"] is None
    assert "metrics" not in summary["rollouts"][1]


def test_no_completions_remains_unavailable_instead_of_zero_variation():
    rows = [
        {
            "slot_id": "waiting",
            "profile": "clean",
            "seed": "7",
            "repetition": 0,
            "status": "unstarted",
        }
    ]
    group = _run(rows)["groups"][0]
    assert group["task_success"] == {"successes": 0, "n": 0, "proportion": None, "wilson_95": None}
    assert group["all_completed"]["metrics"]["provider_calls"] == {
        "n": 0,
        "min": None,
        "median": None,
        "max": None,
        "sample_sd": None,
    }


def test_collection_error_kind_is_retained_in_per_slot_summary():
    row = {
        "slot_id": "failed",
        "profile": "clean",
        "seed": "7",
        "repetition": 1,
        "status": "collection_error",
        "error_type": "TimeoutExpired",
    }
    summary = _run([row])
    assert summary["rollouts"][0]["error_type"] == "TimeoutExpired"
    assert summary["counts"]["collection_errors"] == 1
    assert summary["counts"]["completed"] == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("native"),
        lambda r: r["audit"].update(passed=False),
        lambda r: r["audit"].update(applied_count=5),
        lambda r: r["request_discipline"].update(score=float("nan")),
        lambda r: r["request_discipline"].update(actual_call_count=3),
        lambda r: r["provider_calls"][0].update(intervention_logical_request_index=2),
        lambda r: r["provider_calls"][0]["observation"]["body"].update(count="20"),
        lambda r: r["base_responses"]["1"]["body"].update(count=21),
        lambda r: r["task_correctness"].update(passed=False),
        lambda r: r.update(tool_attempts=4),
        lambda r: r.update(status="failed"),
        lambda r: r["native"].update(is_truncated="no"),
    ],
)
def test_malformed_or_inconsistent_rows_fail_closed(mutate):
    row = _row()
    mutate(row)
    with pytest.raises(analysis.RepeatAnalysisError):
        _run([row])


def test_schedule_requires_exactly_one_row_per_declared_identity():
    row = _row()
    with pytest.raises(analysis.RepeatAnalysisError):
        analysis.analyze_rows([], _schedule([row]))
    with pytest.raises(analysis.RepeatAnalysisError):
        analysis.analyze_rows([row, deepcopy(row)], _schedule([row]))
    with pytest.raises(analysis.RepeatAnalysisError):
        analysis.analyze_rows([row, _row("two", repetition=1)], _schedule([row]))
    wrong = deepcopy(row)
    wrong["seed"] = "23"
    with pytest.raises(analysis.RepeatAnalysisError):
        analysis.analyze_rows([wrong], _schedule([row]))


def test_seed_groups_have_separate_denominators_and_pairwise_is_descriptive():
    rows = [
        _row(f"{seed}-{rep}", seed=seed, repetition=rep) for seed in ("7", "23") for rep in range(3)
    ]
    summary = _run(rows)
    assert [group["task_success"]["n"] for group in summary["groups"]] == [3, 3, 6]
    assert len(summary["pairwise_divergences"]) == 6
    assert summary["counts"]["completed"] == 6
    assert "not additional independent samples" in summary["interpretation"]["pairwise_comparisons"]


def test_provider_behavior_is_separate_from_agent_message_variation():
    left, right = _row(), _row("two", repetition=1)
    right["native"]["agent_messages"][0]["content"] = "finished"
    summary = _run([left, right])
    pair = summary["pairwise_divergences"][0]
    assert pair["first_provider_difference_position"] is None
    assert pair["raw_native_message"]["position"] == 1


def test_opaque_responses_items_are_labeled_raw_not_provider_variation():
    left, right = _row(), _row("two", repetition=1)
    left["native"]["agent_messages"][0]["openai_responses_output"] = [
        {"type": "reasoning", "id": "rs_one", "encrypted_content": "opaque-one"}
    ]
    right["native"]["agent_messages"][0]["openai_responses_output"] = [
        {"type": "reasoning", "id": "rs_two", "encrypted_content": "opaque-two"}
    ]
    pair = _run([left, right])["pairwise_divergences"][0]
    assert pair["request"] is None
    assert pair["observation"] is None
    assert pair["first_provider_difference_position"] is None
    assert pair["raw_native_message"]["position"] == 1


def test_analysis_is_deterministic_does_not_mutate_inputs_and_preserves_scores():
    rows = [_row(), _row("two", repetition=1, score=0.735)]
    original = deepcopy(rows)
    first = _run(rows)
    second = analysis.analyze_rows(list(reversed(rows)), _schedule(rows))
    assert rows == original
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["rollouts"][1]["request_discipline"] == rows[1]["request_discipline"]
    assert analysis.render_summary(first) == analysis.render_summary(second)
    assert "95% Wilson" in analysis.render_summary(first)
    assert "schedule mixture" in analysis.render_summary(first)
    expected_sd = abs(1 - 0.735) / math.sqrt(2)
    assert first["groups"][0]["all_completed"]["metrics"]["discipline_score"][
        "sample_sd"
    ] == pytest.approx(expected_sd)
