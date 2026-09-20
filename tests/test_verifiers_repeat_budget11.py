"""V3 contract and model-free native calibration; never hosted-model evidence."""

import asyncio
from collections import Counter
from copy import deepcopy

import pytest
import test_verifiers_repeat_native as fixtures
from datalox_dirty_integration.repeat_arms import (
    BUDGET11_ARMS,
    build_budget11_schedule,
    parse_experiment,
)
from datalox_dirty_integration.repeat_public import check_row, project_slot, summarize
from test_verifiers_repeat_arms import config

native_transport = fixtures.native_transport


def test_v3_schedule_balances_both_orders_and_each_cell():
    schedule = build_budget11_schedule()
    assert len(schedule) == 36
    assert Counter(slot.arm for slot in schedule) == dict.fromkeys(BUDGET11_ARMS, 18)
    assert Counter(tuple(s.arm for s in schedule[i : i + 2]) for i in range(0, 36, 2)) == {
        ("baseline", "budget11"): 9,
        ("budget11", "baseline"): 9,
    }
    assert set(Counter((s.profile, s.seed, s.arm) for s in schedule).values()) == {3}
    for profile in ("clean", "hostile"):
        for seed in ("1", "7", "23"):
            for arm in BUDGET11_ARMS:
                positions = Counter(
                    s.order % 2
                    for s in schedule
                    if (s.profile, s.seed, s.arm) == (profile, seed, arm)
                )
                assert sorted(positions.values()) == [1, 2]


def test_v3_frozen_contract_rejects_mixed_experiments(native_transport):
    frozen = config(limit=11)
    assert parse_experiment(frozen.model_dump(mode="json")) == frozen
    for key, value in (
        ("repetitions", 5),
        ("seeds", ["1", "7"]),
        ("schema_version", "datalox_repeat_experiment_v2"),
    ):
        invalid = frozen.model_dump(mode="json")
        invalid[key] = value
        with pytest.raises(ValueError):
            parse_experiment(invalid)
    invalid = frozen.model_dump(mode="json")
    invalid["schedule"][1]["arm"] = "budget12"
    with pytest.raises(ValueError):
        parse_experiment(invalid)
    old = config().model_dump(mode="json")
    old["schedule"][1]["arm"] = "budget11"
    with pytest.raises(ValueError):
        parse_experiment(old)


def test_v3_all_slots_native_audit_public_projection_and_analysis(
    tmp_path, monkeypatch, native_transport
):
    from datalox_dirty_integration import repeats
    from datalox_dirty_integration.repeat_evidence import RepeatEvidenceError
    from datalox_dirty_integration.repeat_native import run_native_slot
    from datalox_dirty_integration.repeat_replay import replay_actions

    frozen = config(limit=11)
    for slot in frozen.schedule:
        native_transport["responses"].append(
            fixtures._response(
                tool_calls=[
                    fixtures._call(f"call-{i}", "list_products", offset=0, limit=10)
                    for i in range(1, 13)
                ]
            )
        )
        if slot.arm == "baseline":
            native_transport["responses"].append(fixtures._response())
    monkeypatch.setattr(
        repeats, "_launch_slot", lambda cfg, slot, out, manifest: run_native_slot(cfg, slot, out)
    )
    source = tmp_path / "collection"
    collected = repeats.run_experiment(frozen, source, spend_approved=True)
    assert collected["status"] == "completed"
    summary = repeats.analyze_experiment(source, tmp_path / "analysis")
    assert summary["schema_version"] == "datalox_dirty_repeat_analysis_v3"
    assert summary["counts"]["completed"] == 36
    assert len(summary["within_profile_seed_repetition"]) == 18
    for pair in summary["within_profile_seed_repetition"]:
        assert pair["arms"]["budget11"]["provider_calls"] == 11
        assert pair["arms"]["budget11"]["budget_terminated"] is True
        assert pair["arms"]["baseline"]["provider_calls"] == 12
    rows = []
    for slot in frozen.schedule:
        public = project_slot(source / "slots" / slot.slot_id, frozen, slot)
        check_row(public, frozen, slot)
        rows.append(public)
    assert summarize(rows)["runs"] == 36
    assert set(summarize(rows)["arms"]) == set(BUDGET11_ARMS)
    baseline = next(row for row in rows if row["slot"]["arm"] == "baseline")
    replay = asyncio.run(replay_actions(baseline, None))
    capped = asyncio.run(replay_actions(baseline, 11))
    assert replay["executed_provider_calls"] == 12
    assert capped["executed_provider_calls"] == 11
    assert capped["call_budget"]["rejection"]["requested_call_number"] == 12
    assert capped["same_final_provider_state_as_original"] is False
    assert capped["same_final_provider_data_as_original"] is True
    tampered = deepcopy(baseline)
    tampered["tool_transcript"][1]["content"] = "{}"
    with pytest.raises(RepeatEvidenceError, match="observations differ"):
        asyncio.run(replay_actions(tampered, None))
