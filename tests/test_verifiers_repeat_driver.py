"""Controller-only repeat orchestration tests; no paid inference."""

from __future__ import annotations

import importlib
import json
import signal
import socket
import subprocess
import sys
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "integrations" / "verifiers_dirty_integration"))
driver = importlib.import_module("datalox_dirty_integration.repeats")
contract = importlib.import_module("datalox_dirty_integration.repeat_contract")
BINDINGS = {"test.fixture": "sha256:" + "b" * 64}


def _collected_slot(
    output: Path,
    config: Any,
    slot: Any,
    *,
    verify_index: bool = False,
    cost: Fraction | None = None,
) -> dict[str, Any]:
    """Fixture at the collect_slot audit boundary; never model-performance data."""
    cap = Fraction(str(config.per_rollout_reservation_usd))
    cost = cap if cost is None else cost
    value = {
        **slot.model_dump(mode="json"),
        "status": "completed",
        "native": {
            "token_budget": {
                "passed": True,
                "blocked": False,
                "held_usd": "0",
                "spent_usd": str(cost),
                "limit_usd": str(cap),
            }
        },
    }
    if not verify_index:
        (output / "native").mkdir()
        contract.write_json_exclusive(
            output / "native" / "budget.json",
            {"model_free_controller_fixture": True, "spent_usd": str(cost)},
        )
        _index_row(output, value)
    return value


def _index_row(output: Path, row: dict[str, Any]) -> None:
    driver._atomic_json(
        output / "index.json",
        {
            "files": {"native/budget.json": driver.sha256_file(output / "native" / "budget.json")},
            "row_sha256": driver.canonical_sha256(row),
        },
    )


def _config(*, budget: float = 20.0, reservation: float = 0.25) -> Any:
    return contract.ExperimentConfig(
        experiment_id="model-free-driver-test",
        source_revision="a" * 40,
        bindings=BINDINGS,
        model=contract.ModelConfig(
            max_completion_tokens=4096,
            request_timeout_seconds=120.0,
            connect_timeout_seconds=5.0,
        ),
        per_rollout_timeout_seconds=900.0,
        max_total_cost_usd=budget,
        per_rollout_reservation_usd=reservation,
        schedule=contract.build_schedule(),
    )


@pytest.fixture
def collection_mock(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setenv("OPENAI_API_KEY", "controller-test-only-not-a-key")
    monkeypatch.setattr(driver, "capture_bindings", lambda model: dict(BINDINGS))

    def launch(config: Any, slot: Any, output: Path, manifest: Path) -> None:
        calls.append(slot.slot_id)
        output.mkdir()

    monkeypatch.setattr(driver, "_launch_slot", launch)
    monkeypatch.setattr(driver, "collect_slot", _collected_slot)
    return calls


def test_prepare_freezes_sixty_slots_without_launching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection_mock: list[str]
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(driver.subprocess, "check_output", lambda *args, **kwargs: "a" * 40)
    output = tmp_path / "experiment.json"
    assert (
        driver.main(
            [
                "prepare",
                "--output",
                str(output),
                "--experiment-id",
                "driver-prepare",
                "--max-total-cost-usd",
                "20",
                "--per-rollout-reservation-usd",
                "0.25",
            ]
        )
        == 0
    )
    config = driver.load_experiment(output)
    assert len(config.schedule) == 60
    assert len({slot.slot_id for slot in config.schedule}) == 60
    assert config.model.model == "gpt-5.6-sol"
    assert config.model.reasoning_effort == "medium"
    assert config.model.temperature is None
    assert config.bindings == BINDINGS
    assert collection_mock == []


@pytest.mark.parametrize("failure", ["budget_confirmation", "credential", "binding"])
def test_run_preconditions_fail_before_creating_output_or_launching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection_mock: list[str], failure: str
) -> None:
    if failure == "credential":
        monkeypatch.delenv("OPENAI_API_KEY")
    if failure == "binding":
        monkeypatch.setattr(driver, "capture_bindings", lambda model: {})
    output = tmp_path / failure
    with pytest.raises(ValueError):
        driver.run_experiment(_config(), output, spend_approved=failure != "budget_confirmation")
    assert not output.exists()
    assert collection_mock == []


def test_complete_driver_uses_saved_order_once_and_retains_all_slots(
    tmp_path: Path, collection_mock: list[str]
) -> None:
    config = _config()
    output = tmp_path / "complete"
    result = driver.run_experiment(config, output, spend_approved=True)
    assert collection_mock == [slot.slot_id for slot in config.schedule]
    assert result["status"] == "completed"
    assert result["spent_cost_usd"] == "15"
    assert result["held_cost_usd"] == "0"
    assert Counter(slot["status"] for slot in result["slots"]) == {"completed": 60}
    assert driver.read_json(output / "schedule.json") == [
        slot.model_dump(mode="json") for slot in config.schedule
    ]
    assert len(list((output / "slots").glob("*/index.json"))) == 60
    assert "controller-test-only-not-a-key" not in "".join(
        path.read_text() for path in output.rglob("*.json")
    )
    with pytest.raises(FileExistsError):
        driver.run_experiment(config, output, spend_approved=True)
    assert len(collection_mock) == 60


def test_reservation_budget_stops_before_a_request_that_cannot_fit(
    tmp_path: Path, collection_mock: list[str]
) -> None:
    config = _config(budget=2.0, reservation=1.0)
    result = driver.run_experiment(config, tmp_path / "budget", spend_approved=True)
    assert collection_mock == [slot.slot_id for slot in config.schedule[:2]]
    assert result["status"] == "incomplete"
    assert result["stop_reason"] == "reservation_budget_exhausted"
    assert result["spent_cost_usd"] == "2"
    assert result["held_cost_usd"] == "0"
    assert Counter(slot["status"] for slot in result["slots"]) == {"completed": 2, "unstarted": 58}


def test_decimal_reservations_complete_exactly_at_the_declared_cap(
    tmp_path: Path, collection_mock: list[str]
) -> None:
    config = _config(budget=7.8, reservation=0.13)
    result = driver.run_experiment(config, tmp_path / "exact-budget", spend_approved=True)
    assert collection_mock == [slot.slot_id for slot in config.schedule]
    assert result["status"] == "completed"
    assert result["spent_cost_usd"] == "39/5"
    assert result["held_cost_usd"] == "0"
    assert Counter(slot["status"] for slot in result["slots"]) == {"completed": 60}


def test_verified_unused_reservations_enable_all_sixty_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection_mock: list[str]
) -> None:
    config = _config(budget=9.0, reservation=0.4)
    output = tmp_path / "settled-budget"
    holds = []

    def launch(config: Any, slot: Any, path: Path, manifest: Path) -> None:
        saved = driver.read_json(output / "collection.json")
        assert saved["slots"][slot.order]["status"] == "running"
        assert saved["slots"][slot.order]["reservation_usd"] == "2/5"
        assert saved["held_cost_usd"] == "2/5"
        assert Fraction(saved["spent_cost_usd"]) == slot.order * Fraction("0.07")
        assert Fraction(saved["spent_cost_usd"]) + Fraction(saved["held_cost_usd"]) <= 9
        holds.append(saved["held_cost_usd"])
        collection_mock.append(slot.slot_id)
        path.mkdir()

    def collect(path: Path, config: Any, slot: Any, *, verify_index: bool = False) -> dict:
        return _collected_slot(path, config, slot, verify_index=verify_index, cost=Fraction("0.07"))

    monkeypatch.setattr(driver, "_launch_slot", launch)
    monkeypatch.setattr(driver, "collect_slot", collect)
    result = driver.run_experiment(config, output, spend_approved=True)
    assert result["status"] == "completed"
    assert len(holds) == len(collection_mock) == 60
    assert result["spent_cost_usd"] == "21/5"
    assert result["held_cost_usd"] == "0"
    assert result["cost_accounting"] == "sequential_verified_token_settlement"
    for slot in result["slots"]:
        assert slot["token_cost_usd"] == "7/100"
        path = output / "slots" / slot["slot_id"]
        assert slot["budget_sha256"] == driver.sha256_file(path / "native" / "budget.json")
        assert slot["index_sha256"] == driver.sha256_file(path / "index.json")


def test_partial_settlements_stop_before_insufficient_next_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection_mock: list[str]
) -> None:
    def collect(path: Path, config: Any, slot: Any, *, verify_index: bool = False) -> dict:
        return _collected_slot(path, config, slot, verify_index=verify_index, cost=Fraction("0.3"))

    monkeypatch.setattr(driver, "collect_slot", collect)
    result = driver.run_experiment(
        _config(budget=1.0, reservation=0.4), tmp_path / "partial", spend_approved=True
    )
    # Holds: .4, .3+.4, .6+.4 fit exactly; .9+.4 cannot be dispatched.
    assert len(collection_mock) == 3
    assert result["spent_cost_usd"] == "9/10"
    assert result["held_cost_usd"] == "0"
    assert result["stop_reason"] == "reservation_budget_exhausted"
    assert Counter(slot["status"] for slot in result["slots"]) == {"completed": 3, "unstarted": 57}


@pytest.mark.parametrize(
    "bad_cost", [None, True, False, 0, 0.1, "-1", "0.1", "01", "2/20", "NaN", "1/0", "1"]
)
def test_invalid_or_excessive_settled_cost_keeps_full_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection_mock: list[str], bad_cost: Any
) -> None:
    def collect(path: Path, config: Any, slot: Any, *, verify_index: bool = False) -> dict:
        row = _collected_slot(path, config, slot)
        row["native"]["token_budget"]["spent_usd"] = bad_cost
        _index_row(path, row)
        return row

    monkeypatch.setattr(driver, "collect_slot", collect)
    result = driver.run_experiment(_config(), tmp_path / "invalid-cost", spend_approved=True)
    assert len(collection_mock) == 1
    assert result["status"] == "incomplete"
    assert result["spent_cost_usd"] == "0"
    assert result["held_cost_usd"] == "1/4"
    assert "token_cost_usd" not in result["slots"][0]


@pytest.mark.parametrize(
    "failure",
    [
        "missing_ledger",
        "missing_summary",
        "unpassed",
        "blocked",
        "held",
        "wrong_cap",
        "ledger_tamper",
        "row_tamper",
        "usage_audit",
    ],
)
def test_unverified_or_uncertain_charge_never_releases_its_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection_mock: list[str], failure: str
) -> None:
    def collect(path: Path, config: Any, slot: Any, *, verify_index: bool = False) -> dict:
        row = _collected_slot(path, config, slot, cost=Fraction("0.01"))
        if failure == "usage_audit":
            raise ValueError("native usage failed audit")
        if failure == "missing_ledger":
            (path / "native" / "budget.json").unlink()
        elif failure == "ledger_tamper":
            driver._atomic_json(path / "native" / "budget.json", {"changed": True})
        elif failure == "row_tamper":
            row["native"]["token_budget"]["spent_usd"] = "0"
        else:
            budget = row["native"]["token_budget"]
            if failure == "missing_summary":
                row["native"].pop("token_budget")
            elif failure == "unpassed":
                budget["passed"] = False
            elif failure == "blocked":
                budget["blocked"] = True
            elif failure == "held":
                budget["held_usd"] = "1/100"
            else:
                budget["limit_usd"] = "1"
            _index_row(path, row)
        return row

    monkeypatch.setattr(driver, "collect_slot", collect)
    result = driver.run_experiment(_config(), tmp_path / failure, spend_approved=True)
    assert len(collection_mock) == 1
    assert result["spent_cost_usd"] == "0"
    assert result["held_cost_usd"] == "1/4"
    assert Counter(slot["status"] for slot in result["slots"]) == {
        "collection_error": 1,
        "unstarted": 59,
    }


def test_unknown_second_charge_preserves_prior_exact_cost_and_full_current_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection_mock: list[str]
) -> None:
    def collect(path: Path, config: Any, slot: Any, *, verify_index: bool = False) -> dict:
        if slot.order == 1:
            raise ValueError("unknown token charge")
        return _collected_slot(path, config, slot, cost=Fraction("0.07"))

    monkeypatch.setattr(driver, "collect_slot", collect)
    result = driver.run_experiment(
        _config(budget=9.0, reservation=0.4), tmp_path / "uncertain-second", spend_approved=True
    )
    assert len(collection_mock) == 2
    assert result["spent_cost_usd"] == "7/100"
    assert result["held_cost_usd"] == "2/5"
    assert [row["status"] for row in result["slots"][:3]] == [
        "completed",
        "collection_error",
        "unstarted",
    ]


@pytest.mark.parametrize("error", [RuntimeError("model failed"), KeyboardInterrupt()])
def test_driver_error_and_cancellation_stop_cohort_without_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collection_mock: list[str],
    error: BaseException,
) -> None:
    def failing(config: Any, slot: Any, output: Path, manifest: Path) -> None:
        collection_mock.append(slot.slot_id)
        raise error

    monkeypatch.setattr(driver, "_launch_slot", failing)
    output = tmp_path / "stopped"
    result = driver.run_experiment(_config(), output, spend_approved=True)
    assert len(collection_mock) == 1
    assert result["status"] == "incomplete"
    assert result["stop_reason"] == "collection_error"
    assert result["slots"][0]["error_type"] == type(error).__name__
    assert result["spent_cost_usd"] == "0"
    assert result["held_cost_usd"] == "1/4"
    assert Counter(slot["status"] for slot in result["slots"]) == {
        "collection_error": 1,
        "unstarted": 59,
    }
    assert driver.read_json(output / "collection.json") == result


def test_native_process_nonzero_exit_is_not_relaunched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launches: list[list[str]] = []

    class Process:
        def wait(self, *, timeout: float) -> int:
            return 3

        def poll(self) -> int:
            return 3

    def popen(command: list[str], **kwargs: Any) -> Process:
        launches.append(command)
        assert kwargs["start_new_session"] is True
        return Process()

    monkeypatch.setattr(driver.subprocess, "Popen", popen)
    with pytest.raises(RuntimeError, match="native_slot_exit_3"):
        driver._launch_slot(
            _config(), _config().schedule[0], tmp_path / "slot", tmp_path / "manifest.json"
        )
    assert len(launches) == 1
    assert "_slot" in launches[0]


def test_native_process_timeout_terminates_process_group_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    waits: list[float] = []
    killed: list[tuple[int, signal.Signals]] = []

    class Process:
        pid = 123456789

        def wait(self, *, timeout: float) -> int:
            waits.append(timeout)
            if len(waits) == 1:
                raise subprocess.TimeoutExpired("fixture-only", timeout)
            return 0

        def poll(self) -> None:
            return None

    monkeypatch.setattr(driver.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(driver.os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    with pytest.raises(subprocess.TimeoutExpired):
        driver._launch_slot(
            _config(), _config().schedule[0], tmp_path / "timeout", tmp_path / "manifest.json"
        )
    assert waits == [930.0, 5]
    assert killed == [(123456789, signal.SIGTERM)]


def test_native_process_sigterm_cleans_up_and_restores_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    waits: list[float] = []
    killed: list[tuple[int, signal.Signals]] = []
    original_handler = signal.getsignal(signal.SIGTERM)

    class Process:
        pid = 123456789

        def wait(self, *, timeout: float) -> int:
            waits.append(timeout)
            if len(waits) == 1:
                installed_handler = signal.getsignal(signal.SIGTERM)
                assert callable(installed_handler)
                installed_handler(signal.SIGTERM, None)
            return 0

        def poll(self) -> None:
            return None

    monkeypatch.setattr(driver.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(driver.os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    with pytest.raises(KeyboardInterrupt, match="terminated"):
        driver._launch_slot(
            _config(), _config().schedule[0], tmp_path / "terminated", tmp_path / "manifest.json"
        )
    assert waits == [930.0, 5]
    assert killed == [(123456789, signal.SIGTERM)]
    assert signal.getsignal(signal.SIGTERM) is original_handler


@pytest.mark.parametrize(
    "mutation", ["index_tamper", "index_missing", "schedule", "collection_binding", "slot_identity"]
)
def test_analysis_rejects_retained_artifact_and_identity_mismatch(
    tmp_path: Path, collection_mock: list[str], mutation: str
) -> None:
    config = _config(budget=1.0, reservation=1.0)
    source = tmp_path / "collected"
    driver.run_experiment(config, source, spend_approved=True)
    index = source / "slots" / config.schedule[0].slot_id / "index.json"
    if mutation == "index_tamper":
        index.write_text("{}\n")
    elif mutation == "index_missing":
        index.unlink()
    elif mutation == "schedule":
        schedule = driver.read_json(source / "schedule.json")
        schedule.reverse()
        driver._atomic_json(source / "schedule.json", schedule)
    else:
        collection = driver.read_json(source / "collection.json")
        if mutation == "collection_binding":
            collection["experiment_sha256"] = "sha256:" + "c" * 64
        else:
            collection["slots"][0]["seed"] = "another-seed"
        driver._atomic_json(source / "collection.json", collection)
    output = tmp_path / "analysis"
    with pytest.raises((ValueError, FileNotFoundError)):
        driver.analyze_experiment(source, output)
    assert not output.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "spent",
        "held",
        "slot_cost",
        "budget_hash",
        "reservation",
        "cost_contract",
        "status",
        "unstarted_receipt",
    ],
)
def test_analysis_recomputes_collection_settlement_receipts(
    tmp_path: Path, collection_mock: list[str], mutation: str
) -> None:
    source = tmp_path / "settlement-analysis"
    driver.run_experiment(_config(budget=1.0, reservation=1.0), source, spend_approved=True)
    collection = driver.read_json(source / "collection.json")
    if mutation == "spent":
        collection["spent_cost_usd"] = "0"
    elif mutation == "held":
        collection["held_cost_usd"] = "1"
    elif mutation == "slot_cost":
        collection["slots"][0]["token_cost_usd"] = "0"
    elif mutation == "budget_hash":
        collection["slots"][0]["budget_sha256"] = "sha256:" + "0" * 64
    elif mutation == "reservation":
        collection["slots"][0]["reservation_usd"] = "0"
    elif mutation == "cost_contract":
        collection["cost_accounting"] = "guessed"
    elif mutation == "status":
        collection["status"] = "completed"
    else:
        collection["slots"][1]["token_cost_usd"] = "0"
    driver._atomic_json(source / "collection.json", collection)
    output = tmp_path / "analysis"
    with pytest.raises(ValueError):
        driver.analyze_experiment(source, output)
    assert not output.exists()


def test_capture_bindings_performs_no_provider_or_model_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("verifiers")
    runtime = importlib.import_module("datalox_gated_runtime.provider_runtime")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("binding capture must not execute requests")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(runtime.ProviderRuntime, "handle", forbidden)
    bindings = driver.capture_bindings(_config().model)
    environment = importlib.import_module("datalox_dirty_integration.environment").load_environment(
        profile="clean", num_tasks=1
    )
    save = importlib.import_module("verifiers.legacy.utils.save_utils")
    tool_defs = json.loads(json.dumps(environment.tool_defs, default=save.make_serializable))
    assert bindings["task.tools"] == driver.canonical_sha256(tool_defs)
    assert bindings["task.prompt"] == driver.canonical_sha256(environment.dataset[0]["prompt"])
    assert bindings["provider.initial_state_fingerprint"].startswith("sha256:")
    assert bindings["policy.clean"] != bindings["policy.hostile"]


def test_analysis_is_key_free_and_never_recaptures_or_launches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection_mock: list[str]
) -> None:
    config = _config(budget=1.0, reservation=1.0)
    source = tmp_path / "collected"
    driver.run_experiment(config, source, spend_approved=True)
    original_launch_count = len(collection_mock)
    monkeypatch.delenv("OPENAI_API_KEY")
    analysis = importlib.import_module("datalox_dirty_integration.repeat_analysis")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("analysis must use retained artifacts only")

    def analyze(rows: list[dict], schedule: list[dict]) -> dict:
        # The analyzer's real statistical contract has separate focused tests.
        # This test isolates driver I/O and inference independence.
        assert len(rows) == len(schedule) == 60
        assert Counter(row["status"] for row in rows) == {"completed": 1, "unstarted": 59}
        return {"scheduled": 60, "completed": 1}

    monkeypatch.setattr(driver, "capture_bindings", forbidden)
    monkeypatch.setattr(driver, "_launch_slot", forbidden)
    monkeypatch.setattr(analysis, "analyze_rows", analyze)
    monkeypatch.setattr(analysis, "render_summary", lambda result: "Model-free driver fixture.\n")
    output = tmp_path / "analysis"
    assert driver.analyze_experiment(source, output) == {"scheduled": 60, "completed": 1}
    assert len((output / "rollouts.jsonl").read_text().splitlines()) == 60
    assert len(collection_mock) == original_launch_count
    with pytest.raises(FileExistsError):
        driver.analyze_experiment(source, output)
