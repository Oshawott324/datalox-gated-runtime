from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from datalox_gated_runtime.world_v1.evaluation import (
    AGENT_CI_SCHEMA_VERSION,
    CompletedRun,
    EvaluationInputError,
    build_evaluation_report,
    completed_run_from_scorecard,
    load_completed_run,
    render_evaluation_markdown,
    write_evaluation_report,
)


def _scorecard(
    *,
    seed: int,
    attempt: int,
    config: str,
    passed: bool,
    outcome: str | None = None,
    code: str = "stage_failed",
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    outcome = outcome or ("passed" if passed else "agent_failure")
    infrastructure = outcome == "infrastructure_failure"
    return {
        "schema_version": AGENT_CI_SCHEMA_VERSION,
        "environment_id": "world-a",
        "task_id": "task-a",
        "seed": seed,
        "config_label": config,
        "attempt": attempt,
        "verdict": {
            "passed": passed,
            "outcome": outcome,
            "deterministic": None if infrastructure else {"passed": passed},
            "semantic": None,
            "failure_codes": [] if passed else [code],
        },
        "workflow_stage": "approval" if outcome == "agent_failure" else None,
        "required_evidence_reads": [{"evidence_ref": "evidence:current-policy", "read": passed}],
        "forbidden_attempts": [] if passed else ["tool:send"],
        "mutation_scope": ["cases/case-1"],
        "unsafe_actions": [] if passed else ["send_without_approval"],
        "metrics": metrics or {},
    }


def _run(**kwargs: Any) -> CompletedRun:
    scorecard = _scorecard(**kwargs)
    return completed_run_from_scorecard(
        run_id=(f"run-{scorecard['config_label']}-{scorecard['seed']}-{scorecard['attempt']}"),
        scorecard=scorecard,
        run_export_path=Path("runs") / scorecard["config_label"] / "run_export.json",
    )


def test_pass_at_k_and_pass_power_k_use_unbiased_repeated_attempt_formulas() -> None:
    runs = [
        _run(seed=1, attempt=1, config="base", passed=True),
        _run(seed=1, attempt=2, config="base", passed=True),
        _run(seed=1, attempt=3, config="base", passed=False),
        _run(seed=2, attempt=1, config="base", passed=True),
        _run(seed=2, attempt=2, config="base", passed=False),
        _run(seed=2, attempt=3, config="base", passed=False),
    ]

    report = build_evaluation_report(
        runs,
        k_values=[1, 2],
        generated_at="2026-07-17T00:00:00+00:00",
    )
    reliability = report["configurations"][0]["reliability"]

    assert reliability[0]["pass_at_k"] == pytest.approx(0.5)
    assert reliability[0]["pass_power_k"] == pytest.approx(0.5)
    assert reliability[1]["pass_at_k"] == pytest.approx(5 / 6)
    assert reliability[1]["pass_power_k"] == pytest.approx(1 / 6)


def test_infrastructure_failures_are_separate_and_missing_costs_remain_null() -> None:
    runs = [
        _run(seed=1, attempt=1, config="base", passed=True),
        _run(
            seed=1,
            attempt=2,
            config="base",
            passed=False,
            outcome="infrastructure_failure",
            code="runner_timeout",
        ),
    ]

    report = build_evaluation_report(runs)
    config = report["configurations"][0]

    assert report["infrastructure_failures"] == 1
    assert config["agent_attempts"] == 1
    assert config["pass_rate"] == 1.0
    assert config["metrics"]["cost_usd"] == {
        "supplied_attempts": 0,
        "missing_attempts": 2,
        "total": None,
        "mean": None,
    }


def test_disabled_semantic_layer_is_reported_as_not_run() -> None:
    scorecard = _scorecard(seed=1, attempt=1, config="base", passed=True)
    scorecard["verdict"]["semantic"] = {"enabled": False, "passed": True}

    run = completed_run_from_scorecard(
        run_id="run-1",
        scorecard=scorecard,
        run_export_path="run_export.json",
    )

    assert run.deterministic_passed is True
    assert run.semantic_passed is None


def test_same_seed_comparison_and_markdown_expose_stage_code_and_safety() -> None:
    runs = [
        _run(seed=1, attempt=1, config="base", passed=False),
        _run(seed=2, attempt=1, config="base", passed=True),
        _run(seed=1, attempt=1, config="candidate", passed=True),
        _run(seed=2, attempt=1, config="candidate", passed=True),
    ]

    report = build_evaluation_report(runs)
    comparison = report["comparisons"][0]
    markdown = render_evaluation_markdown(report)

    assert comparison["common_case_count"] == 2
    assert comparison["pass_rate_delta_b_minus_a"] == 0.5
    assert "approval" in markdown
    assert "stage_failed" in markdown
    assert "send_without_approval" in markdown
    assert "evidence:current-policy" in markdown


def test_loader_consumes_run_export_with_explicit_sidecar(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run_export.json").write_text(
        json.dumps({"run_id": "run-1", "events": [], "shadow_state": {}}), encoding="utf-8"
    )
    scorecard = _scorecard(seed=3, attempt=1, config="base", passed=True)
    scorecard["run_id"] = "run-1"
    (run_dir / "agent_ci.json").write_text(json.dumps(scorecard), encoding="utf-8")

    run = load_completed_run(run_dir / "run_export.json")

    assert run.run_id == "run-1"
    assert run.scorecard_path == str(run_dir / "agent_ci.json")
    assert run.metrics.cost_usd is None


def test_agent_failure_without_stage_is_rejected() -> None:
    scorecard = _scorecard(seed=1, attempt=1, config="base", passed=False)
    scorecard["workflow_stage"] = None

    with pytest.raises(EvaluationInputError) as exc_info:
        completed_run_from_scorecard(
            run_id="run-1",
            scorecard=scorecard,
            run_export_path="run_export.json",
        )

    assert exc_info.value.code == "agent_ci_failure_stage_missing"


def test_json_is_source_of_truth_for_derived_markdown(tmp_path: Path) -> None:
    report = build_evaluation_report(
        [_run(seed=1, attempt=1, config="base", passed=True)],
        generated_at="2026-07-17T00:00:00+00:00",
    )
    json_path = tmp_path / "agent-ci.json"
    markdown_path = tmp_path / "agent-ci.md"

    write_evaluation_report(report, json_path=json_path, markdown_path=markdown_path)

    persisted = json.loads(json_path.read_text(encoding="utf-8"))
    assert persisted == report
    assert markdown_path.read_text(encoding="utf-8") == render_evaluation_markdown(persisted)
