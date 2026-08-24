from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from itertools import combinations
from math import comb
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

AGENT_CI_SCHEMA_VERSION = "datalox_agent_ci_run_v1"
REPORT_SCHEMA_VERSION = "datalox_agent_ci_report_v1"


class EvaluationInputError(ValueError):
    """A stable, agent-readable failure while loading a completed run."""

    def __init__(self, code: str, message: str, *, path: Path | None = None) -> None:
        self.code = code
        self.path = path
        suffix = f" ({path})" if path is not None else ""
        super().__init__(f"{code}: {message}{suffix}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": str(self),
            "path": str(self.path) if self.path is not None else None,
        }


@dataclass(frozen=True)
class EvidenceRead:
    evidence_ref: str
    read: bool


@dataclass(frozen=True)
class RunMetrics:
    wall_time_seconds: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    cost_usd: float | None = None


@dataclass(frozen=True)
class CompletedRun:
    run_id: str
    environment_id: str
    task_id: str
    seed: int
    config_label: str
    attempt: int
    passed: bool
    outcome: str
    deterministic_passed: bool | None
    semantic_passed: bool | None
    failure_codes: tuple[str, ...]
    workflow_stage: str | None
    evidence_reads: tuple[EvidenceRead, ...]
    forbidden_attempts: tuple[str, ...]
    mutation_scope: tuple[str, ...]
    unsafe_actions: tuple[str, ...]
    metrics: RunMetrics
    run_export_path: str
    scorecard_path: str | None = None

    @property
    def infrastructure_failure(self) -> bool:
        return self.outcome == "infrastructure_failure"

    @property
    def agent_failure(self) -> bool:
        return self.outcome == "agent_failure"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["failure_codes"] = list(self.failure_codes)
        payload["evidence_reads"] = [asdict(item) for item in self.evidence_reads]
        payload["forbidden_attempts"] = list(self.forbidden_attempts)
        payload["mutation_scope"] = list(self.mutation_scope)
        payload["unsafe_actions"] = list(self.unsafe_actions)
        payload["infrastructure_failure"] = self.infrastructure_failure
        payload["agent_failure"] = self.agent_failure
        return payload


def load_completed_runs(paths: Iterable[Path | str]) -> list[CompletedRun]:
    """Load completed run exports plus their explicit Agent-CI scorecards.

    A run may embed its scorecard as top-level ``agent_ci`` in
    ``run_export.json`` or place the same object in ``agent_ci.json`` beside
    the export. The sidecar is intentionally narrow: it supplies evaluation
    metadata that the execution export does not own.
    """

    runs: list[CompletedRun] = []
    seen_inputs: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            exports = sorted(path.rglob("run_export.json"))
            if not exports:
                raise EvaluationInputError(
                    "agent_ci_run_export_missing",
                    "directory contains no run_export.json",
                    path=path,
                )
        elif path.name == "run_export.json":
            exports = [path]
        else:
            raise EvaluationInputError(
                "agent_ci_input_invalid",
                "input must be a run directory or run_export.json",
                path=path,
            )

        for export_path in exports:
            resolved = export_path.resolve()
            if resolved in seen_inputs:
                continue
            seen_inputs.add(resolved)
            runs.append(load_completed_run(export_path))
    return runs


def load_completed_run(run_export_path: Path | str) -> CompletedRun:
    run_export_path = Path(run_export_path)
    export = _read_json_object(run_export_path, code="agent_ci_run_export_invalid")
    run_id = _required_string(export, "run_id", path=run_export_path)

    embedded = export.get("agent_ci")
    scorecard_path: Path | None = None
    if embedded is None:
        scorecard_path = run_export_path.with_name("agent_ci.json")
        if not scorecard_path.is_file():
            raise EvaluationInputError(
                "agent_ci_scorecard_missing",
                "run export has no embedded agent_ci object and no adjacent agent_ci.json",
                path=run_export_path,
            )
        scorecard = _read_json_object(scorecard_path, code="agent_ci_scorecard_invalid")
    elif isinstance(embedded, dict):
        scorecard = embedded
    else:
        raise EvaluationInputError(
            "agent_ci_scorecard_invalid",
            "agent_ci must be an object",
            path=run_export_path,
        )

    return completed_run_from_scorecard(
        run_id=run_id,
        scorecard=scorecard,
        run_export_path=run_export_path,
        scorecard_path=scorecard_path,
    )


def completed_run_from_scorecard(
    *,
    run_id: str,
    scorecard: Mapping[str, Any],
    run_export_path: Path | str,
    scorecard_path: Path | str | None = None,
) -> CompletedRun:
    """Validate and normalize one ``datalox_agent_ci_run_v1`` scorecard."""

    path = Path(scorecard_path or run_export_path)
    if scorecard.get("schema_version") != AGENT_CI_SCHEMA_VERSION:
        raise EvaluationInputError(
            "agent_ci_schema_unsupported",
            f"schema_version must be {AGENT_CI_SCHEMA_VERSION!r}",
            path=path,
        )
    declared_run_id = scorecard.get("run_id")
    if declared_run_id is not None and declared_run_id != run_id:
        raise EvaluationInputError(
            "agent_ci_run_id_mismatch",
            f"scorecard run_id {declared_run_id!r} does not match export run_id {run_id!r}",
            path=path,
        )

    verdict = _required_mapping(scorecard, "verdict", path=path)
    outcome = _required_string(verdict, "outcome", path=path)
    if outcome not in {"passed", "agent_failure", "infrastructure_failure"}:
        raise EvaluationInputError(
            "agent_ci_outcome_invalid",
            "verdict.outcome must be passed, agent_failure, or infrastructure_failure",
            path=path,
        )
    passed = _required_bool(verdict, "passed", path=path)
    if passed != (outcome == "passed"):
        raise EvaluationInputError(
            "agent_ci_verdict_inconsistent",
            "verdict.passed must be true exactly when outcome is passed",
            path=path,
        )

    deterministic = _optional_layer(
        verdict.get("deterministic"), "deterministic", path, supports_disabled=False
    )
    semantic = _optional_layer(verdict.get("semantic"), "semantic", path, supports_disabled=True)
    failure_codes = _string_tuple(verdict.get("failure_codes"), "verdict.failure_codes", path)
    _validate_verdict_layers(
        passed=passed,
        outcome=outcome,
        deterministic=deterministic,
        semantic=semantic,
        failure_codes=failure_codes,
        path=path,
    )

    stage = scorecard.get("workflow_stage")
    if stage is not None and (not isinstance(stage, str) or not stage.strip()):
        raise EvaluationInputError(
            "agent_ci_workflow_stage_invalid",
            "workflow_stage must be a non-empty string or null",
            path=path,
        )
    if outcome == "agent_failure" and stage is None:
        raise EvaluationInputError(
            "agent_ci_failure_stage_missing",
            "agent failures must identify workflow_stage",
            path=path,
        )

    evidence = _required_sequence(scorecard, "required_evidence_reads", path=path)
    evidence_reads: list[EvidenceRead] = []
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            raise EvaluationInputError(
                "agent_ci_evidence_read_invalid",
                f"required_evidence_reads[{index}] must be an object",
                path=path,
            )
        evidence_reads.append(
            EvidenceRead(
                evidence_ref=_required_string(item, "evidence_ref", path=path),
                read=_required_bool(item, "read", path=path),
            )
        )

    metrics_payload = scorecard.get("metrics", {})
    if not isinstance(metrics_payload, dict):
        raise EvaluationInputError(
            "agent_ci_metrics_invalid",
            "metrics must be an object",
            path=path,
        )
    metrics = RunMetrics(
        wall_time_seconds=_optional_number(metrics_payload, "wall_time_seconds", path),
        input_tokens=_optional_int(metrics_payload, "input_tokens", path),
        output_tokens=_optional_int(metrics_payload, "output_tokens", path),
        total_tokens=_optional_int(metrics_payload, "total_tokens", path),
        cost_usd=_optional_number(metrics_payload, "cost_usd", path),
    )

    seed = scorecard.get("seed")
    attempt = scorecard.get("attempt")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise EvaluationInputError("agent_ci_seed_invalid", "seed must be an integer", path=path)
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise EvaluationInputError(
            "agent_ci_attempt_invalid",
            "attempt must be a positive integer",
            path=path,
        )

    return CompletedRun(
        run_id=run_id,
        environment_id=_required_string(scorecard, "environment_id", path=path),
        task_id=_required_string(scorecard, "task_id", path=path),
        seed=seed,
        config_label=_required_string(scorecard, "config_label", path=path),
        attempt=attempt,
        passed=passed,
        outcome=outcome,
        deterministic_passed=deterministic,
        semantic_passed=semantic,
        failure_codes=failure_codes,
        workflow_stage=stage,
        evidence_reads=tuple(evidence_reads),
        forbidden_attempts=_string_tuple(
            scorecard.get("forbidden_attempts"), "forbidden_attempts", path
        ),
        mutation_scope=_string_tuple(scorecard.get("mutation_scope"), "mutation_scope", path),
        unsafe_actions=_string_tuple(scorecard.get("unsafe_actions"), "unsafe_actions", path),
        metrics=metrics,
        run_export_path=str(Path(run_export_path)),
        scorecard_path=str(Path(scorecard_path)) if scorecard_path is not None else None,
    )


def build_evaluation_report(
    runs: Sequence[CompletedRun],
    *,
    k_values: Sequence[int] = (1,),
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Aggregate completed attempts without counting infrastructure failures as agents."""

    if not runs:
        raise ValueError("at least one completed run is required")
    ks = _validated_k_values(k_values)
    _validate_unique_attempts(runs)

    by_config: dict[tuple[str, str], list[CompletedRun]] = defaultdict(list)
    for run in runs:
        by_config[(run.environment_id, run.config_label)].append(run)

    configurations = [
        _configuration_report(environment_id, config_label, config_runs, ks)
        for (environment_id, config_label), config_runs in sorted(by_config.items())
    ]
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "k_values": list(ks),
        "attempts_total": len(runs),
        "agent_attempts": sum(not run.infrastructure_failure for run in runs),
        "infrastructure_failures": sum(run.infrastructure_failure for run in runs),
        "configurations": configurations,
        "comparisons": _comparison_reports(by_config),
        "runs": [run.to_dict() for run in sorted(runs, key=_run_sort_key)],
    }
    return report


def render_evaluation_markdown(report: Mapping[str, Any]) -> str:
    """Render compact Markdown strictly from the JSON report object."""

    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ValueError(f"unsupported report schema: {report.get('schema_version')!r}")
    lines = [
        "# Datalox Agent-CI Report",
        "",
        f"Generated: {report.get('generated_at')}",
        "",
        (
            f"Attempts: {report.get('attempts_total')} total, "
            f"{report.get('agent_attempts')} agent-evaluable, "
            f"{report.get('infrastructure_failures')} infrastructure failures."
        ),
        "",
        "## Reliability",
        "",
        "| Environment | Configuration | Agent attempts | Pass rate | Det/Sem failures | "
        "pass@k | pass^k | Infra | Wall time | Tokens | Cost (USD) |",
        "|---|---|---:|---:|---:|---|---|---:|---:|---:|---:|",
    ]
    for config in report.get("configurations", []):
        reliability = config["reliability"]
        pass_at = ", ".join(
            f"{item['k']}={_format_rate(item['pass_at_k'])}" for item in reliability
        )
        pass_power = ", ".join(
            f"{item['k']}={_format_rate(item['pass_power_k'])}" for item in reliability
        )
        lines.append(
            "| {environment} | {config} | {attempts} | {rate} | {det}/{sem} | {pass_at} | "
            "{pass_power} | {infra} | {wall} | {tokens} | {cost} |".format(
                environment=_escape_markdown(config["environment_id"]),
                config=_escape_markdown(config["config_label"]),
                attempts=config["agent_attempts"],
                rate=_format_rate(config["pass_rate"]),
                det=config["deterministic_failures"],
                sem=config["semantic_failures"],
                pass_at=pass_at,
                pass_power=pass_power,
                infra=config["infrastructure_failures"],
                wall=_format_metric(config["metrics"]["wall_time_seconds"]["total"]),
                tokens=_format_metric(config["metrics"]["total_tokens"]["total"]),
                cost=_format_metric(config["metrics"]["cost_usd"]["total"]),
            )
        )

    comparisons = report.get("comparisons", [])
    if comparisons:
        lines.extend(
            [
                "",
                "## Same-seed comparisons",
                "",
                "| Environment | A | B | Common cases | A pass rate | B pass rate | B - A |",
                "|---|---|---|---:|---:|---:|---:|",
            ]
        )
        for item in comparisons:
            lines.append(
                "| {environment} | {a} | {b} | {count} | {a_rate} | {b_rate} | {delta} |".format(
                    environment=_escape_markdown(item["environment_id"]),
                    a=_escape_markdown(item["config_a"]),
                    b=_escape_markdown(item["config_b"]),
                    count=item["common_case_count"],
                    a_rate=_format_rate(item["config_a_pass_rate"]),
                    b_rate=_format_rate(item["config_b_pass_rate"]),
                    delta=_format_signed_rate(item["pass_rate_delta_b_minus_a"]),
                )
            )

    failures = [
        run
        for run in report.get("runs", [])
        if run.get("outcome") in {"agent_failure", "infrastructure_failure"}
    ]
    if failures:
        lines.extend(
            [
                "",
                "## Failures",
                "",
                "| Run | Configuration | Seed/attempt | Type | Stage | Codes | Missing evidence | "
                "Unsafe/forbidden |",
                "|---|---|---|---|---|---|---|---|",
            ]
        )
        for run in failures:
            missing = [
                item["evidence_ref"] for item in run.get("evidence_reads", []) if not item["read"]
            ]
            safety = list(run.get("unsafe_actions", [])) + list(run.get("forbidden_attempts", []))
            run_link = f"[{_escape_markdown(run['run_id'])}]({run['run_export_path']})"
            lines.append(
                "| {run} | {config} | {seed}/{attempt} | {outcome} | {stage} | {codes} | "
                "{missing} | {safety} |".format(
                    run=run_link,
                    config=_escape_markdown(run["config_label"]),
                    seed=run["seed"],
                    attempt=run["attempt"],
                    outcome=run["outcome"],
                    stage=_escape_markdown(run.get("workflow_stage") or "—"),
                    codes=_escape_markdown(", ".join(run.get("failure_codes", [])) or "—"),
                    missing=_escape_markdown(", ".join(missing) or "—"),
                    safety=_escape_markdown(", ".join(safety) or "—"),
                )
            )

    lines.append("")
    return "\n".join(lines)


def write_evaluation_report(
    report: Mapping[str, Any], *, json_path: Path | str, markdown_path: Path | str
) -> None:
    json_path = Path(json_path)
    markdown_path = Path(markdown_path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_evaluation_markdown(report), encoding="utf-8")


def _configuration_report(
    environment_id: str,
    config_label: str,
    runs: Sequence[CompletedRun],
    ks: Sequence[int],
) -> dict[str, Any]:
    agent_runs = [run for run in runs if not run.infrastructure_failure]
    passed = sum(run.passed for run in agent_runs)
    failure_codes = Counter(code for run in agent_runs for code in run.failure_codes)
    stages = Counter(run.workflow_stage for run in agent_runs if run.workflow_stage is not None)
    missing_evidence = Counter(
        item.evidence_ref for run in agent_runs for item in run.evidence_reads if not item.read
    )
    forbidden = Counter(item for run in agent_runs for item in run.forbidden_attempts)
    unsafe = Counter(item for run in agent_runs for item in run.unsafe_actions)

    return {
        "environment_id": environment_id,
        "config_label": config_label,
        "tasks": sorted({run.task_id for run in runs}),
        "seeds": sorted({run.seed for run in runs}),
        "attempts_total": len(runs),
        "agent_attempts": len(agent_runs),
        "infrastructure_failures": sum(run.infrastructure_failure for run in runs),
        "agent_passes": passed,
        "agent_failures": len(agent_runs) - passed,
        "deterministic_failures": sum(run.deterministic_passed is False for run in agent_runs),
        "semantic_failures": sum(run.semantic_passed is False for run in agent_runs),
        "pass_rate": passed / len(agent_runs) if agent_runs else None,
        "reliability": [_reliability_for_k(agent_runs, k) for k in ks],
        "failure_codes": _counter_dict(failure_codes),
        "workflow_stages": _counter_dict(stages),
        "missing_evidence_reads": _counter_dict(missing_evidence),
        "forbidden_attempts": _counter_dict(forbidden),
        "unsafe_actions": _counter_dict(unsafe),
        "mutation_scopes": sorted({item for run in agent_runs for item in run.mutation_scope}),
        "metrics": _aggregate_metrics(runs),
    }


def _reliability_for_k(runs: Sequence[CompletedRun], k: int) -> dict[str, Any]:
    by_case: dict[tuple[str, str, int], list[CompletedRun]] = defaultdict(list)
    for run in runs:
        by_case[(run.environment_id, run.task_id, run.seed)].append(run)
    pass_at_values: list[float] = []
    pass_power_values: list[float] = []
    for case_runs in by_case.values():
        n = len(case_runs)
        if n < k:
            continue
        c = sum(run.passed for run in case_runs)
        pass_at_values.append(1.0 - (comb(n - c, k) / comb(n, k) if n - c >= k else 0.0))
        pass_power_values.append(comb(c, k) / comb(n, k) if c >= k else 0.0)
    return {
        "k": k,
        "eligible_case_count": len(pass_at_values),
        "pass_at_k": _mean(pass_at_values),
        "pass_power_k": _mean(pass_power_values),
    }


def _comparison_reports(
    by_config: Mapping[tuple[str, str], Sequence[CompletedRun]],
) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    by_environment: dict[str, dict[str, Sequence[CompletedRun]]] = defaultdict(dict)
    for (environment_id, config_label), runs in by_config.items():
        by_environment[environment_id][config_label] = runs

    for environment_id, configs in sorted(by_environment.items()):
        for (label_a, runs_a), (label_b, runs_b) in combinations(sorted(configs.items()), 2):
            cases_a = _case_pass_rates(runs_a)
            cases_b = _case_pass_rates(runs_b)
            common = sorted(set(cases_a) & set(cases_b))
            if not common:
                continue
            rate_a = _mean([cases_a[key] for key in common])
            rate_b = _mean([cases_b[key] for key in common])
            reports.append(
                {
                    "environment_id": environment_id,
                    "config_a": label_a,
                    "config_b": label_b,
                    "common_case_count": len(common),
                    "common_cases": [
                        {"task_id": task_id, "seed": seed} for task_id, seed in common
                    ],
                    "config_a_pass_rate": rate_a,
                    "config_b_pass_rate": rate_b,
                    "pass_rate_delta_b_minus_a": rate_b - rate_a,
                }
            )
    return reports


def _case_pass_rates(runs: Sequence[CompletedRun]) -> dict[tuple[str, int], float]:
    grouped: dict[tuple[str, int], list[CompletedRun]] = defaultdict(list)
    for run in runs:
        if not run.infrastructure_failure:
            grouped[(run.task_id, run.seed)].append(run)
    return {
        key: sum(run.passed for run in case_runs) / len(case_runs)
        for key, case_runs in grouped.items()
    }


def _aggregate_metrics(runs: Sequence[CompletedRun]) -> dict[str, Any]:
    return {
        "wall_time_seconds": _metric_summary(runs, "wall_time_seconds"),
        "input_tokens": _metric_summary(runs, "input_tokens"),
        "output_tokens": _metric_summary(runs, "output_tokens"),
        "total_tokens": _metric_summary(runs, "total_tokens"),
        "cost_usd": _metric_summary(runs, "cost_usd"),
    }


def _metric_summary(runs: Sequence[CompletedRun], field: str) -> dict[str, Any]:
    values = [getattr(run.metrics, field) for run in runs]
    supplied = [value for value in values if value is not None]
    return {
        "supplied_attempts": len(supplied),
        "missing_attempts": len(values) - len(supplied),
        "total": sum(supplied) if supplied else None,
        "mean": (sum(supplied) / len(supplied)) if supplied else None,
    }


def _validate_unique_attempts(runs: Sequence[CompletedRun]) -> None:
    seen: set[tuple[str, str, int, str, int]] = set()
    for run in runs:
        key = (
            run.environment_id,
            run.task_id,
            run.seed,
            run.config_label,
            run.attempt,
        )
        if key in seen:
            raise ValueError(f"duplicate Agent-CI attempt: {key!r}")
        seen.add(key)


def _validate_verdict_layers(
    *,
    passed: bool,
    outcome: str,
    deterministic: bool | None,
    semantic: bool | None,
    failure_codes: tuple[str, ...],
    path: Path,
) -> None:
    if outcome == "infrastructure_failure":
        if deterministic is not None or semantic is not None:
            raise EvaluationInputError(
                "agent_ci_infrastructure_layers_present",
                "infrastructure failure must not be reported as a verifier result",
                path=path,
            )
        if not failure_codes:
            raise EvaluationInputError(
                "agent_ci_failure_code_missing",
                "infrastructure failure must include a stable failure code",
                path=path,
            )
        return
    if deterministic is None:
        raise EvaluationInputError(
            "agent_ci_deterministic_result_missing",
            "agent-evaluable runs require a deterministic verifier result",
            path=path,
        )
    composite = deterministic and semantic is not False
    if passed != composite:
        raise EvaluationInputError(
            "agent_ci_verdict_inconsistent",
            "final pass must equal deterministic pass AND optional semantic pass",
            path=path,
        )
    if not passed and not failure_codes:
        raise EvaluationInputError(
            "agent_ci_failure_code_missing",
            "failed run must include a stable failure code",
            path=path,
        )


def _optional_layer(value: Any, name: str, path: Path, *, supports_disabled: bool) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("passed"), bool):
        raise EvaluationInputError(
            "agent_ci_verifier_layer_invalid",
            f"verdict.{name} must be null or an object with boolean passed",
            path=path,
        )
    if supports_disabled and value.get("enabled") is False:
        if value["passed"] is not True:
            raise EvaluationInputError(
                "agent_ci_verifier_layer_invalid",
                f"disabled verdict.{name} must report passed=true",
                path=path,
            )
        return None
    return value["passed"]


def _read_json_object(path: Path, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationInputError(code, str(exc), path=path) from exc
    if not isinstance(value, dict):
        raise EvaluationInputError(code, "JSON root must be an object", path=path)
    return value


def _required_mapping(payload: Mapping[str, Any], key: str, *, path: Path) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise EvaluationInputError("agent_ci_field_invalid", f"{key} must be an object", path=path)
    return value


def _required_sequence(payload: Mapping[str, Any], key: str, *, path: Path) -> Sequence[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise EvaluationInputError("agent_ci_field_invalid", f"{key} must be a list", path=path)
    return value


def _required_string(payload: Mapping[str, Any], key: str, *, path: Path) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise EvaluationInputError(
            "agent_ci_field_invalid", f"{key} must be a non-empty string", path=path
        )
    return value


def _required_bool(payload: Mapping[str, Any], key: str, *, path: Path) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise EvaluationInputError("agent_ci_field_invalid", f"{key} must be a boolean", path=path)
    return value


def _string_tuple(value: Any, name: str, path: Path) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise EvaluationInputError(
            "agent_ci_field_invalid", f"{name} must be a list of non-empty strings", path=path
        )
    return tuple(value)


def _optional_int(payload: Mapping[str, Any], key: str, path: Path) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EvaluationInputError(
            "agent_ci_metric_invalid",
            f"metrics.{key} must be a non-negative integer or null",
            path=path,
        )
    return value


def _optional_number(payload: Mapping[str, Any], key: str, path: Path) -> float | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        raise EvaluationInputError(
            "agent_ci_metric_invalid",
            f"metrics.{key} must be a non-negative number or null",
            path=path,
        )
    return float(value)


def _validated_k_values(k_values: Sequence[int]) -> tuple[int, ...]:
    if not k_values:
        raise ValueError("at least one k value is required")
    if any(not isinstance(k, int) or isinstance(k, bool) or k < 1 for k in k_values):
        raise ValueError("k values must be positive integers")
    return tuple(sorted(set(k_values)))


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def _mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _run_sort_key(run: CompletedRun) -> tuple[Any, ...]:
    return (
        run.environment_id,
        run.config_label,
        run.task_id,
        run.seed,
        run.attempt,
        run.run_id,
    )


def _format_rate(value: float | None) -> str:
    return "—" if value is None else f"{value:.1%}"


def _format_signed_rate(value: float | None) -> str:
    return "—" if value is None else f"{value:+.1%}"


def _format_metric(value: int | float | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".")
    return str(value)


def _escape_markdown(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
