"""Reproduce the public Issue #6 V1 intervention calibration."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from datalox_dirty_integration.audit import audit_episode_export, audit_pair, canonical_sha256
from datalox_dirty_integration.contract import (
    provider_admission_path,
    provider_grounding_path,
    provider_release_path,
    provider_runtime_bundle_path,
)
from datalox_dirty_integration.episode import CommerceEpisode
from datalox_dirty_integration.policy import PROFILES, SeededCommercePolicy
from datalox_dirty_integration.reference import (
    ReferenceResult,
    run_careful_reference,
    run_incomplete_pagination_trajectory,
    run_invalid_write_trajectory,
    run_mishandled_quota_trajectory,
    run_quota_probe,
    run_redundant_correct_reference,
)
from datalox_dirty_integration.scoring import (
    EvaluationOracle,
    request_discipline_report_for_episode,
    verify_task_for_episode,
)

SCHEMA_VERSION = "datalox_dirty_integration_calibration_v1"
PROFILE_NAMES = ("clean", "realistic", "hostile")
Trajectory = Callable[[CommerceEpisode, EvaluationOracle], ReferenceResult]


def run_public_calibration(
    *,
    seeds: Iterable[int],
    provider_grounding: Path | None = None,
    provider_admission: Path | None = None,
    provider_runtime_bundle: Path | None = None,
    provider_release: Path | None = None,
) -> dict[str, Any]:
    """Run matched ON/OFF pairs plus deterministic verifier calibration cases."""

    seed_values = tuple(seeds)
    if not seed_values or any(type(seed) is not int or seed < 0 for seed in seed_values):
        raise ValueError("calibration seeds must be a non-empty sequence of non-negative integers")
    if len(set(seed_values)) != len(seed_values):
        raise ValueError("calibration seeds must be unique")
    expected_seeds = tuple(range(seed_values[0], seed_values[0] + len(seed_values)))
    if seed_values != expected_seeds:
        raise ValueError("calibration seeds must be one ascending contiguous range")
    paths = {
        "provider_grounding": (provider_grounding or provider_grounding_path()).resolve(),
        "provider_admission": (provider_admission or provider_admission_path()).resolve(),
        "provider_runtime_bundle": (
            provider_runtime_bundle or provider_runtime_bundle_path()
        ).resolve(),
        "provider_release": (provider_release or provider_release_path()).resolve(),
    }

    profile_reports: dict[str, Any] = {}
    corpus_pairs: list[dict[str, Any]] = []
    total_actions: Counter[str] = Counter()
    total_applied = 0
    total_changed = 0
    total_noops = 0
    valid_false_rejections = 0

    for profile_name in PROFILE_NAMES:
        profile_actions: Counter[str] = Counter()
        profile_applied = 0
        profile_changed = 0
        profile_noops = 0
        off_task_passes = 0
        on_task_passes = 0
        off_request_scores: list[float] = []
        on_request_scores: list[float] = []
        profile_pair_semantics: list[dict[str, Any]] = []
        for seed in seed_values:
            seed_text = str(seed)
            off = _run_trajectory(
                paths=paths,
                profile_name=profile_name,
                seed=seed_text,
                enabled=False,
                trajectory=run_careful_reference,
            )
            on = _run_trajectory(
                paths=paths,
                profile_name=profile_name,
                seed=seed_text,
                enabled=True,
                trajectory=run_careful_reference,
            )
            pair_audit = audit_pair(off["exported"], on["exported"])
            off_passed = off["task_verification"]["passed"]
            on_passed = on["task_verification"]["passed"]
            off_task_passes += int(off_passed)
            on_task_passes += int(on_passed)
            valid_false_rejections += int(not off_passed) + int(not on_passed)
            off_request_scores.append(off["request_discipline"]["score"])
            on_request_scores.append(on["request_discipline"]["score"])
            on_audit = pair_audit["on"]
            profile_actions.update(on_audit["action_counts"])
            profile_applied += on_audit["applied_count"]
            profile_changed += on_audit["observation_changed_count"]
            profile_noops += on_audit["observational_noop_count"]
            semantic_row = {
                "profile": profile_name,
                "seed": seed_text,
                "pair_semantic_sha256": pair_audit["semantic_sha256"],
                "off_task_correctness": off["task_verification"]["score"],
                "on_task_correctness": on["task_verification"]["score"],
                "off_request_discipline": off["request_discipline"]["score"],
                "on_request_discipline": on["request_discipline"]["score"],
            }
            profile_pair_semantics.append(semantic_row)
            corpus_pairs.append(semantic_row)

        total_actions.update(profile_actions)
        total_applied += profile_applied
        total_changed += profile_changed
        total_noops += profile_noops
        profile_reports[profile_name] = {
            "dimensions": asdict(PROFILES[profile_name]),
            "pair_count": len(seed_values),
            "off_task_passes": off_task_passes,
            "on_task_passes": on_task_passes,
            "off_request_discipline_range": _score_range(off_request_scores),
            "on_request_discipline_range": _score_range(on_request_scores),
            "action_counts": dict(sorted(profile_actions.items())),
            "applied_count": profile_applied,
            "observation_changed_count": profile_changed,
            "observational_noop_count": profile_noops,
            "semantic_sha256": canonical_sha256(profile_pair_semantics),
        }

    quota_coverage = {
        profile_name: _run_quota_case(paths, profile_name=profile_name, seed=str(seed_values[0]))
        for profile_name in ("realistic", "hostile")
    }
    total_actions["quota_response"] += len(quota_coverage)
    total_applied += len(quota_coverage)
    total_changed += len(quota_coverage)
    for profile_name, quota_case in quota_coverage.items():
        profile_reports[profile_name]["targeted_quota"] = quota_case

    validation_cases = [
        _validation_case(
            paths,
            case_id="valid_careful",
            expected_pass=True,
            intended_check=None,
            profile_name="clean",
            seed=str(seed_values[0]),
            enabled=False,
            trajectory=run_careful_reference,
        ),
        _validation_case(
            paths,
            case_id="negative_incomplete_pagination",
            expected_pass=False,
            intended_check="complete_catalog_before_write",
            profile_name="clean",
            seed=str(seed_values[0]),
            enabled=False,
            trajectory=run_incomplete_pagination_trajectory,
        ),
        _validation_case(
            paths,
            case_id="negative_invalid_write",
            expected_pass=False,
            intended_check="quantity_transition_correct",
            profile_name="clean",
            seed=str(seed_values[0]),
            enabled=False,
            trajectory=run_invalid_write_trajectory,
        ),
        _validation_case(
            paths,
            case_id="negative_write_after_quota",
            expected_pass=False,
            intended_check="no_write_after_unresolved_read_failure",
            profile_name="realistic",
            seed=str(seed_values[0]),
            enabled=True,
            trajectory=run_mishandled_quota_trajectory,
        ),
    ]
    false_acceptance_count = sum(
        1 for case in validation_cases if not case["expected_pass"] and case["observed_pass"]
    )
    case_false_rejection_count = sum(
        1 for case in validation_cases if case["expected_pass"] and not case["observed_pass"]
    )
    valid_false_rejections += case_false_rejection_count

    efficient = _run_trajectory(
        paths=paths,
        profile_name="clean",
        seed=str(seed_values[0]),
        enabled=False,
        trajectory=run_careful_reference,
    )
    redundant = _run_trajectory(
        paths=paths,
        profile_name="clean",
        seed=str(seed_values[0]),
        enabled=False,
        trajectory=run_redundant_correct_reference,
    )
    quality_delta = (
        efficient["request_discipline"]["score"] - redundant["request_discipline"]["score"]
    )
    quality_discrimination = {
        "passed": (
            efficient["task_verification"]["passed"]
            and redundant["task_verification"]["passed"]
            and quality_delta >= 0.2
        ),
        "minimum_material_delta": 0.2,
        "observed_delta": quality_delta,
        "efficient": _quality_case(efficient),
        "redundant": _quality_case(redundant),
    }

    branch_coverage = {
        "json_type_drift": total_actions["json_type_drift"] > 0,
        "repeat_page": total_actions["repeat_page"] > 0,
        "quota_response": all(case["passed"] for case in quota_coverage.values()),
    }
    acceptance = {
        "all_configured_branches_reached": all(branch_coverage.values()),
        "all_pairs_independently_audited": True,
        "false_acceptance_count": false_acceptance_count,
        "false_rejection_count": valid_false_rejections,
        "quality_discrimination_passed": quality_discrimination["passed"],
    }
    acceptance["passed"] = (
        acceptance["all_configured_branches_reached"]
        and acceptance["false_acceptance_count"] == 0
        and acceptance["false_rejection_count"] == 0
        and acceptance["quality_discrimination_passed"]
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "experiment": "issue_6_v1_read_intervention_calibration",
        "provider_claim": "g1_source_grounded_synthetic_fixture",
        "scope": {
            "interventions": "read_only_v1",
            "negative_write": "existing_modeled_invalid_quantity_only",
            "excluded": ["write_timeout", "unknown_write_completion"],
        },
        "protocol": {
            "profiles": list(PROFILE_NAMES),
            "seed_start": seed_values[0],
            "seed_count": len(seed_values),
            "pair_count": len(seed_values) * len(PROFILE_NAMES),
            "only_paired_variable": "intervention_enabled",
            "client": "model_free_provider_valid_careful_read_v1",
            "aggregate_scope": "paired_on_sides_plus_targeted_quota_probes",
        },
        "profiles": profile_reports,
        "action_counts": dict(sorted(total_actions.items())),
        "applied_count": total_applied,
        "observation_changed_count": total_changed,
        "observational_noop_count": total_noops,
        "pair_corpus_semantic_sha256": canonical_sha256(corpus_pairs),
        "branch_coverage": branch_coverage,
        "quota_coverage": quota_coverage,
        "verifier_calibration": {
            "cases": validation_cases,
            "false_acceptance_count": false_acceptance_count,
            "false_rejection_count": case_false_rejection_count,
        },
        "quality_discrimination": quality_discrimination,
        "acceptance": acceptance,
    }
    report["report_semantic_sha256"] = canonical_sha256(report)
    if not acceptance["passed"]:
        raise RuntimeError("Issue #6 calibration acceptance failed")
    return report


def _run_trajectory(
    *,
    paths: dict[str, Path],
    profile_name: str,
    seed: str,
    enabled: bool,
    trajectory: Trajectory,
) -> dict[str, Any]:
    with _episode(paths, profile_name=profile_name, seed=seed, enabled=enabled) as episode:
        oracle = EvaluationOracle()
        result = trajectory(episode, oracle)
        task_verification = verify_task_for_episode(episode, oracle)
        request_discipline = request_discipline_report_for_episode(episode, oracle)
        exported = episode.export()
        audit = audit_episode_export(exported)
    return {
        "result": asdict(result),
        "task_verification": task_verification.to_dict(),
        "request_discipline": request_discipline.to_dict(),
        "audit": {key: value for key, value in audit.items() if key != "semantic"},
        "exported": exported,
    }


def _run_quota_case(paths: dict[str, Path], *, profile_name: str, seed: str) -> dict[str, Any]:
    with _episode(paths, profile_name=profile_name, seed=seed, enabled=True) as episode:
        observed = run_quota_probe(episode)
        exported = episode.export()
        audit = audit_episode_export(exported)
    threshold = PROFILES[profile_name].request_quota
    expected_index = None if threshold is None else threshold + 1
    passed = observed == {
        "logical_request_index": expected_index,
        "stage": "pre_dispatch",
        "base_invoked": False,
        "status_code": 429,
        "decision_kind": "quota_response",
        "action": {
            "kind": "quota_response",
            "response": {
                "status_code": 429,
                "headers": {"content-type": "application/json"},
                "body": {
                    "type": "rate_limit_error",
                    "message": "Request quota exceeded.",
                },
            },
        },
        "observation_changed": True,
    }
    return {
        "passed": passed,
        "profile": profile_name,
        "declared_request_quota": threshold,
        "expected_logical_request_index": expected_index,
        "observed": observed,
        "trace_semantic_sha256": audit["semantic_sha256"],
    }


def _validation_case(
    paths: dict[str, Path],
    *,
    case_id: str,
    expected_pass: bool,
    intended_check: str | None,
    profile_name: str,
    seed: str,
    enabled: bool,
    trajectory: Trajectory,
) -> dict[str, Any]:
    observed = _run_trajectory(
        paths=paths,
        profile_name=profile_name,
        seed=seed,
        enabled=enabled,
        trajectory=trajectory,
    )
    verification = observed["task_verification"]
    intended_result = None
    if intended_check is not None:
        intended_result = intended_check in verification["failed_check_ids"]
    return {
        "case_id": case_id,
        "expected_pass": expected_pass,
        "observed_pass": verification["passed"],
        "intended_failed_check": intended_check,
        "intended_check_failed": intended_result,
        "failed_check_ids": verification["failed_check_ids"],
        "task_correctness": verification["score"],
        "request_discipline": observed["request_discipline"],
        "trace_semantic_sha256": observed["audit"]["semantic_sha256"],
    }


def _quality_case(observed: dict[str, Any]) -> dict[str, Any]:
    return {
        "strategy": observed["result"]["strategy"],
        "task_correctness": observed["task_verification"]["score"],
        "request_discipline": observed["request_discipline"],
        "trace_semantic_sha256": observed["audit"]["semantic_sha256"],
    }


def _episode(
    paths: dict[str, Path], *, profile_name: str, seed: str, enabled: bool
) -> CommerceEpisode:
    return CommerceEpisode(
        provider_grounding=paths["provider_grounding"],
        provider_admission=paths["provider_admission"],
        provider_runtime_bundle=paths["provider_runtime_bundle"],
        provider_release=paths["provider_release"],
        policy=SeededCommercePolicy(PROFILES[profile_name]),
        intervention_seed=seed,
        intervention_enabled=enabled,
    )


def _score_range(values: list[float]) -> dict[str, float]:
    return {"minimum": min(values), "maximum": max(values)}


def write_report(path: Path, report: dict[str, Any]) -> None:
    path = path.resolve()
    if path.exists():
        raise FileExistsError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed-start", type=int, default=1)
    parser.add_argument("--seed-count", type=int, default=60)
    args = parser.parse_args(argv)
    if args.seed_start < 0:
        parser.error("--seed-start must be non-negative")
    if args.seed_count < 1:
        parser.error("--seed-count must be positive")
    report = run_public_calibration(seeds=range(args.seed_start, args.seed_start + args.seed_count))
    write_report(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
