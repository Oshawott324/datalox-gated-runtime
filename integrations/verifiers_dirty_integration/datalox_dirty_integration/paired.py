"""One-command paired off/on runner for the Serhii experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from datalox_dirty_integration.contract import (
    TASK_INSTRUCTIONS,
    provider_admission_path,
    provider_config_path,
    provider_release_path,
    provider_runtime_bundle_path,
)
from datalox_dirty_integration.episode import CommerceEpisode, sha256_file
from datalox_dirty_integration.policy import SeededCommercePolicy, load_profile
from datalox_dirty_integration.reference import run_careful_reference, run_naive_reference
from datalox_dirty_integration.scoring import EvaluationOracle

SCHEMA_VERSION = "datalox_verifiers_paired_experiment_v1"


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_side(
    *,
    output: Path,
    provider_config: Path,
    provider_admission: Path,
    provider_runtime_bundle: Path,
    provider_release: Path,
    policy: SeededCommercePolicy,
    intervention_seed: str,
    enabled: bool,
) -> dict[str, Any]:
    with CommerceEpisode(
        provider_config=provider_config,
        policy=policy,
        intervention_seed=intervention_seed,
        intervention_enabled=enabled,
        provider_admission=provider_admission,
        provider_runtime_bundle=provider_runtime_bundle,
        provider_release=provider_release,
    ) as episode:
        oracle = EvaluationOracle.from_provider_config(provider_config)
        result = run_careful_reference(episode, oracle)
        exported = episode.export()
        agent_trace = {
            "schema_version": SCHEMA_VERSION,
            "strategy": result.strategy,
            "outcome": result.outcome,
            "calls": exported["delivered_calls"],
            "submission": list(result.submitted),
            "reported_count": result.reported_count,
        }
        verification = {
            "schema_version": SCHEMA_VERSION,
            "task_correctness": result.task_correctness,
            "request_discipline": result.request_discipline,
        }
        _write_json(output / "provider-export.json", exported["provider"])
        _write_json(output / "intervention-trace.json", exported["intervention"])
        _write_json(output / "agent-trace.json", agent_trace)
        _write_json(output / "verification.json", verification)
        return {
            "enabled": enabled,
            "provider_config_sha256": exported["provider_config_sha256"],
            "provider_runtime_sha256": exported["provider_runtime_sha256"],
            "provider_admission_sha256": exported["provider_admission_sha256"],
            "operation_claims_sha256": exported["operation_claims_sha256"],
            "operation_contract_sha256": exported["operation_contract_sha256"],
            "provider_release_config_sha256": exported["provider_release_config_sha256"],
            "provider_release_digest": exported["provider_release_digest"],
            "provider_release_version": exported["provider_release_version"],
            "provider_profile_id": exported["provider_profile_id"],
            "provider_bundle_version": exported["provider_bundle_version"],
            "initial_state_fingerprint": exported["initial_state_fingerprint"],
            "agent_trace_sha256": _canonical_digest(agent_trace),
            "intervention_trace_sha256": _canonical_digest(exported["intervention"]),
            "task_correctness": result.task_correctness,
            "request_discipline": result.request_discipline,
            "outcome": result.outcome,
            "calls": exported["delivered_calls"],
        }


def run_pair(
    *,
    output: Path,
    provider_config: Path,
    provider_admission: Path,
    provider_runtime_bundle: Path,
    provider_release: Path,
    profile: str,
    intervention_seed: str,
) -> dict[str, Any]:
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    provider_config = provider_config.resolve()
    provider_admission = provider_admission.resolve()
    provider_runtime_bundle = provider_runtime_bundle.resolve()
    provider_release = provider_release.resolve()
    policy = SeededCommercePolicy(load_profile(profile))
    task_digest = _canonical_digest({"instructions": TASK_INSTRUCTIONS})
    fixed_inputs = {
        "task_sha256": task_digest,
        "provider_config_artifact": "medusa_store_pagination_v0:gate_config",
        "provider_config_sha256": sha256_file(provider_config),
        "provider_admission_artifact": "medusa_store_pagination_v0:provider_admission",
        "provider_admission_sha256": sha256_file(provider_admission),
        "provider_runtime_artifact": "medusa_store_pagination_v0:provider_runtime",
        "provider_release_artifact": "medusa_store_pagination_v0:provider_release",
        "intervention_seed": intervention_seed,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_sha256": policy.policy_sha256,
        "agent": "model_free_provider_valid_careful_v1",
    }
    off = _run_side(
        output=output / "off",
        provider_config=provider_config,
        provider_admission=provider_admission,
        provider_runtime_bundle=provider_runtime_bundle,
        provider_release=provider_release,
        policy=policy,
        intervention_seed=intervention_seed,
        enabled=False,
    )
    on = _run_side(
        output=output / "on",
        provider_config=provider_config,
        provider_admission=provider_admission,
        provider_runtime_bundle=provider_runtime_bundle,
        provider_release=provider_release,
        policy=policy,
        intervention_seed=intervention_seed,
        enabled=True,
    )
    if off["initial_state_fingerprint"] != on["initial_state_fingerprint"]:
        raise RuntimeError("paired provider states do not have the same initial fingerprint")
    fixed_inputs["provider_runtime_sha256"] = off["provider_runtime_sha256"]
    fixed_inputs["operation_claims_sha256"] = off["operation_claims_sha256"]
    fixed_inputs["operation_contract_sha256"] = off["operation_contract_sha256"]
    fixed_inputs["provider_release_config_sha256"] = off["provider_release_config_sha256"]
    fixed_inputs["provider_release_digest"] = off["provider_release_digest"]
    fixed_inputs["provider_release_version"] = off["provider_release_version"]
    fixed_inputs["provider_profile_id"] = off["provider_profile_id"]
    fixed_inputs["provider_bundle_version"] = off["provider_bundle_version"]
    first_divergence = _first_observation_divergence(off["calls"], on["calls"])
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "fixed_inputs": fixed_inputs,
        "controlled_variable": {
            "off": False,
            "on": True,
            "name": "intervention_enabled",
        },
        "initial_state_fingerprint": off["initial_state_fingerprint"],
    }
    comparison = {
        "schema_version": SCHEMA_VERSION,
        "binding_checks": {
            "same_task": True,
            "same_provider_config": off["provider_config_sha256"] == on["provider_config_sha256"],
            "same_provider_admission": off["provider_admission_sha256"]
            == on["provider_admission_sha256"],
            "same_operation_claims": off["operation_claims_sha256"]
            == on["operation_claims_sha256"],
            "same_operation_contract": off["operation_contract_sha256"]
            == on["operation_contract_sha256"],
            "same_provider_release": off["provider_release_digest"]
            == on["provider_release_digest"],
            "same_initial_provider_state": off["initial_state_fingerprint"]
            == on["initial_state_fingerprint"],
            "same_intervention_policy_and_seed": True,
            "only_intervention_enabled_differs": True,
        },
        "off": {key: off[key] for key in ("outcome", "task_correctness", "request_discipline")},
        "on": {key: on[key] for key in ("outcome", "task_correctness", "request_discipline")},
        "first_delivered_observation_divergence": first_divergence,
    }
    _write_json(output / "pair-manifest.json", manifest)
    _write_json(output / "comparison.json", comparison)
    return comparison


def calibrate(
    *,
    provider_config: Path,
    provider_admission: Path,
    provider_runtime_bundle: Path,
    provider_release: Path,
    profile: str,
    seeds: range,
) -> dict[str, Any]:
    policy = SeededCommercePolicy(load_profile(profile))
    careful: list[dict[str, Any]] = []
    naive: list[dict[str, Any]] = []
    for seed in seeds:
        for strategy, target in ((run_careful_reference, careful), (run_naive_reference, naive)):
            with CommerceEpisode(
                provider_config=provider_config,
                policy=policy,
                intervention_seed=str(seed),
                intervention_enabled=True,
                provider_admission=provider_admission,
                provider_runtime_bundle=provider_runtime_bundle,
                provider_release=provider_release,
            ) as episode:
                oracle = EvaluationOracle.from_provider_config(provider_config)
                target.append(asdict(strategy(episode, oracle)))
    return {
        "profile": profile,
        "seeds": list(seeds),
        "careful": careful,
        "naive": naive,
    }


def _first_observation_divergence(
    off_calls: list[dict[str, Any]], on_calls: list[dict[str, Any]]
) -> dict[str, Any] | None:
    for index, (off, on) in enumerate(zip(off_calls, on_calls, strict=False)):
        if off != on:
            return {"index": index, "off": off, "on": on}
    if len(off_calls) != len(on_calls):
        return {"index": min(len(off_calls), len(on_calls)), "reason": "call_count_differs"}
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("clean", "realistic", "hostile"), default="hostile")
    parser.add_argument("--intervention-seed", default="7")
    args = parser.parse_args(argv)
    comparison = run_pair(
        output=args.output,
        provider_config=provider_config_path(),
        provider_admission=provider_admission_path(),
        provider_runtime_bundle=provider_runtime_bundle_path(),
        provider_release=provider_release_path(),
        profile=args.profile,
        intervention_seed=args.intervention_seed,
    )
    print(json.dumps(comparison, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
