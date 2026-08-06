#!/usr/bin/env python3
"""Prove mutation, verification, functional reset, and replay without a provider."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Mapping, Sequence

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.world_v1.backend import (
    WorldBundleBackend,
    initialize_world_bundle_session,
)
from datalox_gated_runtime.world_v1.contracts import ActorContext


ROOT = Path(__file__).resolve().parents[2]
ENV_DIR = ROOT / "envs/commerce_support_ops_v0"
TRAJECTORIES_PATH = ENV_DIR / "tests/trajectories/trajectories.json"
EPISODE_ID = "refund-duplicate-payment-clean"
TRAJECTORY_ID = "reference-refund-duplicate-payment-clean"
ROLES = (
    "billing_specialist",
    "communications_owner",
    "engineering_owner",
    "support_owner",
)


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _load_steps() -> tuple[Mapping[str, Any], ...]:
    raw = json.loads(TRAJECTORIES_PATH.read_text(encoding="utf-8"))
    matches = [item for item in raw["trajectories"] if item["id"] == TRAJECTORY_ID]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one trajectory {TRAJECTORY_ID!r}")
    trajectory = matches[0]
    if trajectory["episode_id"] != EPISODE_ID or trajectory["expected"] != {
        "failure_codes": [],
        "passed": True,
    }:
        raise RuntimeError("offline trajectory declaration is not the reviewed passing case")
    return tuple(trajectory["steps"])


def _request(step: Mapping[str, Any], index: int) -> CallRequest:
    role = step["actor_role"]
    return CallRequest(
        method=step["method"],
        path=step["path"],
        query=step.get("query", {}),
        body=step.get("body"),
        headers={
            "x-datalox-actor-id": f"offline-smoke-{index}",
            "x-datalox-actor-role": role,
        },
    )


def _probe(backend: WorldBundleBackend, first_step: Mapping[str, Any]) -> dict[str, Any]:
    capabilities = {
        role: backend.tool_schemas(ActorContext(actor_id=f"probe-{role}", role=role))
        for role in ROLES
    }
    response = backend.handle(_request(first_step, 0))
    if response is None or response.status_code != 200 or response.is_mutation:
        raise RuntimeError("functional reset probe did not produce the reviewed read response")
    return {
        "capabilities": capabilities,
        "initial_state": backend.session.list_state(),
        "observation": {
            "status_code": response.status_code,
            "body": response.body,
            "decision_kind": response.decision_kind,
            "reason_code": response.reason_code,
        },
    }


def _execute(backend: WorldBundleBackend, steps: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    decisions: list[dict[str, Any]] = []
    for index, step in enumerate(steps, start=1):
        response = backend.handle(_request(step, index))
        if response is None:
            raise RuntimeError(f"trajectory step {index} did not map to a world operation")
        if not 200 <= response.status_code < 300:
            raise RuntimeError(
                f"trajectory step {index} returned unexpected HTTP {response.status_code}"
            )
        expected_mutation = step["method"].upper() not in {"GET", "HEAD"}
        if response.is_mutation != expected_mutation:
            raise RuntimeError(f"trajectory step {index} mutation classification differs")
        decisions.append(
            {
                "decision_kind": response.decision_kind,
                "is_mutation": response.is_mutation,
                "operation_id": response.operation_id,
                "status_code": response.status_code,
            }
        )
    verifier = backend.verify()
    if not verifier.passed:
        raise RuntimeError(f"reviewed trajectory failed verification: {verifier.to_dict()}")
    return {
        "decisions": decisions,
        "export": backend.session.export(),
        "verifier": verifier.to_dict(),
    }


def _initialize(run_dir: Path) -> WorldBundleBackend:
    initialize_world_bundle_session(
        source_bundle_dir=ENV_DIR,
        run_dir=run_dir,
        episode_id=EPISODE_ID,
    )
    return WorldBundleBackend(run_dir=run_dir)


def main() -> int:
    steps = _load_steps()
    with tempfile.TemporaryDirectory(prefix="datalox-offline-world-") as temporary:
        run_dir = Path(temporary) / "world"

        first = _initialize(run_dir)
        try:
            first_probe = _probe(first, steps[0])
            first_result = _execute(first, steps)
        finally:
            first.close()

        if _canonical_hash(first_probe["initial_state"]) == _canonical_hash(
            first_result["export"]["state"]
        ):
            raise RuntimeError("reviewed trajectory did not mutate durable world state")

        shutil.rmtree(run_dir)
        second = _initialize(run_dir)
        try:
            second_probe = _probe(second, steps[0])
            if _canonical_hash(first_probe) != _canonical_hash(second_probe):
                raise RuntimeError(
                    "functional reset changed capabilities, initial state, or observations"
                )
            second_result = _execute(second, steps)
        finally:
            second.close()

        first_final = _canonical_hash(first_result["export"])
        second_final = _canonical_hash(second_result["export"])
        if first_final != second_final:
            raise RuntimeError(
                "replayed workflow did not produce equivalent final state and evidence"
            )
        if first_result["verifier"] != second_result["verifier"]:
            raise RuntimeError("replayed workflow produced a different verifier verdict")

        mutation_count = sum(1 for decision in first_result["decisions"] if decision["is_mutation"])
        read_count = len(first_result["decisions"]) - mutation_count
        result = {
            "schema_version": "datalox_offline_world_smoke_v1",
            "passed": True,
            "credentials_used": False,
            "network_used": False,
            "world_id": "commerce_support_ops_v0",
            "episode_id": EPISODE_ID,
            "trajectory_id": TRAJECTORY_ID,
            "read_count": read_count,
            "mutation_count": mutation_count,
            "functional_reset_equivalent": True,
            "replay_equivalent": True,
            "verifier_passed": True,
            "initial_probe_sha256": _canonical_hash(first_probe),
            "final_export_sha256": first_final,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
