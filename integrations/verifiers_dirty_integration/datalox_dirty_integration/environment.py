"""Verifiers 0.3.1 legacy entry point for the downstream experiment fixture."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import verifiers as vf
from datasets import Dataset

from datalox_dirty_integration.contract import (
    TASK_INSTRUCTIONS,
    provider_admission_path,
    provider_config_path,
    provider_release_path,
    provider_runtime_bundle_path,
)
from datalox_dirty_integration.episode import CommerceEpisode
from datalox_dirty_integration.policy import SeededCommercePolicy, load_profile
from datalox_dirty_integration.scoring import (
    EvaluationOracle,
    request_discipline_for_episode,
    task_correctness_for_episode,
)

ROLLOUT_EVIDENCE_SCHEMA_VERSION = "datalox_verifiers_rollout_evidence_v1"


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _write_rollout_evidence(
    *,
    evidence_root: Path,
    trajectory_id: str,
    profile: str,
    intervention_seed: str,
    intervention_enabled: bool,
    exported: dict[str, Any],
    scores: tuple[float, float],
) -> Path:
    """Atomically publish controller-only evidence for one completed rollout."""

    trajectory_sha256 = _sha256_bytes(trajectory_id.encode("utf-8"))
    rollout_dir = evidence_root / f"rollout-{trajectory_sha256.removeprefix('sha256:')}"
    if rollout_dir.exists():
        raise FileExistsError(f"rollout evidence already exists: {rollout_dir}")
    pending = Path(tempfile.mkdtemp(prefix=".pending-rollout-", dir=evidence_root))
    try:
        artifacts = {
            "provider-export.json": exported["provider"],
            "intervention-trace.json": exported["intervention"],
            "delivered-observations.json": {
                "schema_version": ROLLOUT_EVIDENCE_SCHEMA_VERSION,
                "calls": exported["delivered_calls"],
            },
            "verification.json": {
                "schema_version": ROLLOUT_EVIDENCE_SCHEMA_VERSION,
                "request_discipline": scores[1],
                "task_correctness": scores[0],
            },
        }
        artifact_digests: dict[str, str] = {}
        for name, value in artifacts.items():
            payload = _canonical_json_bytes(value)
            artifact_digests[name] = _sha256_bytes(payload)
            path = pending / name
            with path.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())

        manifest = {
            "schema_version": ROLLOUT_EVIDENCE_SCHEMA_VERSION,
            "trajectory_id_sha256": trajectory_sha256,
            "profile": profile,
            "intervention": {
                "enabled": intervention_enabled,
                "seed": intervention_seed,
                "policy_id": exported["intervention"]["policy_id"],
                "policy_version": exported["intervention"]["policy_version"],
                "policy_sha256": exported["intervention"]["policy_sha256"],
            },
            "provider": {
                "release_digest": exported["provider_release_digest"],
                "release_version": exported["provider_release_version"],
                "profile_id": exported["provider_profile_id"],
                "bundle_version": exported["provider_bundle_version"],
                "initial_state_fingerprint": exported["initial_state_fingerprint"],
                "config_sha256": exported["provider_config_sha256"],
                "runtime_sha256": exported["provider_runtime_sha256"],
                "admission_sha256": exported["provider_admission_sha256"],
                "operation_claims_sha256": exported["operation_claims_sha256"],
                "operation_contract_sha256": exported["operation_contract_sha256"],
            },
            "artifacts": artifact_digests,
        }
        manifest_payload = _canonical_json_bytes(manifest)
        with (pending / "manifest.json").open("xb") as handle:
            handle.write(manifest_payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, rollout_dir)
    except BaseException:
        shutil.rmtree(pending, ignore_errors=True)
        raise
    return rollout_dir


def list_products(
    offset: int = 0,
    limit: int = 10,
    episode: CommerceEpisode | None = None,
) -> str:
    """List one provider-issued page of products.

    Args:
        offset: Provider offset to request. Start at zero.
        limit: Page size. This admitted slice requires 10.
    """

    if episode is None:
        raise RuntimeError("episode runtime was not injected")
    response = episode.list_products(offset=offset, limit=limit)
    return json.dumps(
        {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response.body,
        },
        sort_keys=True,
    )


def submit_products(
    products_json: str,
    reported_count: int,
    episode: CommerceEpisode | None = None,
) -> str:
    """Submit the complete product set once.

    Args:
        products_json: JSON array of objects containing string `id` and `title`.
        reported_count: Collection count represented as a JSON integer.
    """

    if episode is None:
        raise RuntimeError("episode runtime was not injected")
    return json.dumps(
        episode.submit_products(products_json, reported_count=reported_count), sort_keys=True
    )


class DataloxDirtyIntegrationEnv(vf.StatefulToolEnv):
    """Creates one isolated Datalox provider state per rollout."""

    def __init__(
        self,
        *,
        provider_config: Path,
        provider_admission: Path,
        provider_runtime_bundle: Path,
        provider_release: Path,
        profile: str,
        intervention_seed: str,
        intervention_enabled: bool,
        evidence_dir: str | Path | None,
        **kwargs: Any,
    ) -> None:
        self.provider_config = provider_config
        self.provider_admission = provider_admission
        self.provider_runtime_bundle = provider_runtime_bundle
        self.provider_release = provider_release
        self._episodes: dict[str, CommerceEpisode] = {}
        self._score_cache: dict[str, tuple[float, float]] = {}
        self._oracle = EvaluationOracle.from_provider_config(self.provider_config)
        self.profile_name = profile
        self._intervention_seed = intervention_seed
        self.intervention_enabled = intervention_enabled
        if evidence_dir is None:
            self._evidence_dir = None
        else:
            self._evidence_dir = Path(evidence_dir).expanduser().resolve()
            self._evidence_dir.mkdir(parents=True, exist_ok=True)
            if not self._evidence_dir.is_dir():
                raise NotADirectoryError(
                    f"rollout evidence path is not a directory: {self._evidence_dir}"
                )
        rubric = vf.Rubric(
            funcs=[self.reward_task_correctness, self.reward_request_discipline],
            weights=[0.8, 0.2],
        )
        rubric.add_cleanup_handler(self._clear_cached_scores)
        super().__init__(tools=[], rubric=rubric, **kwargs)
        self.add_tool(list_products, args_to_skip=["episode"])
        self.add_tool(submit_products, args_to_skip=["episode"])

    async def setup_state(self, state: vf.State) -> vf.State:
        trajectory_id = state.get("trajectory_id")
        if not isinstance(trajectory_id, str) or not trajectory_id:
            raise ValueError("Verifiers state requires a trajectory_id")
        if trajectory_id in self._episodes:
            raise RuntimeError("provider state already exists for this trajectory")
        self._episodes[trajectory_id] = CommerceEpisode(
            provider_config=self.provider_config,
            policy=SeededCommercePolicy(load_profile(self.profile_name)),
            intervention_seed=self._intervention_seed,
            intervention_enabled=self.intervention_enabled,
            provider_admission=self.provider_admission,
            provider_runtime_bundle=self.provider_runtime_bundle,
            provider_release=self.provider_release,
        )
        return state

    def update_tool_args(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        messages: Any,
        state: vf.State,
        **kwargs: Any,
    ) -> dict[str, Any]:
        trajectory_id = state.get("trajectory_id")
        if not isinstance(trajectory_id, str):
            raise ValueError("Verifiers state requires a trajectory_id")
        episode = self._episodes.get(trajectory_id)
        if episode is None:
            raise RuntimeError("provider state is unavailable for this trajectory")
        return {**tool_args, "episode": episode}

    async def cleanup(
        self,
        state: vf.State,
        task: object | None = None,
        resources: object | None = None,
    ) -> None:
        trajectory_id = state.get("trajectory_id")
        try:
            if isinstance(trajectory_id, str):
                episode = self._episodes.pop(trajectory_id, None)
                if episode is not None:
                    try:
                        scores = (
                            task_correctness_for_episode(episode, self._oracle),
                            request_discipline_for_episode(episode, self._oracle),
                        )
                        if self._evidence_dir is not None:
                            _write_rollout_evidence(
                                evidence_root=self._evidence_dir,
                                trajectory_id=trajectory_id,
                                profile=self.profile_name,
                                intervention_seed=self._intervention_seed,
                                intervention_enabled=self.intervention_enabled,
                                exported=episode.export(),
                                scores=scores,
                            )
                        self._score_cache[trajectory_id] = scores
                    finally:
                        episode.close()
        finally:
            await super().cleanup(state, task=task, resources=resources)

    def reward_task_correctness(self, state: vf.State, **kwargs: Any) -> float:
        del kwargs
        return self._scores_for(state)[0]

    def reward_request_discipline(self, state: vf.State, **kwargs: Any) -> float:
        del kwargs
        return self._scores_for(state)[1]

    async def _clear_cached_scores(self, state: vf.State) -> None:
        trajectory_id = state.get("trajectory_id")
        if isinstance(trajectory_id, str):
            self._score_cache.pop(trajectory_id, None)

    def _scores_for(self, state: vf.State) -> tuple[float, float]:
        trajectory_id = state.get("trajectory_id")
        if not isinstance(trajectory_id, str):
            return (0.0, 0.0)
        return self._score_cache.get(trajectory_id, (0.0, 0.0))


def load_environment(
    profile: str = "realistic",
    intervention_enabled: bool = True,
    intervention_seed: str = "7",
    evidence_dir: str | Path | None = None,
    num_tasks: int = 12,
    max_turns: int = 30,
    **kwargs: Any,
) -> vf.Environment:
    """Load through ``vf.load_environment('datalox-dirty-integration', ...)``.

    This is intentionally the Verifiers 0.3.1 legacy surface used by
    ``dirty-integration``. Datalox remains a provider-behavior dependency;
    this downstream package owns its task, environment, and rewards.
    """

    profile_value = load_profile(profile)
    if type(num_tasks) is not int or num_tasks < 1:
        raise ValueError("num_tasks must be a positive integer")
    if not isinstance(intervention_seed, str) or not intervention_seed:
        raise ValueError("intervention_seed must be a non-empty string")
    config_path = provider_config_path().resolve()
    admission_path = provider_admission_path().resolve()
    runtime_bundle = provider_runtime_bundle_path().resolve()
    release = provider_release_path().resolve()
    if not config_path.is_file():
        raise FileNotFoundError(f"provider config does not exist: {config_path}")
    if not admission_path.is_file():
        raise FileNotFoundError(f"provider admission does not exist: {admission_path}")
    if not runtime_bundle.is_dir():
        raise FileNotFoundError(f"provider runtime bundle does not exist: {runtime_bundle}")
    if not release.is_dir():
        raise FileNotFoundError(f"provider release does not exist: {release}")

    dataset = Dataset.from_list(
        [{"question": TASK_INSTRUCTIONS, "answer": ""} for _ in range(num_tasks)]
    )
    environment = DataloxDirtyIntegrationEnv(
        provider_config=config_path,
        provider_admission=admission_path,
        provider_runtime_bundle=runtime_bundle,
        provider_release=release,
        profile=profile,
        intervention_seed=intervention_seed,
        intervention_enabled=intervention_enabled,
        evidence_dir=evidence_dir,
        dataset=dataset,
        max_turns=max_turns,
        **kwargs,
    )
    # Keep strict validation above while making the consumed profile explicit to
    # the operator. Environment attributes are not copied into rollout state.
    environment.datalox_profile = profile_value
    return environment
