"""Verifiers 0.3.1 legacy entry point for the downstream experiment fixture."""

from __future__ import annotations

import json
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
        if isinstance(trajectory_id, str):
            episode = self._episodes.pop(trajectory_id, None)
            if episode is not None:
                try:
                    scores = (
                        task_correctness_for_episode(episode, self._oracle),
                        request_discipline_for_episode(episode, self._oracle),
                    )
                finally:
                    episode.close()
                self._score_cache[trajectory_id] = scores
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
        dataset=dataset,
        max_turns=max_turns,
        **kwargs,
    )
    # Keep strict validation above while making the consumed profile explicit to
    # the operator. Environment attributes are not copied into rollout state.
    environment.datalox_profile = profile_value
    return environment
