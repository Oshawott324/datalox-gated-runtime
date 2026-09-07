"""Quota-branch coverage for the seeded intervention policy.

The supplied careful trajectory stays below every configured threshold, so the
pre-dispatch quota decision was never exercised by a deterministic run. These
tests separate two claims that the fixture previously conflated:

* a plausible trajectory reaches the quota on some seeds, and
* the quota decision itself is attributed correctly when it is reached.

Everything here is model-free and offline.
"""

from __future__ import annotations

from typing import Any

import pytest

from datalox_dirty_integration.contract import (
    provider_admission_path,
    provider_config_path,
    provider_release_path,
    provider_runtime_bundle_path,
)
from datalox_dirty_integration.episode import CommerceEpisode
from datalox_dirty_integration.policy import PROFILES, SeededCommercePolicy, load_profile
from datalox_dirty_integration.reference import (
    run_careful_reference,
    run_persistent_reference,
)
from datalox_dirty_integration.scoring import EvaluationOracle

QUOTA_KIND = "quota_response"


def _episode(profile: str, seed: str) -> CommerceEpisode:
    return CommerceEpisode(
        provider_config=provider_config_path(),
        policy=SeededCommercePolicy(load_profile(profile)),
        intervention_seed=seed,
        intervention_enabled=True,
        provider_admission=provider_admission_path(),
        provider_runtime_bundle=provider_runtime_bundle_path(),
        provider_release=provider_release_path(),
    )


def _quota_events(episode: CommerceEpisode) -> list[dict[str, Any]]:
    trace = episode.export()["intervention"]
    return [event for event in trace["events"] if event["decision"]["kind"] == QUOTA_KIND]


def test_careful_trajectory_never_reaches_the_quota() -> None:
    """Documents the coverage gap the persistent client exists to close."""

    for profile in ("realistic", "hostile"):
        with _episode(profile, "3") as episode:
            oracle = EvaluationOracle.from_provider_config(provider_config_path())
            result = run_careful_reference(episode, oracle)
            assert result.outcome == "submitted"
            assert _quota_events(episode) == []


def test_persistent_trajectory_reaches_the_quota() -> None:
    with _episode("realistic", "3") as episode:
        oracle = EvaluationOracle.from_provider_config(provider_config_path())
        result = run_persistent_reference(episode, oracle)
        assert result.outcome == "rate_limited"
        assert _quota_events(episode)


@pytest.mark.parametrize("profile", ["realistic", "hostile"])
def test_quota_decision_is_attributed_at_the_declared_index(profile: str) -> None:
    """The quota fires one request past the threshold and costs no provider call."""

    quota = PROFILES[profile].request_quota
    assert quota is not None
    with _episode(profile, "1") as episode:
        for _ in range(quota + 3):
            episode.list_products(offset=0, limit=10)
        events = _quota_events(episode)

    assert [event["logical_request_index"] for event in events] == list(range(quota + 1, quota + 4))
    for event in events:
        assert event["stage"] == "pre_dispatch"
        assert event["applied"] is True
        assert event["base"]["invoked"] is False
        assert event["delivered"]["response"]["status_code"] == 429
        assert event["decision"]["decision_id"] is not None
        assert event["decision"]["action_sha256"] is not None


def test_calls_below_the_threshold_are_never_quota_denied() -> None:
    quota = PROFILES["realistic"].request_quota
    assert quota is not None
    with _episode("realistic", "1") as episode:
        statuses = [episode.list_products(offset=0, limit=10).status_code for _ in range(quota)]

    assert 429 not in statuses
