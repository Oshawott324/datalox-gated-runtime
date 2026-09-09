"""Regression trajectories for verifier checks the V1 calibration never breaks.

The V1 calibration declares three negatives, and between them they break three
of the twelve named checks. A check that nothing can break is not evidence that
it works, so every trajectory here is a plausible agent mistake: five reach a
check no declared negative fails, and two give an already covered failure a
second, intervention-driven cause.

Each row carries its own seed, because a trajectory written to fail on one
intervention proves nothing if an earlier intervention of another kind already
broke the same check.

This is regression coverage. It does not change the V1 acceptance gate.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest

from datalox_dirty_integration.contract import (
    provider_admission_path,
    provider_grounding_path,
    provider_release_path,
    provider_runtime_bundle_path,
)
from datalox_dirty_integration.episode import CommerceEpisode
from datalox_dirty_integration.policy import PROFILES, SeededCommercePolicy
from datalox_dirty_integration.reference import (
    run_careful_reference,
    run_credulous_repeat_trajectory,
    run_extra_variant_trajectory,
    run_second_cart_trajectory,
    run_type_credulous_trajectory,
    run_unconfirmed_write_trajectory,
    run_unrelated_cart_trajectory,
    run_wrong_variant_trajectory,
)
from datalox_dirty_integration.scoring import EvaluationOracle, verify_task_for_episode

#: Checks the V1 calibration already breaks with its own negatives.
V1_COVERED = frozenset(
    {
        "complete_catalog_before_write",
        "quantity_transition_correct",
        "no_write_after_unresolved_read_failure",
    }
)

#: trajectory, profile, seed, and the check it is written to break.
REGRESSIONS: tuple[tuple[str, Callable[..., Any], str, str, str], ...] = (
    (
        "wrong_variant",
        run_wrong_variant_trajectory,
        "clean",
        "7",
        "lowest_price_variant_added_once",
    ),
    ("extra_variant", run_extra_variant_trajectory, "clean", "7", "final_provider_state_matches"),
    ("second_cart", run_second_cart_trajectory, "clean", "7", "single_expected_cart_created"),
    ("unrelated_cart", run_unrelated_cart_trajectory, "clean", "7", "single_final_cart"),
    (
        "unconfirmed_write",
        run_unconfirmed_write_trajectory,
        "clean",
        "7",
        "confirmation_read_matches",
    ),
    # Seed 2 drifts the count type on request 2 with no repeat before it. On
    # seed 7 the first two interventions are repeats, which would leave the
    # catalog incomplete before the drift this trajectory is written for.
    (
        "type_credulous",
        run_type_credulous_trajectory,
        "hostile",
        "2",
        "complete_catalog_before_write",
    ),
    (
        "credulous_repeat",
        run_credulous_repeat_trajectory,
        "hostile",
        "7",
        "complete_catalog_before_write",
    ),
)


def _applied_kinds(episode: CommerceEpisode) -> tuple[str, ...]:
    """Kinds of the interventions that actually reached the client, in order."""

    return tuple(
        event["decision"]["kind"]
        for event in episode.export()["intervention"]["events"]
        if event["applied"]
    )


def _run(trajectory: Callable[..., Any], profile: str, seed: str) -> tuple[Any, tuple[str, ...]]:
    with CommerceEpisode(
        provider_grounding=provider_grounding_path(),
        provider_admission=provider_admission_path(),
        provider_runtime_bundle=provider_runtime_bundle_path(),
        provider_release=provider_release_path(),
        policy=SeededCommercePolicy(PROFILES[profile]),
        intervention_seed=seed,
        intervention_enabled=True,
    ) as episode:
        trajectory(episode, EvaluationOracle())
        return verify_task_for_episode(episode, EvaluationOracle()), _applied_kinds(episode)


def _verify(trajectory: Callable[..., Any], profile: str, seed: str) -> Any:
    report, _ = _run(trajectory, profile, seed)
    return report


@pytest.mark.parametrize(
    ("name", "trajectory", "profile", "seed", "intended"),
    REGRESSIONS,
    ids=[row[0] for row in REGRESSIONS],
)
def test_regression_trajectory_fails_its_intended_check(
    name: str, trajectory: Callable[..., Any], profile: str, seed: str, intended: str
) -> None:
    """The intended check must be the first verifier failure.

    Verification is fail-fast, so an earlier failure would hide the one the
    trajectory is written for. The exact tuple asserts that nothing masks it,
    not that no later check would also have failed.
    """

    del name
    report = _verify(trajectory, profile, seed)
    assert report.failed_check_ids == (intended,)
    assert report.score == 0.0


def test_valid_trajectory_is_not_rejected() -> None:
    """The regressions must not have made the verifier trigger-happy."""

    report = _verify(run_careful_reference, "clean", "7")
    assert report.failed_check_ids == ()
    assert report.score == 1.0


def test_regressions_reach_checks_the_v1_negatives_never_break() -> None:
    """Five checks gain their first failing trajectory here."""

    reached = {intended for *_, intended in REGRESSIONS}
    assert reached - V1_COVERED == {
        "lowest_price_variant_added_once",
        "final_provider_state_matches",
        "single_expected_cart_created",
        "single_final_cart",
        "confirmation_read_matches",
    }


def test_incomplete_catalog_has_two_distinct_causes() -> None:
    """Type drift and a repeated page fail the same check for different reasons.

    Each runs on the seed whose first intervention is the one under test, so
    neither result can be explained by the other kind of fault.
    """

    drift, drift_kinds = _run(run_type_credulous_trajectory, "hostile", "2")
    repeat, repeat_kinds = _run(run_credulous_repeat_trajectory, "hostile", "7")
    assert drift_kinds == ("json_type_drift",)
    assert repeat_kinds[0] == "repeat_page"
    assert drift.failed_check_ids == ("complete_catalog_before_write",)
    assert repeat.failed_check_ids == ("complete_catalog_before_write",)
