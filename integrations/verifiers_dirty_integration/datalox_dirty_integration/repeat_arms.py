"""Versioned controller contract for the fixed 90-slot, three-arm experiment."""

from __future__ import annotations

from itertools import permutations
from typing import Annotated, Any, Literal, Self

from pydantic import BeforeValidator, StringConstraints, model_validator

from datalox_dirty_integration.repeat_contract import (
    ExperimentConfig,
    RolloutSlot,
    _integer_literal,
    build_schedule,
)

Arm = Literal["baseline", "budget12", "inert-reporting-label"]
ARMS: tuple[Arm, ...] = ("baseline", "budget12", "inert-reporting-label")
BUDGET_STOP = "harness_call_budget_exhausted"


class ArmSlot(RolloutSlot):
    slot_id: Annotated[
        str,
        StringConstraints(
            pattern=r"^r[0-9]+-s[0-9]+-(clean|hostile)-(baseline|budget12|inert-reporting-label)$"
        ),
    ]
    arm: Arm


def build_arm_schedule() -> list[ArmSlot]:
    """Interleave arms within profile/seed blocks; use each order five times.

    Each profile/seed stratum uses five distinct permutations across repeats.
    The thirty blocks use each of the six permutations five times overall.
    Profile order retains the V1 counterbalancing rule. No RNG is involved.
    """
    orders = tuple(permutations(ARMS))
    result = []
    for slot in build_schedule(("1", "7", "23"), 5):
        block = ("1", "7", "23").index(slot.seed) * 2 + (slot.profile == "hostile")
        for arm in orders[(block + slot.repetition - 1) % len(orders)]:
            result.append(
                ArmSlot(
                    **{
                        **slot.model_dump(),
                        "slot_id": f"{slot.slot_id}-{arm}",
                        "order": len(result),
                    },
                    arm=arm,
                )
            )
    return result


class ArmExperimentConfig(ExperimentConfig):
    schema_version: Literal["datalox_repeat_experiment_v2"] = "datalox_repeat_experiment_v2"
    repetitions: Annotated[Literal[5], BeforeValidator(_integer_literal)] = 5
    schedule: list[ArmSlot]

    @model_validator(mode="after")
    def fixed_experiment(self) -> Self:
        if self.per_rollout_reservation_usd > self.max_total_cost_usd:
            raise ValueError("per-rollout reservation must fit the total spending cap")
        if self.seeds != ("1", "7", "23") or self.schedule != build_arm_schedule():
            raise ValueError("V2 requires the exact counterbalanced 90-slot schedule")
        return self


def arm_controls(slot: ArmSlot) -> dict[str, Any]:
    """Reporting-only values; never pass the arm or label into the environment."""
    return {
        "arm": slot.arm,
        "provider_call_budget": 12 if slot.arm == "budget12" else None,
        "reporting_label": "inert-reporting-label" if slot.arm == "inert-reporting-label" else None,
    }


def parse_experiment(value: dict[str, Any]) -> ExperimentConfig | ArmExperimentConfig:
    import json

    contract = (
        ArmExperimentConfig
        if value.get("schema_version") == "datalox_repeat_experiment_v2"
        else ExperimentConfig
    )
    return contract.model_validate_json(json.dumps(value, allow_nan=False))


def effect_digest(exported: dict[str, Any]) -> str:
    from datalox_dirty_integration.audit import canonical_sha256

    return canonical_sha256(
        {key: exported[key] for key in ("provider", "intervention", "delivered_calls")}
    )


def audit_call_budget(
    receipt: dict[str, Any],
    slot: ArmSlot,
    exported: dict[str, Any],
    termination_reason: str,
    pending: list[dict[str, Any]],
) -> None:
    """Bind a controller stop to exactly twelve effects and an undispatched call."""
    from datalox_dirty_integration.repeat_evidence import (
        RepeatEvidenceError,
        _equal,
    )
    from datalox_dirty_integration.call_budget_environment import provider_tool_binds

    limit = arm_controls(slot)["provider_call_budget"]
    count = len(exported["delivered_calls"])
    rejection = receipt.get("rejection")
    _equal(
        receipt,
        {
            "schema_version": "datalox_harness_call_budget_v1",
            "limit": limit,
            "executed_provider_calls": count,
            "rejection": rejection,
            "termination_reason": termination_reason,
        },
        "call budget receipt",
    )
    if limit is not None and count > limit:
        raise RepeatEvidenceError("provider call budget exceeded")
    if rejection is None:
        if termination_reason == BUDGET_STOP:
            raise RepeatEvidenceError("budget termination requires a rejected request")
        return
    if limit != 12 or count != 12 or termination_reason != BUDGET_STOP or not pending:
        raise RepeatEvidenceError("budget rejection requires call 13 and native budget termination")
    _equal(
        rejection,
        {
            "requested_call_number": 13,
            "tool": pending[0],
            "effect_sha256": effect_digest(exported),
        },
        "budget rejection",
    )
    if not provider_tool_binds(pending[0]):
        raise RepeatEvidenceError("budget rejection requires a valid provider tool request")
