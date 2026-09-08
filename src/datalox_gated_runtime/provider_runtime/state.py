"""Canonical provider behavior-state projection shared by admission and execution."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from datalox_gated_runtime.json_digest import canonical_json_sha256


def project_provider_behavior_state(provider_state: Any) -> Any:
    """Remove receipt history while retaining every provider-behavior state field."""

    if not isinstance(provider_state, dict):
        return deepcopy(provider_state)
    if provider_state.get("protocol") == "gate_config_v1":
        return deepcopy(provider_state.get("shadow_state"))
    return {
        key: deepcopy(value)
        for key, value in provider_state.items()
        if key not in {"events", "verifier_events"}
    }


def provider_behavior_state_sha256(provider_state: Any) -> str:
    return canonical_json_sha256(project_provider_behavior_state(provider_state))
