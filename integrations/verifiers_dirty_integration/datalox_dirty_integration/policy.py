"""Consumer-owned seeded intervention policy for the Serhii experiment.

The generic Datalox core executes decisions from this policy. This downstream
fixture alone owns the distribution, profile names, and fault frequency.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from datalox_gated_runtime.interception.interventions import (
    InterventionDecision,
    JsonTypeDriftAction,
    QuotaResponseAction,
    RepeatPageAction,
)
from datalox_gated_runtime.models import CallRequest

LIST_PRODUCTS_OPERATION = "medusa.store.products.list"


def _draw(*, seed: str, logical_request_index: int, salt: str) -> float:
    key = f"{seed}:{logical_request_index}:{salt}".encode()
    return int.from_bytes(hashlib.sha256(key).digest()[:8], "big") / 2**64


@dataclass(frozen=True)
class FaultProfile:
    repeat_page_rate: float
    count_type_drift_rate: float
    request_quota: int | None

    def __post_init__(self) -> None:
        for field_name in ("repeat_page_rate", "count_type_drift_rate"):
            value = getattr(self, field_name)
            if type(value) not in {float, int} or not 0 <= value <= 1:
                raise ValueError(f"{field_name} must be a number in [0, 1]")
        if self.request_quota is not None and (
            type(self.request_quota) is not int or self.request_quota < 1
        ):
            raise ValueError("request_quota must be a positive integer or null")


PROFILES: dict[str, FaultProfile] = {
    "clean": FaultProfile(0.0, 0.0, None),
    "realistic": FaultProfile(0.15, 0.25, 12),
    "hostile": FaultProfile(0.30, 0.50, 16),
}


class SeededCommercePolicy:
    """Pure deterministic policy over ``(seed, logical request index)``.

    The quota is evaluated first because it is a pre-dispatch outcome. A call
    that is still within budget receives at most one post-response mutation.
    The Datalox core applies the returned action exactly once.
    """

    policy_id = "serhii_commerce_read_faults"
    policy_version = "1"

    def __init__(self, profile: FaultProfile) -> None:
        self.profile = profile
        canonical = json.dumps(
            {
                "policy_id": self.policy_id,
                "profile": asdict(profile),
                "version": self.policy_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.policy_sha256 = f"sha256:{hashlib.sha256(canonical).hexdigest()}"

    def decide(
        self,
        *,
        seed: str,
        logical_request_index: int,
        operation_id: str,
        request: CallRequest,
    ) -> InterventionDecision | None:
        if operation_id != LIST_PRODUCTS_OPERATION:
            return None
        self._require_list_request(request)

        quota = self.profile.request_quota
        if quota is not None and logical_request_index > quota:
            return self._decision(
                seed=seed,
                logical_request_index=logical_request_index,
                action=QuotaResponseAction(
                    status_code=429,
                    headers={"content-type": "application/json"},
                    body={
                        "type": "rate_limit_error",
                        "message": "Request quota exceeded.",
                    },
                ),
            )

        if logical_request_index > 1 and (
            _draw(
                seed=seed,
                logical_request_index=logical_request_index,
                salt="repeat_page",
            )
            < self.profile.repeat_page_rate
        ):
            return self._decision(
                seed=seed,
                logical_request_index=logical_request_index,
                action=RepeatPageAction(source_request_index=logical_request_index - 1),
            )

        if (
            _draw(
                seed=seed,
                logical_request_index=logical_request_index,
                salt="count_type_drift",
            )
            < self.profile.count_type_drift_rate
        ):
            return self._decision(
                seed=seed,
                logical_request_index=logical_request_index,
                action=JsonTypeDriftAction(
                    pointer="/count",
                    from_type="integer",
                    to_type="string",
                    value="50",
                ),
            )
        return None

    def _decision(
        self,
        *,
        seed: str,
        logical_request_index: int,
        action: Any,
    ) -> InterventionDecision:
        digest = hashlib.sha256(
            f"{self.policy_sha256}:{seed}:{logical_request_index}:{type(action).__name__}".encode()
        ).hexdigest()[:24]
        return InterventionDecision(
            decision_id=f"decision_{digest}",
            operation_id=LIST_PRODUCTS_OPERATION,
            action=action,
        )

    @staticmethod
    def _require_list_request(request: CallRequest) -> None:
        if (
            request.normalized_method() != "GET"
            or request.authority != "api.medusa.local"
            or request.path != "/store/products"
        ):
            raise ValueError("list-products policy received a request outside its operation")


def load_profile(name: str) -> FaultProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown profile {name!r}; expected one of {sorted(PROFILES)}") from exc
