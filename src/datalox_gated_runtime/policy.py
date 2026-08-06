from __future__ import annotations

from dataclasses import dataclass

from datalox_gated_runtime.models import (
    CallRequest,
    DenyRuleConfig,
    GateDecision,
    PolicyConfig,
    RouteRule,
    path_prefix_matches,
)


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    method: str
    path_prefix: str
    decision_kind: str
    reason_code: str
    message: str

    def matches(self, request: CallRequest) -> bool:
        return self.method.upper() == request.normalized_method() and path_prefix_matches(
            request.path, self.path_prefix
        )

    def decision(self) -> GateDecision:
        return GateDecision(
            kind=self.decision_kind,  # type: ignore[arg-type]
            reason_code=self.reason_code,
            message=self.message,
            rule_id=self.rule_id,
        )


class GatePolicy:
    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        *,
        deny: list[DenyRuleConfig] | None = None,
        shadow_write: list[RouteRule] | None = None,
        live_capture: list[RouteRule] | None = None,
        config_owned: bool = False,
        allow_live: bool = False,
    ) -> None:
        self._rules = rules or []
        self._deny = deny or []
        self._shadow_write = shadow_write or []
        self._live_capture = live_capture or []
        self._config_owned = config_owned
        self._allow_live = allow_live

    @classmethod
    def default(cls) -> GatePolicy:
        return cls(
            rules=[
                PolicyRule(
                    rule_id="deny_live_robot_action",
                    method="POST",
                    path_prefix="/robot/",
                    decision_kind="deny",
                    reason_code="live_action_not_allowed",
                    message="Live robot or hardware actions are blocked in gated runtime.",
                ),
                PolicyRule(
                    rule_id="deny_run_start",
                    method="POST",
                    path_prefix="/runs/",
                    decision_kind="deny",
                    reason_code="live_run_action_not_allowed",
                    message="Live run actions are blocked in gated runtime.",
                ),
            ]
        )

    @classmethod
    def from_config(cls, policy: PolicyConfig | None, *, allow_live: bool = False) -> GatePolicy:
        if policy is None:
            return cls.default()
        return cls(
            deny=list(policy.deny),
            shadow_write=list(policy.shadow_write),
            live_capture=list(policy.live_capture),
            config_owned=True,
            allow_live=allow_live,
        )

    def decide(
        self,
        request: CallRequest,
        has_response_case: bool,
        *,
        has_shadow_write: bool = False,
    ) -> GateDecision:
        for rule in self._rules:
            if rule.matches(request):
                return rule.decision()
        for rule in self._deny:
            if _deny_rule_matches(rule, request):
                return GateDecision(
                    kind="deny",
                    reason_code=rule.reason_code,
                    message=rule.message,
                )

        method = request.normalized_method()
        if method == "GET" and has_shadow_write:
            return GateDecision(
                kind="shadow_read",
                reason_code="shadow_state_overlay_v0",
                message="Returned a shadow state overlay for this read.",
            )
        if method == "GET" and has_response_case:
            return GateDecision(
                kind="replay",
                reason_code="captured_response_replayed",
                message="Returned a captured response case.",
            )
        if method == "GET" and self._allow_live and _any_rule_matches(self._live_capture, request):
            return GateDecision(
                kind="live_capture",
                reason_code="live_capture_allowed",
                message="Call may be captured from the live provider.",
            )
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            if self._config_owned:
                if _any_rule_matches(self._shadow_write, request):
                    return GateDecision(
                        kind="shadow_write",
                        reason_code="write_shadowed",
                        message="Write was recorded in shadow state and not sent to a live provider.",
                    )
                return GateDecision(
                    kind="deny",
                    reason_code="write_not_permitted",
                    message=(
                        "Write path is not permitted by this environment policy. "
                        "Add a policy.shadow_write rule for this path."
                    ),
                )
            return GateDecision(
                kind="shadow_write",
                reason_code="write_shadowed",
                message="Write was recorded in shadow state and not sent to a live provider.",
            )
        return GateDecision(
            kind="miss",
            reason_code="no_admissible_response_case",
            message="No admissible response case matched this call.",
        )


def _deny_rule_matches(rule: DenyRuleConfig, request: CallRequest) -> bool:
    return rule.method.upper() == request.normalized_method() and path_prefix_matches(
        request.path, rule.path_prefix
    )


def _any_rule_matches(rules: list[RouteRule], request: CallRequest) -> bool:
    return any(rule.matches(request) for rule in rules)
