import json
from pathlib import Path

import pytest

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.policy import GatePolicy


def _write_config(tmp_path: Path, policy: dict | None = None) -> Path:
    raw = {
        "config_id": "policy_config_test",
        "response_cases": [
            {
                "case_id": "widgets_001",
                "method": "GET",
                "path": "/widgets/1",
                "status_code": 200,
                "body": {"id": "1"},
            }
        ],
        "audit_rules": [],
    }
    if policy is not None:
        raw["policy"] = policy
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(json.dumps(raw), encoding="utf-8")
    return config_path


def _policy_from_config(
    tmp_path: Path, policy: dict | None, *, allow_live: bool = False
) -> GatePolicy:
    config = load_gate_config(_write_config(tmp_path, policy))
    return GatePolicy.from_config(config.policy, allow_live=allow_live)


def test_config_deny_rule_produces_deny_decision_with_configured_reason_code(
    tmp_path: Path,
) -> None:
    policy = _policy_from_config(
        tmp_path,
        {
            "deny": [
                {
                    "method": "POST",
                    "path_prefix": "/robot/",
                    "reason_code": "robot_blocked_by_env",
                    "message": "This environment forbids robot writes.",
                }
            ],
            "shadow_write": [{"path_prefix": "/shadow/"}],
        },
    )

    decision = policy.decide(
        CallRequest(method="POST", path="/robot/move"),
        has_response_case=False,
    )

    assert decision.kind == "deny"
    assert decision.reason_code == "robot_blocked_by_env"
    assert decision.message == "This environment forbids robot writes."


def test_config_deny_rule_path_prefix_is_segment_safe(tmp_path: Path) -> None:
    policy = _policy_from_config(
        tmp_path,
        {
            "deny": [
                {
                    "method": "POST",
                    "path_prefix": "/robot",
                    "reason_code": "robot_blocked_by_env",
                    "message": "This environment forbids robot writes.",
                }
            ],
            "shadow_write": [{"path_prefix": "/robotics"}],
        },
    )

    denied = policy.decide(
        CallRequest(method="POST", path="/robot/move"),
        has_response_case=False,
    )
    permitted = policy.decide(
        CallRequest(method="POST", path="/robotics/move"),
        has_response_case=False,
    )

    assert denied.kind == "deny"
    assert denied.reason_code == "robot_blocked_by_env"
    assert permitted.kind == "shadow_write"


def test_config_shadow_write_allowlist_permits_listed_writes_and_denies_unlisted_writes(
    tmp_path: Path,
) -> None:
    policy = _policy_from_config(
        tmp_path,
        {"shadow_write": [{"method": "POST", "path_prefix": "/shadow/"}]},
    )

    permitted = policy.decide(
        CallRequest(method="POST", path="/shadow/items"),
        has_response_case=False,
    )
    denied = policy.decide(
        CallRequest(method="POST", path="/unlisted/items"),
        has_response_case=False,
    )

    assert permitted.kind == "shadow_write"
    assert denied.kind == "deny"
    assert denied.reason_code == "write_not_permitted"


def test_shadow_write_path_prefix_is_segment_safe(tmp_path: Path) -> None:
    policy = _policy_from_config(tmp_path, {"shadow_write": [{"path_prefix": "/reports"}]})

    permitted = policy.decide(
        CallRequest(method="POST", path="/reports/triage"),
        has_response_case=False,
    )
    denied = policy.decide(
        CallRequest(method="POST", path="/reports-evil/triage"),
        has_response_case=False,
    )

    assert permitted.kind == "shadow_write"
    assert denied.kind == "deny"
    assert denied.reason_code == "write_not_permitted"


def test_policy_block_without_shadow_write_denies_writes_with_agent_remediation(
    tmp_path: Path,
) -> None:
    policy = _policy_from_config(tmp_path, {})

    decision = policy.decide(
        CallRequest(method="POST", path="/anywhere"),
        has_response_case=False,
    )

    assert decision.kind == "deny"
    assert decision.reason_code == "write_not_permitted"
    assert "policy.shadow_write" in decision.message


def test_explicit_root_shadow_write_rule_allows_all_writes(tmp_path: Path) -> None:
    policy = _policy_from_config(tmp_path, {"shadow_write": [{"path_prefix": "/"}]})

    decision = policy.decide(
        CallRequest(method="DELETE", path="/anything/at/all"),
        has_response_case=False,
    )

    assert decision.kind == "shadow_write"


def test_root_shadow_write_rule_still_allows_arbitrary_writes(tmp_path: Path) -> None:
    policy = _policy_from_config(tmp_path, {"shadow_write": [{"path_prefix": "/"}]})

    decision = policy.decide(
        CallRequest(method="PATCH", path="/reports-evil/triage"),
        has_response_case=False,
    )

    assert decision.kind == "shadow_write"


def test_live_rules_require_allow_live(tmp_path: Path) -> None:
    policy_without_live = _policy_from_config(
        tmp_path,
        {"live_capture": [{"path_prefix": "/provider/"}]},
        allow_live=False,
    )
    policy_with_live = _policy_from_config(
        tmp_path,
        {"live_capture": [{"path_prefix": "/provider/"}]},
        allow_live=True,
    )

    without_live = policy_without_live.decide(
        CallRequest(method="GET", path="/provider/resource"),
        has_response_case=False,
    )
    with_live = policy_with_live.decide(
        CallRequest(method="GET", path="/provider/resource"),
        has_response_case=False,
    )

    assert without_live.kind == "miss"
    assert with_live.kind == "live_capture"


def test_live_capture_path_prefix_is_segment_safe(tmp_path: Path) -> None:
    policy = _policy_from_config(
        tmp_path,
        {"live_capture": [{"path_prefix": "/github"}]},
        allow_live=True,
    )

    allowed = policy.decide(
        CallRequest(method="GET", path="/github/repos/o/r"),
        has_response_case=False,
    )
    missed = policy.decide(
        CallRequest(method="GET", path="/githubevil/repos/o/r"),
        has_response_case=False,
    )

    assert allowed.kind == "live_capture"
    assert missed.kind == "miss"


def test_live_capture_exact_route_does_not_match_child_path(tmp_path: Path) -> None:
    policy = _policy_from_config(
        tmp_path,
        {"live_capture": [{"path_prefix": "/camera", "exact": True}]},
        allow_live=True,
    )

    allowed = policy.decide(
        CallRequest(method="GET", path="/camera"),
        has_response_case=False,
    )
    missed = policy.decide(
        CallRequest(method="GET", path="/camera/stream"),
        has_response_case=False,
    )

    assert allowed.kind == "live_capture"
    assert missed.kind == "miss"


def test_live_capture_exact_must_be_boolean(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"policy\.live_capture\[0\]\.exact"):
        load_gate_config(
            _write_config(
                tmp_path,
                {"live_capture": [{"path_prefix": "/camera", "exact": "yes"}]},
            )
        )


def test_live_capture_rules_reject_non_get_method_at_config_load(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"live_capture.*GET"):
        load_gate_config(
            _write_config(
                tmp_path,
                {"live_capture": [{"method": "POST", "path_prefix": "/provider/"}]},
            )
        )


def test_live_capture_path_prefix_root_is_rejected_at_config_load(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"policy\.live_capture\[0\].path_prefix"):
        load_gate_config(
            _write_config(
                tmp_path,
                {"live_capture": [{"path_prefix": "/"}]},
            )
        )


def test_missing_policy_block_keeps_legacy_defaults(tmp_path: Path) -> None:
    policy = _policy_from_config(tmp_path, None)

    robot = policy.decide(
        CallRequest(method="POST", path="/robot/move"),
        has_response_case=False,
    )
    generic = policy.decide(
        CallRequest(method="POST", path="/generic/write"),
        has_response_case=False,
    )

    assert robot.kind == "deny"
    assert generic.kind == "shadow_write"
