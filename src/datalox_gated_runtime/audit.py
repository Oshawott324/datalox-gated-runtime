from __future__ import annotations

from typing import Any

from dataclasses import dataclass

from datalox_gated_runtime.models import LedgerEvent, McpLedgerEvent, RunExport

_MCP_MISSED_REASON_CODES = frozenset(
    {
        "mcp_replay_case_missing",
        "mcp_live_disabled",
        "mcp_upstream_unavailable",
        "mcp_tool_not_exposed",
    }
)
_MCP_AUDIT_RULE_TYPES = frozenset(
    {
        "require_mcp_call",
        "forbid_mcp_call",
        "require_mcp_shadow",
        "forbid_mcp_shadow_arguments_contains",
    }
)


@dataclass(frozen=True)
class AuditResult:
    passed: bool
    verifier_type: str
    checks: dict[str, bool]
    failure_codes: list[str]


def run_basic_audit(run_export: RunExport) -> AuditResult:
    checks = {
        "no_missed_calls": _no_missed_calls_passed(run_export),
        "live_actions_denied": all(
            event.response_status_code == 403
            for event in _http_events(run_export)
            if event.decision.reason_code
            in {"live_action_not_allowed", "live_run_action_not_allowed"}
        ),
        "has_agent_activity": bool(run_export.events),
    }
    failure_codes = [name for name, passed in checks.items() if not passed]
    return AuditResult(
        passed=not failure_codes,
        verifier_type="basic_post_run_audit",
        checks=checks,
        failure_codes=failure_codes,
    )


def run_config_audit(run_export: RunExport, audit_rules: list[dict[str, Any]]) -> AuditResult:
    checks: dict[str, bool] = {"no_missed_calls": _no_missed_calls_passed(run_export)}
    for index, rule in enumerate(audit_rules):
        if not isinstance(rule, dict):
            failure_code = f"invalid_audit_rule_{index}"
            checks[failure_code] = False
            continue

        failure_code = _rule_failure_code(rule, index)
        if failure_code is None:
            checks[f"invalid_audit_rule_{index}"] = False
            continue

        rule_type = rule.get("type")
        body_contains = rule.get("body_contains", {})
        arguments_contains = rule.get("arguments_contains", {})
        if rule_type in {
            "require_shadow_write",
            "forbid_shadow_write_body_contains",
        } and not isinstance(body_contains, dict):
            checks[failure_code] = False
            continue
        if rule_type in _MCP_AUDIT_RULE_TYPES and (
            not _non_empty_str(rule.get("tool_name")) or not isinstance(arguments_contains, dict)
        ):
            checks[failure_code] = False
            continue

        if rule_type == "require_call":
            checks[failure_code] = _has_call(
                run_export,
                method=rule.get("method", ""),
                path=rule.get("path", ""),
            )
        elif rule_type == "require_shadow_write":
            checks[failure_code] = _has_shadow_write(
                run_export,
                path=rule.get("path", ""),
                expected_body=body_contains,
            )
        elif rule_type == "forbid_shadow_write_body_contains":
            checks[failure_code] = not _has_shadow_write(
                run_export,
                path=rule.get("path", ""),
                expected_body=body_contains,
            )
        elif rule_type == "forbid_call":
            if not _valid_forbid_call_rule(rule):
                checks[failure_code] = False
                continue
            checks[failure_code] = not _has_call(
                run_export,
                method=rule["method"],
                path=rule.get("path", ""),
                path_prefix=rule.get("path_prefix", ""),
            )
        elif rule_type == "require_mcp_call":
            checks[failure_code] = _has_mcp_call(
                run_export,
                tool_name=rule["tool_name"],
                expected_arguments=arguments_contains,
            )
        elif rule_type == "forbid_mcp_call":
            checks[failure_code] = not _has_mcp_call(
                run_export,
                tool_name=rule["tool_name"],
                expected_arguments=arguments_contains,
            )
        elif rule_type == "require_mcp_shadow":
            checks[failure_code] = _has_mcp_shadow_call(
                run_export,
                tool_name=rule["tool_name"],
                expected_arguments=arguments_contains,
            )
        elif rule_type == "forbid_mcp_shadow_arguments_contains":
            checks[failure_code] = not _has_mcp_shadow_call(
                run_export,
                tool_name=rule["tool_name"],
                expected_arguments=arguments_contains,
            )
        else:
            checks[failure_code] = False

    failure_codes = [name for name, passed in checks.items() if not passed]
    return AuditResult(
        passed=not failure_codes,
        verifier_type="config_post_run_audit",
        checks=checks,
        failure_codes=failure_codes,
    )


def _rule_failure_code(rule: dict[str, Any], index: int) -> str | None:
    failure_code = rule.get("failure_code")
    if isinstance(failure_code, str) and failure_code.strip():
        return failure_code
    return None


def _valid_forbid_call_rule(rule: dict[str, Any]) -> bool:
    if not _non_empty_str(rule.get("method")):
        return False
    has_path = "path" in rule
    has_path_prefix = "path_prefix" in rule
    if has_path == has_path_prefix:
        return False
    if has_path and not _non_empty_str(rule["path"]):
        return False
    if has_path_prefix and not _non_empty_str(rule["path_prefix"]):
        return False
    return True


def _non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _http_events(run_export: RunExport) -> list[LedgerEvent]:
    return [event for event in run_export.events if isinstance(event, LedgerEvent)]


def _mcp_events(run_export: RunExport) -> list[McpLedgerEvent]:
    return [event for event in run_export.events if isinstance(event, McpLedgerEvent)]


def _no_missed_calls_passed(run_export: RunExport) -> bool:
    for event in _http_events(run_export):
        if event.decision.kind == "miss":
            return False
    for event in _mcp_events(run_export):
        if event.decision.kind == "deny" and event.decision.reason_code in _MCP_MISSED_REASON_CODES:
            return False
    return True


def _has_call(run_export: RunExport, *, method: str, path: str, path_prefix: str = "") -> bool:
    if not method:
        return False
    if not path and not path_prefix:
        return False
    for event in _http_events(run_export):
        if event.request.normalized_method() != method.upper():
            continue
        if path and event.request.path == path:
            return True
        if path_prefix and event.request.path.startswith(path_prefix):
            return True
    return False


def _has_mcp_call(
    run_export: RunExport,
    *,
    tool_name: str,
    expected_arguments: dict[str, Any],
) -> bool:
    for event in _mcp_events(run_export):
        if event.tool_name != tool_name:
            continue
        if _dict_contains(event.arguments, expected_arguments):
            return True
    return False


def _has_mcp_shadow_call(
    run_export: RunExport,
    *,
    tool_name: str,
    expected_arguments: dict[str, Any],
) -> bool:
    if not isinstance(run_export.shadow_state, dict):
        return False
    tool_calls = run_export.shadow_state.get("mcp_tool_calls")
    if not isinstance(tool_calls, list):
        return False
    for tool_call in tool_calls:
        if not isinstance(tool_call, dict):
            continue
        if tool_call.get("tool_name") != tool_name:
            continue
        arguments = tool_call.get("arguments")
        if isinstance(arguments, dict) and _dict_contains(arguments, expected_arguments):
            return True
    return False


def _has_shadow_write(
    run_export: RunExport,
    *,
    path: str,
    expected_body: dict[str, Any],
) -> bool:
    if not path:
        return False
    if not isinstance(run_export.shadow_state, dict):
        return False
    writes = run_export.shadow_state.get("writes")
    if not isinstance(writes, list):
        return False
    for write in writes:
        if not isinstance(write, dict):
            continue
        if write.get("path") != path:
            continue
        body = write.get("body")
        if isinstance(body, dict) and _dict_contains(body, expected_body):
            return True
    return False


def _dict_contains(body: dict[str, Any], expected: dict[str, Any]) -> bool:
    for key, value in expected.items():
        if key not in body:
            return False
        if body[key] != value:
            return False
    return True
