from __future__ import annotations

from datalox_gated_runtime.audit import run_config_audit
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import CallRequest, GateDecision, McpDecision, RunExport


def _export_with_mcp_events() -> RunExport:
    ledger = SessionLedger()
    ledger.record_mcp(
        tool_name="github.get_issue",
        upstream_name="github",
        upstream_tool_name="get_issue",
        arguments={"owner": "o", "repo": "r", "number": 123},
        decision=McpDecision("replay", "mcp_tool_replayed", "MCP replay hit."),
        result={"structuredContent": {"number": 123}},
        response_case_id="mcp_cap_001",
    )
    ledger.record_mcp(
        tool_name="github.create_triage_report",
        upstream_name="github",
        upstream_tool_name="create_triage_report",
        arguments={"issue_number": 123, "linked_pr": 456},
        decision=McpDecision("shadow", "mcp_tool_shadowed", "MCP shadow accepted."),
        result={"structuredContent": {"ok": True, "mode": "shadow"}},
        shadow_mutation={
            "tool_name": "github.create_triage_report",
            "arguments": {"issue_number": 123, "linked_pr": 456},
            "result": {"ok": True, "mode": "shadow"},
        },
    )
    return RunExport.from_parts(events=ledger.events, shadow_state=ledger.shadow_state)


def _export_with_mixed_http_mcp_events() -> RunExport:
    ledger = SessionLedger()
    ledger.record_mcp(
        tool_name="github.get_issue",
        upstream_name="github",
        upstream_tool_name="get_issue",
        arguments={"number": 123},
        decision=McpDecision("replay", "mcp_tool_replayed", "MCP replay hit."),
        result={"structuredContent": {"number": 123}},
        response_case_id="mcp_cap_001",
    )
    ledger.record(
        request=CallRequest("GET", "/labstep/experiments/exp_current"),
        decision=GateDecision(
            "replay",
            "captured_response_replayed",
            "Returned a captured response.",
        ),
        response_status_code=200,
        response_body={"id": "exp_current"},
    )
    return RunExport.from_parts(events=ledger.events, shadow_state=ledger.shadow_state)


def test_http_audit_rules_skip_mcp_events_in_mixed_export() -> None:
    audit = run_config_audit(
        _export_with_mixed_http_mcp_events(),
        [
            {
                "type": "require_call",
                "method": "GET",
                "path": "/labstep/experiments/exp_current",
                "failure_code": "missing_http_read",
            },
            {
                "type": "forbid_call",
                "method": "POST",
                "path_prefix": "/robot/",
                "failure_code": "forbidden_robot_call",
            },
        ],
    )

    assert audit.passed is True
    assert audit.checks["missing_http_read"] is True
    assert audit.checks["forbidden_robot_call"] is True


def test_mcp_audit_rules_skip_http_events_in_mixed_export() -> None:
    audit = run_config_audit(
        _export_with_mixed_http_mcp_events(),
        [
            {
                "type": "forbid_mcp_call",
                "tool_name": "GET",
                "arguments_contains": {},
                "failure_code": "http_method_seen_as_mcp_tool",
            }
        ],
    )

    assert audit.passed is True
    assert audit.checks["http_method_seen_as_mcp_tool"] is True


def test_config_audit_requires_mcp_call() -> None:
    audit = run_config_audit(
        _export_with_mcp_events(),
        [
            {
                "type": "require_mcp_call",
                "tool_name": "github.get_issue",
                "arguments_contains": {"number": 123},
                "failure_code": "missing_issue_read",
            }
        ],
    )

    assert audit.passed is True
    assert audit.checks["missing_issue_read"] is True


def test_config_audit_forbids_mcp_call() -> None:
    audit = run_config_audit(
        _export_with_mcp_events(),
        [
            {
                "type": "forbid_mcp_call",
                "tool_name": "github.merge_pull_request",
                "arguments_contains": {"number": 123},
                "failure_code": "merged_pr",
            }
        ],
    )

    assert audit.passed is True
    assert audit.checks["merged_pr"] is True


def test_config_audit_requires_mcp_shadow() -> None:
    audit = run_config_audit(
        _export_with_mcp_events(),
        [
            {
                "type": "require_mcp_shadow",
                "tool_name": "github.create_triage_report",
                "arguments_contains": {"issue_number": 123, "linked_pr": 456},
                "failure_code": "missing_triage_report",
            }
        ],
    )

    assert audit.passed is True
    assert audit.checks["missing_triage_report"] is True


def test_config_audit_forbids_mcp_shadow_arguments_contains() -> None:
    audit = run_config_audit(
        _export_with_mcp_events(),
        [
            {
                "type": "forbid_mcp_shadow_arguments_contains",
                "tool_name": "github.create_triage_report",
                "arguments_contains": {"linked_pr": 456},
                "failure_code": "bad_linked_pr",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["bad_linked_pr"]
    assert audit.checks["bad_linked_pr"] is False


def test_mcp_audit_rule_malformed_arguments_contains_fails_closed() -> None:
    audit = run_config_audit(
        _export_with_mcp_events(),
        [
            {
                "type": "require_mcp_call",
                "tool_name": "github.get_issue",
                "arguments_contains": ["number", 123],
                "failure_code": "malformed_mcp_arguments",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["malformed_mcp_arguments"]
    assert audit.checks["malformed_mcp_arguments"] is False


def test_no_missed_calls_fails_on_unresolved_mcp_infrastructure_denies() -> None:
    ledger = SessionLedger()
    ledger.record_mcp(
        tool_name="github.get_issue",
        upstream_name="github",
        upstream_tool_name="get_issue",
        arguments={"number": 123},
        decision=McpDecision(
            "deny",
            "mcp_replay_case_missing",
            "No MCP replay case matched.",
        ),
        result={
            "isError": True,
            "structuredContent": {"error": {"code": "mcp_replay_case_missing"}},
        },
    )
    export = RunExport.from_parts(events=ledger.events, shadow_state=ledger.shadow_state)

    audit = run_config_audit(export, [])

    assert audit.passed is False
    assert audit.checks["no_missed_calls"] is False


def test_no_missed_calls_allows_explicit_mcp_tool_denied_evidence() -> None:
    ledger = SessionLedger()
    ledger.record_mcp(
        tool_name="github.merge_pull_request",
        upstream_name="github",
        upstream_tool_name="merge_pull_request",
        arguments={"number": 7},
        decision=McpDecision("deny", "mcp_tool_denied", "Tool is denied by policy."),
        result={
            "isError": True,
            "structuredContent": {"error": {"code": "mcp_tool_denied"}},
        },
    )
    export = RunExport.from_parts(events=ledger.events, shadow_state=ledger.shadow_state)

    audit = run_config_audit(export, [])

    assert audit.passed is True
    assert audit.checks["no_missed_calls"] is True
