import json
from pathlib import Path

import pytest

from datalox_gated_runtime.audit import AuditResult
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.mcp_capture import McpCaptureStore
from datalox_gated_runtime.models import McpDecision, McpResponseCase
from datalox_gated_runtime.promote import promote_session
from datalox_gated_runtime.verify import verify_replay


def _build_mcp_capture_run(
    run_dir: Path,
    *,
    write_schema_snapshot: bool = True,
) -> None:
    run_dir.mkdir(parents=True)
    (run_dir / "task.json").write_text(
        json.dumps({"task_id": "mcp_capture", "title": "MCP capture"}),
        encoding="utf-8",
    )
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "mcp_capture_source",
                "response_cases": [],
                "audit_rules": [],
                "mcp": {
                    "upstreams": {
                        "github": {
                            "transport": "stdio",
                            "command": "fake-github",
                            "args": [],
                        }
                    },
                    "tools": {
                        "github.get_issue": "live",
                        "github.create_triage_report": "shadow",
                        "github.merge_pull_request": "deny",
                    },
                    "generated": {
                        "tool_schemas": {
                            "github.get_issue": {
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"number": {"type": "integer"}},
                                }
                            }
                        },
                        "response_cases": [],
                    },
                    "live": {
                        "github.get_issue": {
                            "contract": "safe_read",
                            "evidence_ref": "evidence/mcp/github.md#get_issue",
                        }
                    },
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    if write_schema_snapshot:
        (run_dir / "mcp_tool_schemas.json").write_text(
            json.dumps(
                {
                    "github.get_issue": {
                        "description": "Read one GitHub issue.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "owner": {"type": "string"},
                                "repo": {"type": "string"},
                                "number": {"type": "integer"},
                            },
                            "required": ["owner", "repo", "number"],
                        },
                    },
                    "github.create_triage_report": {
                        "description": "Create a local triage report.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "issue_number": {"type": "integer"},
                                "summary": {"type": "string"},
                            },
                            "required": ["issue_number"],
                        },
                    },
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    case = McpResponseCase(
        case_id="mcp_cap_001",
        tool_name="github.get_issue",
        arguments={"owner": "o", "repo": "r", "number": 123},
        result={"structuredContent": {"number": 123, "state": "open"}},
        evidence_ref="mcp-live:github:2026-07-06T00:00:00Z",
        input_schema={"type": "object", "properties": {"number": {"type": "integer"}}},
    )
    McpCaptureStore(run_dir / "mcp_captures.jsonl").append(case)
    ledger = SessionLedger(path=run_dir / "ledger.jsonl")
    ledger.record_mcp(
        tool_name="github.get_issue",
        upstream_name="github",
        upstream_tool_name="get_issue",
        arguments={"owner": "o", "repo": "r", "number": 123},
        decision=McpDecision("live", "mcp_tool_live", "Live MCP tool call captured."),
        result={"structuredContent": {"number": 123, "state": "open"}},
        response_case_id="mcp_cap_001",
    )
    ledger.record_mcp(
        tool_name="github.create_triage_report",
        upstream_name="github",
        upstream_tool_name="create_triage_report",
        arguments={"issue_number": 123},
        decision=McpDecision("shadow", "mcp_tool_shadowed", "MCP tool call shadowed."),
        result={"structuredContent": {"ok": True, "mode": "shadow"}},
        shadow_mutation={
            "tool_name": "github.create_triage_report",
            "arguments": {"issue_number": 123},
            "result": {"ok": True, "mode": "shadow"},
        },
    )
    (run_dir / "audit.json").write_text(json.dumps({"passed": True}), encoding="utf-8")


def test_promote_emits_mcp_generated_replay_environment(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_mcp_capture_run(run_dir)

    summary = promote_session(run_dir=run_dir, out_dir=out_dir)

    payload = json.loads((out_dir / "gate_config.json").read_text(encoding="utf-8"))
    assert payload["mcp"]["tools"]["github.get_issue"] == "replay"
    assert payload["mcp"]["tools"]["github.create_triage_report"] == "shadow"
    assert payload["mcp"]["tools"]["github.merge_pull_request"] == "deny"
    assert "live" not in payload["mcp"]
    assert payload["mcp"]["upstreams"] == {}
    get_issue_schema = payload["mcp"]["generated"]["tool_schemas"]["github.get_issue"][
        "inputSchema"
    ]
    assert get_issue_schema["type"] == "object"
    assert set(get_issue_schema["properties"]) == {"owner", "repo", "number"}
    assert get_issue_schema["required"] == ["owner", "repo", "number"]
    assert (
        payload["mcp"]["generated"]["tool_schemas"]["github.get_issue"]["description"]
        == "Read one GitHub issue."
    )
    assert (
        payload["mcp"]["generated"]["tool_schemas"]["github.create_triage_report"]["inputSchema"][
            "properties"
        ]["issue_number"]["type"]
        == "integer"
    )
    assert "github.merge_pull_request" not in payload["mcp"]["generated"]["tool_schemas"]
    assert payload["mcp"]["generated"]["response_cases"][0]["case_id"] == "mcp_cap_001"
    replay_script = json.loads((out_dir / "replay_script.json").read_text(encoding="utf-8"))
    assert replay_script[0] == {
        "surface": "mcp",
        "tool_name": "github.get_issue",
        "arguments": {"owner": "o", "repo": "r", "number": 123},
    }
    assert summary["mcp_response_case_count"] == 1
    load_gate_config(out_dir / "gate_config.json")


def test_verify_replay_handles_promoted_mcp_without_upstream(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_mcp_capture_run(run_dir)
    promote_session(run_dir=run_dir, out_dir=out_dir)

    result = verify_replay(out_dir)

    assert result.fidelity_passed is True
    assert result.miss_paths == []


def test_verify_replay_audits_mcp_replay_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_mcp_capture_run(run_dir)
    promote_session(run_dir=run_dir, out_dir=out_dir)
    seen: dict[str, object] = {}

    def fake_run_config_audit(run_export, audit_rules):
        seen["surfaces"] = [getattr(event, "surface", "http") for event in run_export.events]
        return AuditResult(
            passed=True,
            verifier_type="config_post_run_audit",
            checks={"no_missed_calls": True},
            failure_codes=[],
        )

    monkeypatch.setattr("datalox_gated_runtime.verify.run_config_audit", fake_run_config_audit)

    result = verify_replay(out_dir)

    assert result.fidelity_passed is True
    assert "mcp" in seen["surfaces"]


def test_verify_replay_fails_on_mcp_replay_case_missing(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_mcp_capture_run(run_dir)
    promote_session(run_dir=run_dir, out_dir=out_dir)
    payload = json.loads((out_dir / "gate_config.json").read_text(encoding="utf-8"))
    payload["mcp"]["generated"]["response_cases"] = []
    (out_dir / "gate_config.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    result = verify_replay(out_dir)

    assert result.fidelity_passed is False
    assert result.miss_paths == ['MCP github.get_issue {"number":123,"owner":"o","repo":"r"}']


def test_verify_replay_fails_on_mcp_replay_tool_not_exposed(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_mcp_capture_run(run_dir)
    promote_session(run_dir=run_dir, out_dir=out_dir)
    payload = json.loads((out_dir / "gate_config.json").read_text(encoding="utf-8"))
    del payload["mcp"]["tools"]["github.get_issue"]
    (out_dir / "gate_config.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    result = verify_replay(out_dir)

    assert result.fidelity_passed is False
    assert result.miss_paths == ['MCP github.get_issue {"number":123,"owner":"o","repo":"r"}']


def test_promote_dedupes_mcp_captures_with_last_case_winning(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_mcp_capture_run(run_dir)
    McpCaptureStore(run_dir / "mcp_captures.jsonl").append(
        McpResponseCase(
            case_id="mcp_cap_002",
            tool_name="github.get_issue",
            arguments={"number": 123, "repo": "r", "owner": "o"},
            result={"structuredContent": {"number": 123, "state": "updated"}},
            evidence_ref="mcp-live:github:later",
            input_schema={"type": "object", "properties": {"number": {"type": "integer"}}},
        )
    )

    promote_session(run_dir=run_dir, out_dir=out_dir)

    payload = json.loads((out_dir / "gate_config.json").read_text(encoding="utf-8"))
    cases = payload["mcp"]["generated"]["response_cases"]
    assert len(cases) == 1
    assert cases[0]["case_id"] == "mcp_cap_002"
    assert cases[0]["result"]["structuredContent"]["state"] == "updated"


def test_promote_preserves_uncaptured_live_tool_and_needed_upstream(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_mcp_capture_run(run_dir)
    payload = json.loads((run_dir / "gate_config.json").read_text(encoding="utf-8"))
    payload["mcp"]["tools"]["github.list_labels"] = "live"
    payload["mcp"]["live"]["github.list_labels"] = {
        "contract": "safe_read",
        "evidence_ref": "evidence/mcp/github.md#list_labels",
    }
    (run_dir / "gate_config.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    promote_session(run_dir=run_dir, out_dir=out_dir)

    promoted = json.loads((out_dir / "gate_config.json").read_text(encoding="utf-8"))
    assert promoted["mcp"]["tools"]["github.get_issue"] == "replay"
    assert promoted["mcp"]["tools"]["github.list_labels"] == "live"
    assert set(promoted["mcp"]["upstreams"]) == {"github"}
    assert set(promoted["mcp"]["live"]) == {"github.list_labels"}


def test_promote_rejects_exposed_mcp_tool_without_promoted_schema(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _build_mcp_capture_run(run_dir, write_schema_snapshot=False)

    with pytest.raises(
        ValueError,
        match="mcp promoted tool schema unavailable: github.create_triage_report",
    ):
        promote_session(run_dir=run_dir, out_dir=tmp_path / "env")
