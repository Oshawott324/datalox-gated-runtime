import asyncio
import json
from pathlib import Path
from typing import Any

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.mcp_capture import McpCaptureStore
from datalox_gated_runtime.mcp_runtime import McpGatedRuntime
from datalox_gated_runtime.models import McpToolCall


class FakeUpstream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(
        self,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        self.calls.append((f"{upstream_name}.{upstream_tool_name}", dict(arguments)))
        return {"structuredContent": {"number": arguments["number"], "state": "open"}}


class RaisingUpstream:
    async def call_tool(
        self,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        raise RuntimeError("upstream process exited")


def _write_config(path: Path, mcp: dict[str, object]) -> None:
    path.write_text(
        json.dumps(
            {"config_id": "mcp_runtime", "response_cases": [], "audit_rules": [], "mcp": mcp},
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_shadow_tool_records_mcp_shadow_mutation(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {"github": {"transport": "stdio", "command": "fake-github", "args": []}},
            "tools": {"github.create_triage_report": "shadow"},
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    ledger = SessionLedger(path=tmp_path / "ledger.jsonl")
    runtime = McpGatedRuntime(config=config.mcp, ledger=ledger)

    response = asyncio.run(
        runtime.handle(McpToolCall("github.create_triage_report", {"issue_number": 123}))
    )

    assert response.decision.kind == "shadow"
    assert response.result["structuredContent"]["mode"] == "shadow"
    assert response.result["structuredContent"]["reason_code"] == "mcp_tool_shadowed"
    assert ledger.shadow_state["mcp_tool_calls"][0]["tool_name"] == "github.create_triage_report"
    event = json.loads((tmp_path / "ledger.jsonl").read_text(encoding="utf-8"))
    assert event["result"] == response.result
    assert event["result"]["structuredContent"]["event_id"] == response.event_id


def test_unknown_tool_records_structured_deny(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {"github": {"transport": "stdio", "command": "fake-github", "args": []}},
            "tools": {"github.get_issue": "replay"},
            "generated": {
                "tool_schemas": {"github.get_issue": {"inputSchema": {"type": "object"}}}
            },
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    runtime = McpGatedRuntime(config=config.mcp, ledger=SessionLedger())

    response = asyncio.run(runtime.handle(McpToolCall("github.delete_repo", {"repo": "demo"})))

    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "mcp_tool_not_exposed"
    assert response.result["isError"] is True
    assert response.result["structuredContent"]["error"]["tool_name"] == "github.delete_repo"


def test_live_tool_without_allow_live_denies_without_calling_upstream(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {"github": {"transport": "stdio", "command": "fake-github", "args": []}},
            "tools": {"github.get_issue": "live"},
            "live": {
                "github.get_issue": {
                    "contract": "safe_read",
                    "evidence_ref": "evidence/mcp/github.md#get_issue",
                }
            },
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    upstream = FakeUpstream()
    runtime = McpGatedRuntime(config=config.mcp, ledger=SessionLedger(), upstream_client=upstream)

    response = asyncio.run(runtime.handle(McpToolCall("github.get_issue", {"number": 123})))

    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "mcp_live_disabled"
    assert upstream.calls == []


def test_live_tool_records_structured_deny_when_upstream_call_raises(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {"github": {"transport": "stdio", "command": "fake-github", "args": []}},
            "tools": {"github.get_issue": "live"},
            "live": {
                "github.get_issue": {
                    "contract": "safe_read",
                    "evidence_ref": "evidence/mcp/github.md#get_issue",
                }
            },
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    capture_path = tmp_path / "mcp_captures.jsonl"
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = McpGatedRuntime(
        config=config.mcp,
        ledger=SessionLedger(path=ledger_path),
        upstream_client=RaisingUpstream(),
        capture_store=McpCaptureStore(capture_path),
        allow_live=True,
    )

    response = asyncio.run(runtime.handle(McpToolCall("github.get_issue", {"number": 123})))

    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "mcp_upstream_unavailable"
    assert response.result["isError"] is True
    assert response.result["structuredContent"]["error"]["code"] == "mcp_upstream_unavailable"
    assert not capture_path.exists()
    event = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert event["surface"] == "mcp"
    assert event["decision"]["kind"] == "deny"
    assert event["decision"]["reason_code"] == "mcp_upstream_unavailable"
    assert event["result"]["isError"] is True


def test_live_tool_with_allow_live_captures_result(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {"github": {"transport": "stdio", "command": "fake-github", "args": []}},
            "tools": {"github.get_issue": "live"},
            "live": {
                "github.get_issue": {
                    "contract": "safe_read",
                    "evidence_ref": "evidence/mcp/github.md#get_issue",
                }
            },
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    upstream = FakeUpstream()
    capture_path = tmp_path / "mcp_captures.jsonl"
    runtime = McpGatedRuntime(
        config=config.mcp,
        ledger=SessionLedger(path=tmp_path / "ledger.jsonl"),
        upstream_client=upstream,
        capture_store=McpCaptureStore(capture_path),
        allow_live=True,
        input_schemas={
            "github.get_issue": {"type": "object", "properties": {"number": {"type": "integer"}}}
        },
    )

    response = asyncio.run(runtime.handle(McpToolCall("github.get_issue", {"number": 123})))

    assert response.decision.kind == "live"
    assert response.result["structuredContent"]["state"] == "open"
    assert response.response_case_id is not None
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    assert capture["tool_name"] == "github.get_issue"
    assert capture["evidence_ref"] == "evidence/mcp/github.md#get_issue"
    assert upstream.calls == [("github.get_issue", {"number": 123})]


def test_live_tool_without_declared_upstream_denies_without_calling_upstream(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {},
            "tools": {"github.get_issue": "live"},
            "live": {
                "github.get_issue": {
                    "contract": "safe_read",
                    "evidence_ref": "evidence/mcp/github.md#get_issue",
                }
            },
            "generated": {
                "tool_schemas": {"github.get_issue": {"inputSchema": {"type": "object"}}}
            },
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    upstream = FakeUpstream()
    runtime = McpGatedRuntime(
        config=config.mcp,
        ledger=SessionLedger(),
        upstream_client=upstream,
        allow_live=True,
    )

    response = asyncio.run(runtime.handle(McpToolCall("github.get_issue", {"number": 123})))

    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "mcp_upstream_unavailable"
    assert upstream.calls == []


def test_live_tool_without_upstream_client_records_unavailable(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {"github": {"transport": "stdio", "command": "fake-github", "args": []}},
            "tools": {"github.get_issue": "live"},
            "live": {
                "github.get_issue": {
                    "contract": "safe_read",
                    "evidence_ref": "evidence/mcp/github.md#get_issue",
                }
            },
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    runtime = McpGatedRuntime(config=config.mcp, ledger=SessionLedger(), allow_live=True)

    response = asyncio.run(runtime.handle(McpToolCall("github.get_issue", {"number": 123})))

    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "mcp_upstream_unavailable"
    assert response.result["isError"] is True


def test_replay_tool_requires_exact_case(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {},
            "tools": {"github.get_issue": "replay"},
            "generated": {
                "tool_schemas": {"github.get_issue": {"inputSchema": {"type": "object"}}},
                "response_cases": [
                    {
                        "case_id": "mcp_cap_001",
                        "tool_name": "github.get_issue",
                        "arguments": {"number": 123},
                        "result": {"structuredContent": {"number": 123}},
                    }
                ],
            },
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    runtime = McpGatedRuntime(config=config.mcp, ledger=SessionLedger())

    hit = asyncio.run(runtime.handle(McpToolCall("github.get_issue", {"number": 123})))
    miss = asyncio.run(runtime.handle(McpToolCall("github.get_issue", {"number": 124})))

    assert hit.decision.kind == "replay"
    assert hit.response_case_id == "mcp_cap_001"
    assert miss.decision.kind == "deny"
    assert miss.decision.reason_code == "mcp_replay_case_missing"


def test_declared_deny_tool_records_deny_if_direct_call_reaches_runtime(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    _write_config(
        config_path,
        {
            "upstreams": {"github": {"transport": "stdio", "command": "fake-github", "args": []}},
            "tools": {"github.merge_pull_request": "deny"},
        },
    )
    config = load_gate_config(config_path)
    assert config.mcp is not None
    ledger = SessionLedger(path=tmp_path / "ledger.jsonl")
    runtime = McpGatedRuntime(config=config.mcp, ledger=ledger)

    response = asyncio.run(runtime.handle(McpToolCall("github.merge_pull_request", {"number": 7})))

    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "mcp_tool_denied"
    event = json.loads((tmp_path / "ledger.jsonl").read_text(encoding="utf-8"))
    assert event["surface"] == "mcp"
    assert event["tool_name"] == "github.merge_pull_request"
