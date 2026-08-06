import asyncio
import json
from pathlib import Path

from mcp import types

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.mcp_capture import McpCaptureStore
from datalox_gated_runtime.mcp_registry import McpToolRegistry
from datalox_gated_runtime.mcp_runtime import McpGatedRuntime
from datalox_gated_runtime.promote import promote_session
from datalox_gated_runtime.verify import verify_replay


class FakeGitHubMcp:
    async def list_tools(self, upstream_name: str) -> list[types.Tool]:
        assert upstream_name == "github"
        return [
            types.Tool(
                name="get_issue",
                inputSchema={"type": "object", "properties": {"number": {"type": "integer"}}},
            ),
            types.Tool(
                name="create_triage_report",
                inputSchema={"type": "object", "properties": {"issue_number": {"type": "integer"}}},
            ),
            types.Tool(
                name="merge_pull_request",
                inputSchema={"type": "object", "properties": {"number": {"type": "integer"}}},
            ),
            types.Tool(
                name="delete_repo",
                inputSchema={"type": "object", "properties": {"repo": {"type": "string"}}},
            ),
        ]

    async def call_tool(
        self,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict,
    ) -> dict:
        assert upstream_name == "github"
        assert upstream_tool_name == "get_issue"
        return {"structuredContent": {"number": arguments["number"], "state": "open"}}


def _write_live_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True)
    (run_dir / "task.json").write_text(
        json.dumps({"task_id": "mcp_smoke", "title": "MCP smoke"}),
        encoding="utf-8",
    )
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "mcp_smoke_source",
                "response_cases": [],
                "audit_rules": [
                    {
                        "type": "require_mcp_call",
                        "tool_name": "github.get_issue",
                        "arguments_contains": {"number": 123},
                        "failure_code": "missing_issue_read",
                    },
                    {
                        "type": "require_mcp_shadow",
                        "tool_name": "github.create_triage_report",
                        "arguments_contains": {"issue_number": 123},
                        "failure_code": "missing_triage_report",
                    },
                ],
                "mcp": {
                    "upstreams": {
                        "github": {"transport": "stdio", "command": "fake-github", "args": []}
                    },
                    "tools": {
                        "github.get_issue": "live",
                        "github.create_triage_report": "shadow",
                        "github.merge_pull_request": "deny",
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


def test_mcp_gated_tools_capture_promote_verify_smoke(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    env_dir = tmp_path / "env"
    _write_live_run(run_dir)
    config = load_gate_config(run_dir / "gate_config.json")
    assert config.mcp is not None
    upstream = FakeGitHubMcp()
    ledger = SessionLedger(path=run_dir / "ledger.jsonl")
    runtime = McpGatedRuntime(
        config=config.mcp,
        ledger=ledger,
        upstream_client=upstream,
        capture_store=McpCaptureStore(run_dir / "mcp_captures.jsonl"),
        allow_live=True,
        input_schemas={
            "github.get_issue": {
                "type": "object",
                "properties": {"number": {"type": "integer"}},
            }
        },
    )
    registry = McpToolRegistry(
        run_dir=run_dir,
        config=config.mcp,
        mcp_runtime=runtime,
        upstream_client=upstream,
    )

    listed = asyncio.run(registry.list_tools())
    names = {tool.name for tool in listed}
    assert names >= {"github.get_issue", "github.create_triage_report"}
    assert "github.merge_pull_request" not in names
    assert "github.delete_repo" not in names
    live = asyncio.run(registry.call_tool("github.get_issue", {"number": 123}))
    shadow = asyncio.run(registry.call_tool("github.create_triage_report", {"issue_number": 123}))
    denied = asyncio.run(registry.call_tool("github.merge_pull_request", {"number": 7}))
    assert live.structuredContent["state"] == "open"
    assert shadow.structuredContent["mode"] == "shadow"
    assert denied.isError is True

    (run_dir / "audit.json").write_text(json.dumps({"passed": True}), encoding="utf-8")
    promote_session(run_dir=run_dir, out_dir=env_dir)
    verify = verify_replay(env_dir)

    assert verify.fidelity_passed is True
    promoted = json.loads((env_dir / "gate_config.json").read_text(encoding="utf-8"))
    assert promoted["mcp"]["tools"]["github.get_issue"] == "replay"
