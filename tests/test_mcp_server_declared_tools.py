import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from mcp import types
from world_v1_helpers import create_valid_bundle

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.mcp_registry import McpToolRegistry
from datalox_gated_runtime.mcp_runtime import McpGatedRuntime
from datalox_gated_runtime.mcp_server import _build_low_level_components, build_low_level_server
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.world_v1.backend import (
    WorldBundleBackend,
    initialize_world_bundle_session,
)


class FakeSchemaUpstream:
    async def list_tools(self, upstream_name: str) -> list[types.Tool]:
        assert upstream_name == "github"
        return [
            types.Tool(
                name="get_issue",
                description="Read one GitHub issue.",
                inputSchema={"type": "object", "properties": {"number": {"type": "integer"}}},
            ),
            types.Tool(
                name="create_triage_report",
                description="Create a local triage report.",
                inputSchema={
                    "type": "object",
                    "properties": {"issue_number": {"type": "integer"}},
                },
            ),
            types.Tool(
                name="delete_repo",
                description="Delete a repository.",
                inputSchema={"type": "object", "properties": {"repo": {"type": "string"}}},
            ),
        ]

    async def call_tool(
        self,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "structuredContent": {
                "tool": f"{upstream_name}.{upstream_tool_name}",
                "arguments": arguments,
            }
        }


def _body_digest(body: object) -> str:
    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _parsed_text(result: types.CallToolResult) -> dict[str, Any]:
    assert len(result.content) == 1
    assert isinstance(result.content[0], types.TextContent)
    return json.loads(result.content[0].text)


def _write_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True)
    (run_dir / "task.json").write_text(
        json.dumps({"task_id": "t", "title": "T"}),
        encoding="utf-8",
    )
    (run_dir / "session_manifest.json").write_text(
        json.dumps({"session_id": "s"}),
        encoding="utf-8",
    )
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "mcp_tools",
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
                    "live": {
                        "github.get_issue": {
                            "contract": "safe_read",
                            "evidence_ref": "evidence/mcp/github.md#get_issue",
                        }
                    },
                    "generated": {
                        "tool_schemas": {
                            "github.get_issue": {
                                "description": "Read one GitHub issue.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"number": {"type": "integer"}},
                                },
                            },
                            "github.create_triage_report": {
                                "description": "Create a local triage report.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"issue_number": {"type": "integer"}},
                                },
                            },
                        }
                    },
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_registry_lists_only_declared_non_denied_tools(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)
    config = load_gate_config(run_dir / "gate_config.json")
    assert config.mcp is not None
    runtime = McpGatedRuntime(
        config=config.mcp,
        ledger=SessionLedger(),
    )
    registry = McpToolRegistry(
        run_dir=run_dir,
        config=config.mcp,
        mcp_runtime=runtime,
        upstream_client=FakeSchemaUpstream(),
    )

    tools = asyncio.run(registry.list_tools())

    names = {tool.name for tool in tools}
    assert "github.get_issue" in names
    assert "github.create_triage_report" in names
    assert "github.merge_pull_request" not in names
    assert "github.delete_repo" not in names
    get_issue = next(tool for tool in tools if tool.name == "github.get_issue")
    assert get_issue.inputSchema["type"] == "object"
    assert get_issue.description == "Read one GitHub issue."
    snapshot = json.loads((run_dir / "mcp_tool_schemas.json").read_text(encoding="utf-8"))
    assert snapshot["github.get_issue"]["inputSchema"]["type"] == "object"
    assert snapshot["github.get_issue"]["description"] == "Read one GitHub issue."
    assert (
        snapshot["github.create_triage_report"]["inputSchema"]["properties"]["issue_number"]["type"]
        == "integer"
    )
    assert "github.merge_pull_request" not in snapshot


def test_registry_direct_denied_call_fails_closed_when_dispatched(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)
    config = load_gate_config(run_dir / "gate_config.json")
    assert config.mcp is not None
    ledger = SessionLedger(path=run_dir / "ledger.jsonl")
    runtime = McpGatedRuntime(
        config=config.mcp,
        ledger=ledger,
    )
    registry = McpToolRegistry(
        run_dir=run_dir,
        config=config.mcp,
        mcp_runtime=runtime,
        upstream_client=FakeSchemaUpstream(),
    )

    result = asyncio.run(registry.call_tool("github.merge_pull_request", {"number": 7}))

    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "mcp_tool_denied"
    event = json.loads((run_dir / "ledger.jsonl").read_text(encoding="utf-8"))
    assert event["decision"]["reason_code"] == "mcp_tool_denied"


def test_registry_utility_tools_preserved(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)
    config = load_gate_config(run_dir / "gate_config.json")
    assert config.mcp is not None
    runtime = McpGatedRuntime(
        config=config.mcp,
        ledger=SessionLedger(),
    )
    registry = McpToolRegistry(
        run_dir=run_dir,
        config=config.mcp,
        mcp_runtime=runtime,
        upstream_client=FakeSchemaUpstream(),
    )

    tools = asyncio.run(registry.list_tools())

    names = {tool.name for tool in tools}
    assert {"get_task", "get_session_manifest", "gate_request"} <= names
    utility_descriptions = {
        tool.name: tool.description
        for tool in tools
        if tool.name in {"get_task", "get_session_manifest", "gate_request"}
    }
    assert all(description and description.strip() for description in utility_descriptions.values())


def _write_replay_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True)
    (run_dir / "task.json").write_text(
        json.dumps({"task_id": "t", "title": "T"}),
        encoding="utf-8",
    )
    (run_dir / "session_manifest.json").write_text(
        json.dumps({"session_id": "s"}),
        encoding="utf-8",
    )
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "mcp_replay_tools",
                "response_cases": [
                    {
                        "case_id": "http_health_001",
                        "method": "GET",
                        "path": "/health",
                        "status_code": 200,
                        "body": {"status": "ok"},
                    }
                ],
                "audit_rules": [],
                "policy": {
                    "deny": [
                        {
                            "method": "POST",
                            "path_prefix": "/danger",
                            "reason_code": "test_denied",
                            "message": "Denied in test.",
                        }
                    ]
                },
                "mcp": {
                    "upstreams": {},
                    "tools": {
                        "github.get_issue": "replay",
                        "github.create_triage_report": "shadow",
                        "github.merge_pull_request": "deny",
                    },
                    "generated": {
                        "tool_schemas": {
                            "github.get_issue": {
                                "description": "Read one replayed GitHub issue.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"number": {"type": "integer"}},
                                },
                            },
                            "github.create_triage_report": {
                                "description": "Create a shadowed triage report.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"issue_number": {"type": "integer"}},
                                },
                            },
                        },
                        "response_cases": [
                            {
                                "case_id": "mcp_cap_001",
                                "tool_name": "github.get_issue",
                                "arguments": {"number": 123},
                                "result": {"structuredContent": {"number": 123, "state": "open"}},
                            }
                        ],
                    },
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_http_live_mcp_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True)
    (run_dir / "task.json").write_text(
        json.dumps({"task_id": "t", "title": "T"}),
        encoding="utf-8",
    )
    (run_dir / "session_manifest.json").write_text(
        json.dumps({"session_id": "s"}),
        encoding="utf-8",
    )
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "mcp_http_live",
                "response_cases": [],
                "audit_rules": [],
                "policy": {"live_capture": [{"path_prefix": "/github/"}]},
                "live": {"upstreams": {"github": {"base_url": "https://api.github.test"}}},
                "mcp": {
                    "upstreams": {},
                    "tools": {"github.create_triage_report": "shadow"},
                    "generated": {
                        "tool_schemas": {
                            "github.create_triage_report": {
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"issue_number": {"type": "integer"}},
                                }
                            }
                        }
                    },
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_world_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True)
    source_bundle = create_valid_bundle(run_dir / "source-bundle")
    initialize_world_bundle_session(
        source_bundle_dir=source_bundle,
        run_dir=run_dir,
        episode_id="episode-1",
    )
    (run_dir / "task.json").write_text(
        json.dumps({"task_id": "t", "title": "T"}),
        encoding="utf-8",
    )
    (run_dir / "session_manifest.json").write_text(
        json.dumps({"session_id": "s"}),
        encoding="utf-8",
    )
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "mcp_world",
                "response_cases": [],
                "audit_rules": [],
                "mcp": {
                    "upstreams": {},
                    "tools": {},
                },
                "world": {
                    "kind": "world_bundle_v1",
                    "seed": 0,
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


async def _low_level_list_tools(server) -> list[types.Tool]:
    handler = server.request_handlers[types.ListToolsRequest]
    result = await handler(types.ListToolsRequest(method="tools/list"))
    return result.root.tools


async def _low_level_call_tool(
    server,
    name: str,
    arguments: dict[str, Any],
) -> types.CallToolResult:
    handler = server.request_handlers[types.CallToolRequest]
    result = await handler(
        types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name=name, arguments=arguments),
        )
    )
    return result.root


def test_low_level_server_list_tools_hides_deny_and_exposes_declared(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_replay_run(run_dir)
    server = build_low_level_server(run_dir)

    tools = asyncio.run(_low_level_list_tools(server))

    names = {tool.name for tool in tools}
    assert "github.get_issue" in names
    assert "github.create_triage_report" in names
    assert "github.merge_pull_request" not in names
    assert {"get_task", "get_session_manifest", "gate_request"} <= names
    descriptions = {tool.name: tool.description for tool in tools}
    assert descriptions["github.get_issue"] == "Read one replayed GitHub issue."
    assert descriptions["github.create_triage_report"] == "Create a shadowed triage report."
    assert all(descriptions[name] for name in ("get_task", "get_session_manifest", "gate_request"))


def test_execution_low_level_components_require_compiled_tool_schemas(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)
    config_path = run_dir / "gate_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    del config["mcp"]["generated"]
    config_path.write_text(json.dumps(config), encoding="utf-8")
    _, registry = _build_low_level_components(run_dir)

    with pytest.raises(ValueError, match=r"mcp tool schema unavailable: github\."):
        asyncio.run(registry.snapshot_declared_tool_schemas())


def test_low_level_server_call_tool_routes_replay_and_shadow(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_replay_run(run_dir)
    server = build_low_level_server(run_dir)

    replay = asyncio.run(_low_level_call_tool(server, "github.get_issue", {"number": 123}))
    shadow = asyncio.run(
        _low_level_call_tool(server, "github.create_triage_report", {"issue_number": 123})
    )

    assert replay.isError is False
    assert replay.structuredContent == {"number": 123, "state": "open"}
    assert shadow.isError is False
    assert shadow.structuredContent["mode"] == "shadow"


def test_low_level_server_gate_request_uses_shared_http_ledger(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_replay_run(run_dir)
    server = build_low_level_server(run_dir)

    mcp_result = asyncio.run(
        _low_level_call_tool(server, "github.create_triage_report", {"issue_number": 123})
    )
    http_result = asyncio.run(
        _low_level_call_tool(server, "gate_request", {"method": "GET", "path": "/health"})
    )
    denied_result = asyncio.run(
        _low_level_call_tool(server, "gate_request", {"method": "POST", "path": "/danger"})
    )

    assert mcp_result.isError is False
    assert http_result.isError is False
    assert http_result.structuredContent["status_code"] == 200
    assert http_result.structuredContent["body"] == {"status": "ok"}
    assert http_result.structuredContent["body_sha256"] == _body_digest(
        http_result.structuredContent["body"]
    )
    assert http_result.structuredContent == _parsed_text(http_result)
    assert denied_result.structuredContent["decision"]["kind"] == "deny"
    assert denied_result.structuredContent["body_sha256"] == _body_digest(
        denied_result.structuredContent["body"]
    )
    assert denied_result.structuredContent == _parsed_text(denied_result)
    events = [
        json.loads(line)
        for line in (run_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [event.get("surface", "http") for event in events] == ["mcp", "http", "http"]
    assert events[0]["tool_name"] == "github.create_triage_report"
    assert events[1]["request"]["path"] == "/health"
    assert events[1]["response_case_id"] == "http_health_001"


def test_low_level_server_records_world_response_digest_for_routed_tool(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    _write_world_run(run_dir)
    server = build_low_level_server(run_dir)

    result = asyncio.run(_low_level_call_tool(server, "counter.read", {}))

    assert result.isError is False
    assert result.structuredContent["body_sha256"] == _body_digest(result.structuredContent["body"])
    backend = WorldBundleBackend(run_dir=run_dir)
    try:
        digest_events = [
            event
            for event in backend.session.list_events()
            if event["type"] == "world_response_digest_recorded"
        ]
        assert len(digest_events) == 1
        payload = digest_events[0]["payload"]
        assert payload["body_sha256"] == result.structuredContent["body_sha256"]
        assert payload["status_code"] == result.structuredContent["status_code"]
        assert payload["tool_id"] == "counter.read"
        assert payload["request"] == {
            "method": "GET",
            "path": "/counter",
            "query": {},
            "body": None,
        }
    finally:
        backend.close()


def test_world_response_digest_event_is_atomic_with_denial_and_rolled_back_on_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "run"
    _write_world_run(run_dir)
    backend = WorldBundleBackend(run_dir=run_dir)

    try:
        denied = backend.handle(
            CallRequest(
                method="POST",
                path="/counter",
                body={"amount": 1},
                headers={
                    "x-datalox-actor-id": "viewer-1",
                    "x-datalox-actor-role": "viewer",
                },
            )
        )

        assert denied is not None and denied.status_code == 403
        assert denied.reason_code == "world_tool_hidden"
        denied_events = [
            event["type"]
            for event in backend.session.list_events()
            if event["type"] in {"tool_invocation_denied", "world_response_digest_recorded"}
        ]
        assert denied_events == ["tool_invocation_denied", "world_response_digest_recorded"]
        denied_digest = next(
            event
            for event in backend.session.list_events()
            if event["type"] == "world_response_digest_recorded"
        )
        assert denied_digest["payload"]["body_sha256"] == _body_digest(denied.body)

        def _boom(request, *, actor, session):
            session.set_state("counter", session.get_state("counter") + 1)
            raise RuntimeError("boom")

        monkeypatch.setattr(backend.bundle.implementation, "handle", _boom)

        with pytest.raises(RuntimeError, match="boom"):
            backend.handle(
                CallRequest(
                    method="GET",
                    path="/counter",
                    headers={
                        "x-datalox-actor-id": "operator-1",
                        "x-datalox-actor-role": "operator",
                    },
                )
            )

        assert (
            sum(
                1
                for event in backend.session.list_events()
                if event["type"] == "world_response_digest_recorded"
            )
            == 1
        )
    finally:
        backend.close()


def test_low_level_server_gate_request_denies_http_provider_access(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    _write_http_live_mcp_run(run_dir)
    server = build_low_level_server(run_dir)

    result = asyncio.run(
        _low_level_call_tool(
            server,
            "gate_request",
            {"method": "GET", "path": "/github/issues/123"},
        )
    )

    assert result.isError is False
    assert result.structuredContent["decision"]["kind"] == "deny"
    assert result.structuredContent["body"]["error"]["code"] == "provider_access_forbidden"
    assert not (run_dir / "captures.jsonl").exists()
    event = json.loads((run_dir / "ledger.jsonl").read_text(encoding="utf-8"))
    assert event["decision"]["reason_code"] == "provider_access_forbidden"


def test_low_level_server_live_mcp_call_is_locally_denied(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)
    server = build_low_level_server(run_dir)

    result = asyncio.run(_low_level_call_tool(server, "github.get_issue", {"number": 123}))

    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "provider_access_forbidden"
    assert not (run_dir / "mcp_captures.jsonl").exists()


def test_execution_tool_listing_never_discovers_schema_from_live_upstream(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)
    server = build_low_level_server(run_dir)

    tools = asyncio.run(_low_level_list_tools(server))

    assert "github.get_issue" in {tool.name for tool in tools}
    assert (run_dir / "mcp_tool_schemas.json").exists()
