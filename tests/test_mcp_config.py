import json
from pathlib import Path

import pytest

from datalox_gated_runtime.config import load_gate_config


def _write_config(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _base_config() -> dict[str, object]:
    return {"config_id": "mcp_config", "response_cases": [], "audit_rules": []}


def test_loads_minimal_mcp_block(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {
            "github": {
                "transport": "stdio",
                "command": "github-mcp-server",
                "args": ["--read-only"],
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
    }
    _write_config(config_path, payload)

    config = load_gate_config(config_path)

    assert config.mcp is not None
    assert config.mcp.upstreams["github"].transport == "stdio"
    assert config.mcp.upstreams["github"].command == "github-mcp-server"
    assert config.mcp.upstreams["github"].args == ["--read-only"]
    assert config.mcp.tools["github.get_issue"] == "live"
    assert config.mcp.live["github.get_issue"].contract == "safe_read"


def test_replay_tool_can_use_generated_schema_without_upstream(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {},
        "tools": {"github.get_issue": "replay"},
        "generated": {
            "tool_schemas": {
                "github.get_issue": {
                    "description": "Read one replayed GitHub issue.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"number": {"type": "integer"}},
                        "required": ["number"],
                    },
                }
            },
            "response_cases": [
                {
                    "case_id": "mcp_cap_001",
                    "tool_name": "github.get_issue",
                    "arguments": {"number": 123},
                    "result": {"structuredContent": {"number": 123, "state": "open"}},
                    "evidence_ref": "mcp-live:github:2026-07-06T00:00:00Z",
                }
            ],
        },
    }
    _write_config(config_path, payload)

    config = load_gate_config(config_path)

    assert config.mcp is not None
    assert config.mcp.generated.tool_schemas["github.get_issue"]["inputSchema"]["type"] == "object"
    assert (
        config.mcp.generated.tool_schemas["github.get_issue"]["description"]
        == "Read one replayed GitHub issue."
    )
    assert config.mcp.generated.response_cases[0].case_id == "mcp_cap_001"


def test_allows_dots_inside_upstream_tool_name(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {},
        "tools": {"github.search.repos": "replay"},
        "generated": {
            "tool_schemas": {
                "github.search.repos": {
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    }
                }
            },
            "response_cases": [
                {
                    "case_id": "mcp_cap_search_repos",
                    "tool_name": "github.search.repos",
                    "arguments": {"query": "datalox"},
                    "result": {"structuredContent": {"total_count": 1}},
                }
            ],
        },
    }
    _write_config(config_path, payload)

    config = load_gate_config(config_path)

    assert config.mcp is not None
    assert "github.search.repos" in config.mcp.generated.tool_schemas
    assert config.mcp.generated.response_cases[0].tool_name == "github.search.repos"


def test_deny_tool_does_not_require_schema_or_upstream(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {},
        "tools": {"github.merge_pull_request": "deny"},
    }
    _write_config(config_path, payload)

    config = load_gate_config(config_path)

    assert config.mcp is not None
    assert config.mcp.tools["github.merge_pull_request"] == "deny"


def test_rejects_unknown_mcp_upstream_field(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {
            "github": {
                "transport": "stdio",
                "command": "github-mcp-server",
                "argz": ["--read-only"],
            }
        },
        "tools": {"github.merge_pull_request": "deny"},
    }
    _write_config(config_path, payload)

    with pytest.raises(ValueError, match=r"mcp\.upstreams\.github\.argz|unknown field"):
        load_gate_config(config_path)


@pytest.mark.parametrize("description", ["", 3])
def test_rejects_invalid_generated_tool_description(
    tmp_path: Path,
    description: object,
) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {},
        "tools": {"github.get_issue": "replay"},
        "generated": {
            "tool_schemas": {
                "github.get_issue": {
                    "description": description,
                    "inputSchema": {"type": "object"},
                }
            }
        },
    }
    _write_config(config_path, payload)

    with pytest.raises(ValueError, match="description must be a non-empty string"):
        load_gate_config(config_path)


def test_rejects_unknown_key_inside_mcp_block(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {},
        "tools": {"github.merge_pull_request": "deny"},
        "ambient_mcp": {},
    }
    _write_config(config_path, payload)

    with pytest.raises(ValueError, match=r"mcp\.ambient_mcp is not supported"):
        load_gate_config(config_path)


def test_rejects_invalid_mcp_tool_upstream_segment_even_with_generated_schema(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {},
        "tools": {"git/hub.get_issue": "replay"},
        "generated": {
            "tool_schemas": {
                "git/hub.get_issue": {
                    "inputSchema": {
                        "type": "object",
                        "properties": {"number": {"type": "integer"}},
                        "required": ["number"],
                    }
                }
            }
        },
    }
    _write_config(config_path, payload)

    with pytest.raises(ValueError, match=r"mcp tool keys must be <upstream>\.<tool>"):
        load_gate_config(config_path)


def test_rejects_exposed_tool_without_schema_source(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {},
        "tools": {"github.create_triage_report": "shadow"},
    }
    _write_config(config_path, payload)

    with pytest.raises(
        ValueError, match=r"mcp tool schema unavailable: github\.create_triage_report"
    ):
        load_gate_config(config_path)


def test_rejects_live_tool_without_safe_read_contract(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {"github": {"transport": "stdio", "command": "github-mcp-server", "args": []}},
        "tools": {"github.get_issue": "live"},
    }
    _write_config(config_path, payload)

    with pytest.raises(ValueError, match=r"mcp\.live\.github\.get_issue is required"):
        load_gate_config(config_path)


def test_rejects_mcp_live_for_non_live_tool(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["mcp"] = {
        "upstreams": {"github": {"transport": "stdio", "command": "github-mcp-server", "args": []}},
        "tools": {"github.get_issue": "shadow"},
        "live": {
            "github.get_issue": {
                "contract": "safe_read",
                "evidence_ref": "evidence/mcp/github.md#get_issue",
            }
        },
    }
    _write_config(config_path, payload)

    with pytest.raises(
        ValueError, match=r"mcp\.live\.github\.get_issue requires mcp\.tools decision live"
    ):
        load_gate_config(config_path)


def test_rejects_ambient_mcp(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    payload = _base_config()
    payload["ambient_mcp"] = {"servers": []}
    _write_config(config_path, payload)

    with pytest.raises(ValueError, match="ambient_mcp is not supported"):
        load_gate_config(config_path)
