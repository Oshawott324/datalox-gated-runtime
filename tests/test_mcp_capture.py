import json
from pathlib import Path

import pytest

from datalox_gated_runtime.mcp_capture import (
    McpCaptureStore,
    McpReplayStore,
    canonical_arguments,
    load_mcp_captures,
)
from datalox_gated_runtime.models import McpResponseCase


def test_canonical_arguments_are_order_independent() -> None:
    left = {"repo": "r", "owner": "o", "number": 123}
    right = {"number": 123, "owner": "o", "repo": "r"}

    assert canonical_arguments(left) == canonical_arguments(right)
    assert canonical_arguments(left) == '{"number":123,"owner":"o","repo":"r"}'


def test_capture_store_appends_jsonl_and_loads_cases(tmp_path: Path) -> None:
    path = tmp_path / "mcp_captures.jsonl"
    case = McpResponseCase(
        case_id="mcp_cap_001",
        tool_name="github.get_issue",
        arguments={"owner": "o", "repo": "r", "number": 123},
        result={"structuredContent": {"number": 123}},
        evidence_ref="mcp-live:github:2026-07-06T00:00:00Z",
        input_schema={"type": "object", "properties": {"number": {"type": "integer"}}},
    )

    McpCaptureStore(path).append(case)

    assert load_mcp_captures(path) == [case]
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["tool_name"] == "github.get_issue"
    assert raw["arguments"]["number"] == 123


def test_replay_store_matches_exact_arguments_only() -> None:
    case = McpResponseCase(
        case_id="mcp_cap_001",
        tool_name="github.get_issue",
        arguments={"owner": "o", "repo": "r", "number": 123},
        result={"structuredContent": {"number": 123}},
    )
    store = McpReplayStore([case])

    assert store.find("github.get_issue", {"repo": "r", "number": 123, "owner": "o"}) == case
    assert store.find("github.get_issue", {"owner": "o", "repo": "r", "number": "123"}) is None
    assert store.find("github.get_issue", {"owner": "o", "repo": "r"}) is None
    assert store.find("github.list_issues", {"owner": "o", "repo": "r", "number": 123}) is None


def test_load_mcp_captures_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert load_mcp_captures(tmp_path / "missing.jsonl") == []


def test_load_mcp_captures_rejects_corrupt_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "mcp_captures.jsonl"
    path.write_text("{bad json\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid mcp captures jsonl at line 1"):
        load_mcp_captures(path)


def test_load_mcp_captures_rejects_invalid_case_shape(tmp_path: Path) -> None:
    path = tmp_path / "mcp_captures.jsonl"
    path.write_text(
        json.dumps(
            {
                "case_id": "mcp_cap_001",
                "tool_name": "github.get_issue",
                "arguments": [],
                "result": {"structuredContent": {"number": 123}},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid mcp captures jsonl at line 1"):
        load_mcp_captures(path)
