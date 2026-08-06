import json
from pathlib import Path

import pytest

from datalox_gated_runtime import CallRequest, GatedRuntime, ResponseCase
from datalox_gated_runtime.ledger import (
    SessionLedger,
    load_events,
    shadow_state_from_events,
)
from datalox_gated_runtime.models import McpDecision, McpLedgerEvent


def test_load_events_rehydrates_nested_dataclasses(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        response_cases=[
            ResponseCase(
                case_id="case_001",
                method="GET",
                path="/x",
                status_code=200,
                body={"ok": True},
            )
        ],
    )
    runtime.handle(CallRequest(method="GET", path="/x"))
    runtime.handle(CallRequest(method="POST", path="/assay-results", body={"result": "pass"}))

    events = load_events(ledger_path)

    assert len(events) == 2
    assert events[0].request.path == "/x"
    assert events[0].decision.kind == "replay"
    assert events[1].request.path == "/assay-results"
    assert events[1].shadow_mutation == {
        "method": "POST",
        "path": "/assay-results",
        "query": {},
        "body": {"result": "pass"},
    }


def test_append_preserves_existing_ledger_lines(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        response_cases=[
            ResponseCase(
                case_id="case_001",
                method="GET",
                path="/x",
                status_code=200,
                body={"ok": True},
            )
        ],
    )

    runtime.handle(CallRequest(method="GET", path="/x"))
    runtime.handle(CallRequest(method="POST", path="/y", body={"hello": "world"}))

    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]

    assert len(rows) == 2
    assert rows[0]["request"]["path"] == "/x"
    assert rows[1]["request"]["path"] == "/y"


def test_load_events_raises_on_malformed_jsonl(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger_path.write_text("{broken_json\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid ledger jsonl at line 1"):
        load_events(ledger_path)


def test_shadow_state_from_events_rebuilds_writes(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        response_cases=[
            ResponseCase(
                case_id="case_001",
                method="GET",
                path="/x",
                status_code=200,
                body={"ok": True},
            )
        ],
    )
    runtime.handle(CallRequest(method="GET", path="/x"))
    runtime.handle(CallRequest(method="POST", path="/assay-results", body={"result": "pass"}))

    events = load_events(ledger_path)
    shadow_state = shadow_state_from_events(events)

    assert shadow_state == {
        "writes": [
            {"method": "POST", "path": "/assay-results", "query": {}, "body": {"result": "pass"}},
        ],
        "mcp_tool_calls": [],
    }


def test_ledger_appends_jsonl_events(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        response_cases=[
            ResponseCase(
                case_id="case_001",
                method="GET",
                path="/x",
                status_code=200,
                body={"ok": True},
            )
        ],
    )

    runtime.handle(CallRequest(method="GET", path="/x"))
    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]

    assert len(rows) == 1
    assert rows[0]["request"]["path"] == "/x"
    assert rows[0]["decision"]["kind"] == "replay"


def test_ledger_persists_shadow_mutation(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(ledger=SessionLedger(path=ledger_path))

    runtime.handle(CallRequest(method="POST", path="/assay-results", body={"result": "pass"}))
    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]

    assert len(rows) == 1
    assert rows[0]["decision"]["kind"] == "shadow_write"
    assert rows[0]["shadow_mutation"] == {
        "method": "POST",
        "path": "/assay-results",
        "query": {},
        "body": {"result": "pass"},
    }


def test_ledger_appends_multiple_events(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        response_cases=[
            ResponseCase(
                case_id="case_001",
                method="GET",
                path="/x",
                status_code=200,
                body={"ok": True},
            )
        ],
    )

    runtime.handle(CallRequest(method="GET", path="/x"))
    runtime.handle(CallRequest(method="POST", path="/y"))

    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]

    assert len(rows) == 2
    assert rows[0]["request"]["path"] == "/x"
    assert rows[1]["request"]["path"] == "/y"
    assert rows[0]["decision"]["kind"] == "replay"
    assert rows[1]["decision"]["kind"] == "shadow_write"


def test_session_ledger_rehydrates_events_and_shadow_state_from_existing_file(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "ledger.jsonl"

    first_runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        response_cases=[
            ResponseCase(
                case_id="case_001",
                method="GET",
                path="/x",
                status_code=200,
                body={"ok": True},
            )
        ],
    )
    first_runtime.handle(CallRequest(method="GET", path="/x"))
    first_runtime.handle(CallRequest(method="POST", path="/assay-results", body={"result": "pass"}))

    second_ledger = SessionLedger(path=ledger_path)
    assert len(second_ledger.events) == 2
    assert second_ledger.events[0].request.path == "/x"
    assert second_ledger.shadow_state == {
        "writes": [
            {"method": "POST", "path": "/assay-results", "query": {}, "body": {"result": "pass"}}
        ],
        "mcp_tool_calls": [],
    }


def test_rehydrated_shadow_read_matches_repeated_query_values(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    first_runtime = GatedRuntime(ledger=SessionLedger(path=ledger_path))
    query = {"conditions[]": ["climate", "energy"]}
    first_runtime.handle(
        CallRequest(
            method="POST",
            path="/records",
            query=query,
            body={"status": "reviewed"},
        )
    )

    second_runtime = GatedRuntime(ledger=SessionLedger(path=ledger_path))
    response = second_runtime.handle(CallRequest(method="GET", path="/records", query=query))

    assert second_runtime.ledger.events[0].request.query == {"conditions[]": ("climate", "energy")}
    assert response.decision.kind == "shadow_read"
    assert response.body == {"status": "reviewed"}


def test_session_ledger_rejects_corrupt_tail_jsonl(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    first_line = json.dumps(
        {
            "event_id": "evt_1",
            "created_at": "2026-07-01T00:00:00+00:00",
            "request": {
                "method": "GET",
                "path": "/x",
                "body": None,
                "headers": {},
                "operation_id": None,
            },
            "decision": {"kind": "replay", "reason_code": "ok", "message": "ok", "rule_id": None},
            "response_status_code": 200,
            "response_body": {"ok": True},
        },
    )
    ledger_path.write_text(f"{first_line}\n{{broken_json\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid ledger jsonl at line 2"):
        SessionLedger(path=ledger_path)


def test_session_ledger_append_keeps_rehydrated_events_in_memory(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    first_runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        response_cases=[
            ResponseCase(
                case_id="case_001",
                method="GET",
                path="/x",
                status_code=200,
                body={"ok": True},
            )
        ],
    )
    first_runtime.handle(CallRequest(method="GET", path="/x"))

    second_ledger = SessionLedger(path=ledger_path)
    runtime = GatedRuntime(ledger=second_ledger, response_cases=first_runtime.response_cases)
    runtime.handle(CallRequest(method="POST", path="/y"))

    assert len(second_ledger.events) == 2
    assert second_ledger.events[0].request.path == "/x"
    assert second_ledger.events[1].request.path == "/y"
    assert second_ledger.shadow_state["writes"] == [
        {"method": "POST", "path": "/y", "query": {}, "body": None},
    ]


def test_load_events_rehydrates_mcp_events_and_shadow_state(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = SessionLedger(path=ledger_path)

    ledger.record_mcp(
        tool_name="github.create_triage_report",
        upstream_name="github",
        upstream_tool_name="create_triage_report",
        arguments={"issue_number": 123},
        decision=McpDecision(
            kind="shadow",
            reason_code="mcp_tool_shadowed",
            message="MCP tool call shadowed.",
        ),
        result={"structuredContent": {"ok": True, "mode": "shadow"}},
        shadow_mutation={
            "tool_name": "github.create_triage_report",
            "arguments": {"issue_number": 123},
            "result": {"ok": True, "mode": "shadow"},
        },
    )

    events = load_events(ledger_path)
    shadow_state = shadow_state_from_events(events)

    assert isinstance(events[0], McpLedgerEvent)
    assert events[0].surface == "mcp"
    assert shadow_state == {
        "writes": [],
        "mcp_tool_calls": [
            {
                "tool_name": "github.create_triage_report",
                "arguments": {"issue_number": 123},
                "result": {"ok": True, "mode": "shadow"},
            }
        ],
    }


def test_load_events_rejects_unknown_surface(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger_path.write_text(
        json.dumps(
            {
                "surface": "ftp",
                "event_id": "evt_bad",
                "created_at": "2026-07-01T00:00:00+00:00",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid ledger jsonl at line 1"):
        load_events(ledger_path)
