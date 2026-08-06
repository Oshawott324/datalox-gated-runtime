import json
from dataclasses import dataclass

import pytest

from datalox_gated_runtime.models import (
    CallRequest,
    GateDecision,
    LedgerEvent,
    McpDecision,
    McpLedgerEvent,
    ResponseCase,
    RunExport,
)
from datalox_gated_runtime.serializer import dataclass_from_dict, dataclass_to_dict


def test_response_case_roundtrips_through_json_dict() -> None:
    original = ResponseCase(
        case_id="case_001",
        method="GET",
        path="/labstep/experiments/exp_current",
        status_code=200,
        body={"id": "exp_current", "status": "active"},
        evidence_ref="examples/lab_ops_stale_result/response_cases.json#case_001",
    )

    encoded = dataclass_to_dict(original)
    decoded = dataclass_from_dict(ResponseCase, encoded)

    assert decoded == original


def test_call_request_defaults_survive_roundtrip() -> None:
    encoded = dataclass_to_dict(CallRequest(method="GET", path="/health"))
    decoded = dataclass_from_dict(CallRequest, encoded)

    assert decoded.method == "GET"
    assert decoded.path == "/health"
    assert decoded.headers == {}
    assert decoded.body is None


def test_unknown_key_rejected_with_name() -> None:
    payload = dataclass_to_dict(CallRequest(method="GET", path="/health"))
    payload["unexpected_field"] = "bad"

    with pytest.raises(ValueError, match="unexpected_field"):
        dataclass_from_dict(CallRequest, payload)


@dataclass(frozen=True)
class Envelope:
    request: CallRequest


def test_nested_dataclass_roundtrip() -> None:
    original = Envelope(request=CallRequest(method="POST", path="/v1/items"))
    encoded = dataclass_to_dict(original)
    decoded = dataclass_from_dict(Envelope, encoded)

    assert decoded == original


def test_nested_model_roundtrip_for_ledger_event() -> None:
    original = LedgerEvent(
        event_id="event_001",
        created_at="2026-01-01T00:00:00Z",
        request=CallRequest(
            method="GET",
            path="/health",
            query={"status": ["active", "pending"]},
        ),
        decision=GateDecision(kind="replay", reason_code="cached", message="replay"),
        response_status_code=200,
        response_body={"status": "ok"},
    )

    encoded = dataclass_to_dict(original)
    decoded = dataclass_from_dict(LedgerEvent, json.loads(json.dumps(encoded)))

    assert isinstance(decoded.request, CallRequest)
    assert isinstance(decoded.decision, GateDecision)
    assert decoded == original


def test_nested_model_roundtrip_for_run_export_events() -> None:
    event = LedgerEvent(
        event_id="event_001",
        created_at="2026-01-01T00:00:00Z",
        request=CallRequest(method="GET", path="/health"),
        decision=GateDecision(kind="replay", reason_code="cached", message="replay"),
        response_status_code=200,
        response_body={"status": "ok"},
    )
    original = RunExport(
        run_id="run_001",
        created_at="2026-01-01T00:00:00Z",
        events=[event],
        shadow_state={},
    )

    encoded = dataclass_to_dict(original)
    decoded = dataclass_from_dict(RunExport, encoded)

    assert isinstance(decoded.events[0], LedgerEvent)
    assert isinstance(decoded.events[0].request, CallRequest)
    assert decoded == original


def test_run_export_decodes_mixed_http_mcp_events_by_surface() -> None:
    payload = {
        "run_id": "run_001",
        "created_at": "2026-01-01T00:00:00Z",
        "events": [
            {
                "event_id": "event_http_001",
                "created_at": "2026-01-01T00:00:00Z",
                "request": {"method": "GET", "path": "/health"},
                "decision": {"kind": "replay", "reason_code": "cached", "message": "replay"},
                "response_status_code": 200,
                "response_body": {"status": "ok"},
            },
            {
                "surface": "mcp",
                "event_id": "event_mcp_001",
                "created_at": "2026-01-01T00:00:01Z",
                "tool_name": "github.create_triage_report",
                "upstream_name": "github",
                "upstream_tool_name": "create_triage_report",
                "arguments": {"issue_number": 123},
                "decision": {
                    "kind": "shadow",
                    "reason_code": "mcp_tool_shadowed",
                    "message": "MCP tool call shadowed.",
                },
                "result": {"structuredContent": {"ok": True, "mode": "shadow"}},
                "shadow_mutation": {
                    "tool_name": "github.create_triage_report",
                    "arguments": {"issue_number": 123},
                    "result": {"ok": True, "mode": "shadow"},
                },
            },
        ],
        "shadow_state": {"writes": [], "mcp_tool_calls": []},
    }

    decoded = dataclass_from_dict(RunExport, payload)

    assert isinstance(decoded.events[0], LedgerEvent)
    assert decoded.events[0].surface == "http"
    assert isinstance(decoded.events[0].request, CallRequest)
    assert isinstance(decoded.events[1], McpLedgerEvent)
    assert isinstance(decoded.events[1].decision, McpDecision)
    assert decoded.events[1].tool_name == "github.create_triage_report"


def test_run_export_rejects_unknown_event_surface() -> None:
    payload = {
        "run_id": "run_001",
        "created_at": "2026-01-01T00:00:00Z",
        "events": [
            {
                "surface": "ftp",
                "event_id": "event_bad_001",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ],
        "shadow_state": {},
    }

    with pytest.raises(ValueError, match="unsupported event surface: ftp"):
        dataclass_from_dict(RunExport, payload)
