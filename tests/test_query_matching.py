import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.mcp_server import build_server
from datalox_gated_runtime.models import CallRequest, ResponseCase
from datalox_gated_runtime.runtime import GatedRuntime
from datalox_gated_runtime.serializer import dataclass_from_dict, dataclass_to_dict
from datalox_gated_runtime.session import create_session


def _call_tool_json(server, name: str, arguments: dict) -> dict:
    result = asyncio.run(server.call_tool(name, arguments))
    content_blocks = result[0] if isinstance(result, tuple) else result
    assert len(content_blocks) == 1
    return json.loads(content_blocks[0].text)


def test_query_mismatch_is_a_miss() -> None:
    runtime = GatedRuntime(
        response_cases=[
            ResponseCase(
                case_id="repos_page_2",
                method="GET",
                path="/repos",
                query={"page": "2"},
                status_code=200,
                body={"page": 2},
            )
        ]
    )

    bare_response = runtime.handle(CallRequest(method="GET", path="/repos"))
    matched_response = runtime.handle(CallRequest(method="GET", path="/repos", query={"page": "2"}))

    assert bare_response.status_code == 404
    assert bare_response.decision.kind == "miss"
    assert matched_response.status_code == 200
    assert matched_response.body == {"page": 2}
    assert matched_response.decision.kind == "replay"


def test_query_specific_response_case_replays_despite_path_shadow_write() -> None:
    runtime = GatedRuntime(
        response_cases=[
            ResponseCase(
                case_id="captured_view",
                method="GET",
                path="/x",
                query={"view": "captured"},
                status_code=200,
                body={"version": "captured"},
            )
        ]
    )

    runtime.handle(CallRequest(method="POST", path="/x", body={"version": "shadow"}))
    response = runtime.handle(CallRequest(method="GET", path="/x", query={"view": "captured"}))

    assert response.status_code == 200
    assert response.decision.kind == "replay"
    assert response.response_case_id == "captured_view"
    assert response.body == {"version": "captured"}


def test_http_server_forwards_query_params(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get("/labstep/experiments/exp_current?verbose=1")

    assert response.status_code == 404
    assert response.headers["x-datalox-decision"] == "miss"


def test_call_request_query_roundtrips() -> None:
    original = CallRequest(method="GET", path="/repos", query={"page": "2"})

    encoded = dataclass_to_dict(original)
    decoded = dataclass_from_dict(CallRequest, encoded)

    assert decoded == original


def test_repeated_query_values_normalize_and_roundtrip_in_order() -> None:
    original = CallRequest(
        method="GET",
        path="/documents",
        query={
            "conditions[]": ["climate", "energy"],
            "fields[]": ["title"],
            "page": "2",
        },
    )

    assert original.query == {
        "conditions[]": ("climate", "energy"),
        "fields[]": "title",
        "page": "2",
    }
    encoded = dataclass_to_dict(original)
    assert encoded["query"]["fields[]"] == "title"
    decoded = dataclass_from_dict(CallRequest, json.loads(json.dumps(encoded)))
    assert decoded == original


def test_response_case_matching_preserves_repeated_value_order() -> None:
    response_case = ResponseCase(
        case_id="ordered_conditions",
        method="GET",
        path="/documents",
        query={"conditions[]": ["climate", "energy"]},
        status_code=200,
        body={"count": 2},
    )

    assert response_case.matches(
        CallRequest(
            method="GET",
            path="/documents",
            query={"conditions[]": ("climate", "energy")},
        )
    )
    assert not response_case.matches(
        CallRequest(
            method="GET",
            path="/documents",
            query={"conditions[]": ("energy", "climate")},
        )
    )


def test_response_case_scalar_matches_singleton_sequence_wire_equivalent() -> None:
    response_case = ResponseCase(
        case_id="title_field",
        method="GET",
        path="/documents",
        query={"fields[]": "title"},
        status_code=200,
        body={"title": "Energy rule"},
    )

    request = CallRequest(
        method="GET",
        path="/documents",
        query={"fields[]": ["title"]},
    )

    assert request.query == {"fields[]": "title"}
    assert response_case.matches(request)


def test_gate_config_response_case_query_loads_and_matches(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        json.dumps(
            {
                "config_id": "query_config",
                "response_cases": [
                    {
                        "case_id": "repos_page_2",
                        "method": "GET",
                        "path": "/repos",
                        "query": {"page": "2"},
                        "status_code": 200,
                        "body": {"page": 2},
                    }
                ],
                "audit_rules": [],
            }
        ),
        encoding="utf-8",
    )

    config = load_gate_config(config_path)
    response_case = config.response_cases[0]

    assert response_case.query == {"page": "2"}
    assert response_case.matches(CallRequest(method="GET", path="/repos", query={"page": "2"}))
    assert not response_case.matches(CallRequest(method="GET", path="/repos", query={"page": "3"}))


def test_gate_config_repeated_query_loads_and_matches(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        json.dumps(
            {
                "config_id": "repeated_query_config",
                "response_cases": [
                    {
                        "case_id": "documents_conditions",
                        "method": "GET",
                        "path": "/documents",
                        "query": {
                            "conditions[]": ["climate", "energy"],
                            "fields[]": ["title"],
                        },
                        "status_code": 200,
                        "body": {"count": 2},
                    }
                ],
                "audit_rules": [],
            }
        ),
        encoding="utf-8",
    )

    response_case = load_gate_config(config_path).response_cases[0]

    assert response_case.query == {
        "conditions[]": ("climate", "energy"),
        "fields[]": "title",
    }
    assert response_case.matches(
        CallRequest(
            method="GET",
            path="/documents",
            query={
                "conditions[]": ["climate", "energy"],
                "fields[]": "title",
            },
        )
    )


def test_gate_config_rejects_non_string_query_values(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        json.dumps(
            {
                "config_id": "query_config",
                "response_cases": [
                    {
                        "case_id": "repos_page_2",
                        "method": "GET",
                        "path": "/repos",
                        "query": {"page": 2},
                        "status_code": 200,
                        "body": {"page": 2},
                    }
                ],
                "audit_rules": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"response_cases\[0\]\.query.page must be a string"):
        load_gate_config(config_path)


def test_mcp_gate_request_accepts_query(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )
    server = build_server(run_dir)

    result = _call_tool_json(
        server,
        "gate_request",
        {
            "method": "GET",
            "path": "/labstep/experiments/exp_current",
            "query": {"verbose": "1"},
        },
    )

    assert result["status_code"] == 404
    assert result["decision"]["kind"] == "miss"
    event = json.loads((run_dir / "ledger.jsonl").read_text(encoding="utf-8"))
    assert event["request"]["query"] == {"verbose": "1"}


def test_mcp_gate_request_preserves_repeated_query_values(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )
    server = build_server(run_dir)

    result = _call_tool_json(
        server,
        "gate_request",
        {
            "method": "GET",
            "path": "/labstep/experiments/exp_current",
            "query": {
                "conditions[]": ["climate", "energy"],
                "fields[]": ["title"],
            },
        },
    )

    assert result["status_code"] == 404
    event = json.loads((run_dir / "ledger.jsonl").read_text(encoding="utf-8"))
    assert event["request"]["query"] == {
        "conditions[]": ["climate", "energy"],
        "fields[]": "title",
    }
