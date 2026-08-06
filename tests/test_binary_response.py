import asyncio
from dataclasses import asdict
import json
from pathlib import Path

from fastapi.testclient import TestClient

from datalox_gated_runtime import (
    CallRequest,
    GatePolicy,
    GatedRuntime,
    ResponseCase,
    make_binary_response_body,
)
from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.ledger import SessionLedger, load_events
from datalox_gated_runtime.mcp_registry import McpToolRegistry
from datalox_gated_runtime.models import McpGateConfig
from datalox_gated_runtime.world_backend import WorldResponse


PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff"


class _BinaryWorld:
    world_id = "binary_test"

    def handle(self, request: CallRequest) -> WorldResponse:
        if request.path == "/empty":
            body = make_binary_response_body(b"", content_type="application/octet-stream")
        else:
            body = make_binary_response_body(PNG_BYTES, content_type="image/png")
        return WorldResponse(
            status_code=200,
            body=body,
            is_mutation=False,
            world_id=self.world_id,
        )


class _MalformedBinaryWorld:
    world_id = "malformed_binary_test"

    def __init__(
        self,
        body: dict,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.body = body
        self.status_code = status_code
        self.headers = headers or {}

    def handle(self, request: CallRequest) -> WorldResponse:
        return WorldResponse(
            status_code=self.status_code,
            body=self.body,
            is_mutation=False,
            world_id=self.world_id,
            headers=self.headers,
        )


class _UnusedMcpRuntime:
    async def handle(self, _call):
        raise AssertionError("gate_request must use the HTTP-shaped runtime")


def _write_config(run_dir: Path) -> None:
    run_dir.mkdir()
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "binary_response_test",
                "response_cases": [],
                "audit_rules": [],
            }
        ),
        encoding="utf-8",
    )


def test_http_projection_emits_exact_binary_bytes_and_content_type(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    _write_config(run_dir)
    monkeypatch.setattr(
        "datalox_gated_runtime.http_server.create_world_backend",
        lambda **_kwargs: _BinaryWorld(),
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get("/image")

    assert response.status_code == 200
    assert response.content == PNG_BYTES
    assert response.headers["content-type"] == "image/png"
    assert response.headers["content-length"] == str(len(PNG_BYTES))


def test_http_projection_preserves_empty_binary_body(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    _write_config(run_dir)
    monkeypatch.setattr(
        "datalox_gated_runtime.http_server.create_world_backend",
        lambda **_kwargs: _BinaryWorld(),
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get("/empty")

    assert response.status_code == 200
    assert response.content == b""
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-length"] == "0"


def test_response_case_binary_replay_emits_exact_bytes_and_keeps_json_ledger(
    tmp_path: Path,
    monkeypatch,
) -> None:
    envelope = make_binary_response_body(PNG_BYTES, content_type="image/png")
    runtime = GatedRuntime(
        policy=GatePolicy.default(),
        response_cases=[
            ResponseCase(
                case_id="binary_case",
                method="GET",
                path="/image",
                status_code=200,
                body=envelope,
            )
        ],
        ledger=SessionLedger(path=tmp_path / "ledger.jsonl"),
    )
    run_dir = tmp_path / "run"
    _write_config(run_dir)
    monkeypatch.setattr(
        "datalox_gated_runtime.http_server.GatedRuntime",
        lambda **_kwargs: runtime,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get("/image")

    assert response.content == PNG_BYTES
    assert response.headers["content-type"] == "image/png"
    event = load_events(tmp_path / "ledger.jsonl")[0]
    assert event.response_body == envelope
    json.dumps(asdict(runtime.export()), allow_nan=False)


def test_binary_envelope_stays_json_serializable_in_response_ledger_export_and_mcp(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        world_backend=_BinaryWorld(),
    )
    expected = make_binary_response_body(PNG_BYTES, content_type="image/png")

    response = runtime.handle(CallRequest(method="GET", path="/image"))
    run_export = runtime.export()
    registry = McpToolRegistry(
        run_dir=tmp_path,
        config=McpGateConfig(),
        mcp_runtime=_UnusedMcpRuntime(),
        http_runtime=runtime,
    )
    mcp_payload = asyncio.run(
        registry._call_tool_payload(
            "gate_request",
            {"method": "GET", "path": "/image"},
        )
    )

    assert response.body == expected
    assert run_export.events[0].response_body == expected
    assert mcp_payload["body"] == expected
    assert load_events(ledger_path)[0].response_body == expected
    json.dumps(asdict(run_export), allow_nan=False)
    json.dumps(mcp_payload, allow_nan=False)


def test_runtime_rejects_invalid_base64_with_stable_error(tmp_path: Path) -> None:
    malformed = {
        "$datalox_binary_response": {
            "schema_version": "datalox_binary_response_v1",
            "content_type": "image/png",
            "data_base64": "not base64!",
        }
    }
    runtime = GatedRuntime(
        ledger=SessionLedger(path=tmp_path / "ledger.jsonl"),
        world_backend=_MalformedBinaryWorld(malformed),
    )

    response = runtime.handle(CallRequest(method="GET", path="/image"))

    assert response.status_code == 500
    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "binary_response_envelope_invalid"
    assert response.body == {
        "error": {
            "code": "binary_response_envelope_invalid",
            "message": "Binary response envelope data_base64 is not valid base64.",
            "details": {
                "reason": "base64_invalid",
                "field": "$datalox_binary_response.data_base64",
            },
        }
    }
    assert load_events(tmp_path / "ledger.jsonl")[0].response_body == response.body


def test_runtime_rejects_malformed_envelope_shape_with_stable_error() -> None:
    malformed = {
        "$datalox_binary_response": {
            "schema_version": "datalox_binary_response_v1",
            "content_type": "image/png",
            "data_base64": "",
            "unexpected": True,
        }
    }
    runtime = GatedRuntime(world_backend=_MalformedBinaryWorld(malformed))

    response = runtime.handle(CallRequest(method="GET", path="/image"))

    assert response.status_code == 500
    assert response.decision.reason_code == "binary_response_envelope_invalid"
    assert response.body["error"]["details"] == {
        "reason": "payload_fields_invalid",
        "field": "$datalox_binary_response",
    }


def test_runtime_rejects_noncanonical_base64_before_ledger_insertion(
    tmp_path: Path,
) -> None:
    malformed = {
        "$datalox_binary_response": {
            "schema_version": "datalox_binary_response_v1",
            "content_type": "image/png",
            "data_base64": "AB==",
        }
    }
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        world_backend=_MalformedBinaryWorld(malformed),
    )

    response = runtime.handle(CallRequest(method="GET", path="/image"))

    assert response.status_code == 500
    assert response.body["error"]["details"]["reason"] == "base64_noncanonical"
    assert load_events(ledger_path)[0].response_body == response.body


def test_runtime_rejects_content_type_header_conflict() -> None:
    envelope = make_binary_response_body(PNG_BYTES, content_type="image/png")
    runtime = GatedRuntime(
        world_backend=_MalformedBinaryWorld(
            envelope,
            headers={"Content-Type": "image/svg+xml"},
        )
    )

    response = runtime.handle(CallRequest(method="GET", path="/image"))

    assert response.status_code == 500
    assert response.body["error"]["details"] == {
        "reason": "content_type_header_conflict",
        "field": "headers.content-type",
    }


def test_http_projection_preserves_matching_content_length(
    tmp_path: Path,
    monkeypatch,
) -> None:
    envelope = make_binary_response_body(PNG_BYTES, content_type="image/png")
    run_dir = tmp_path / "run"
    _write_config(run_dir)
    monkeypatch.setattr(
        "datalox_gated_runtime.http_server.create_world_backend",
        lambda **_kwargs: _MalformedBinaryWorld(
            envelope,
            headers={"Content-Length": str(len(PNG_BYTES))},
        ),
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get("/image")

    assert response.status_code == 200
    assert response.content == PNG_BYTES
    assert response.headers["content-length"] == str(len(PNG_BYTES))


def test_runtime_rejects_mismatched_content_length_before_ledger(
    tmp_path: Path,
) -> None:
    envelope = make_binary_response_body(PNG_BYTES, content_type="image/png")
    ledger_path = tmp_path / "ledger.jsonl"
    runtime = GatedRuntime(
        ledger=SessionLedger(path=ledger_path),
        world_backend=_MalformedBinaryWorld(
            envelope,
            headers={"Content-Length": str(len(PNG_BYTES) + 1)},
        ),
    )

    response = runtime.handle(CallRequest(method="GET", path="/image"))

    assert response.status_code == 500
    assert response.body["error"]["details"] == {
        "reason": "content_length_header_mismatch",
        "field": "headers.content-length",
    }
    assert load_events(ledger_path)[0].response_body == response.body


def test_runtime_rejects_noncanonical_content_length() -> None:
    envelope = make_binary_response_body(PNG_BYTES, content_type="image/png")
    runtime = GatedRuntime(
        world_backend=_MalformedBinaryWorld(
            envelope,
            headers={"Content-Length": f"0{len(PNG_BYTES)}"},
        ),
    )

    response = runtime.handle(CallRequest(method="GET", path="/image"))

    assert response.status_code == 500
    assert response.body["error"]["details"] == {
        "reason": "content_length_header_invalid",
        "field": "headers.content-length",
    }


def test_runtime_rejects_duplicate_case_content_length_headers() -> None:
    envelope = make_binary_response_body(PNG_BYTES, content_type="image/png")
    length = str(len(PNG_BYTES))
    runtime = GatedRuntime(
        world_backend=_MalformedBinaryWorld(
            envelope,
            headers={"Content-Length": length, "content-length": length},
        ),
    )

    response = runtime.handle(CallRequest(method="GET", path="/image"))

    assert response.status_code == 500
    assert response.body["error"]["details"] == {
        "reason": "content_length_header_duplicate",
        "field": "headers.content-length",
    }


def test_runtime_rejects_binary_envelope_for_bodyless_http_statuses() -> None:
    envelope = make_binary_response_body(b"", content_type="application/octet-stream")

    for status_code in (100, 204, 205, 304):
        runtime = GatedRuntime(
            world_backend=_MalformedBinaryWorld(envelope, status_code=status_code),
        )
        response = runtime.handle(CallRequest(method="GET", path="/empty"))

        assert response.status_code == 500
        assert response.body["error"]["details"] == {
            "reason": "status_code_forbids_body",
            "field": "status_code",
        }
