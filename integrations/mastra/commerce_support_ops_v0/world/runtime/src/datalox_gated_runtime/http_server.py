"""HTTP adapter for the gated runtime."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from datalox_gated_runtime.binary_response import (
    BinaryResponseEnvelopeError,
    decode_binary_response_body,
    inspect_binary_response_body,
)
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.query import query_from_items
from datalox_gated_runtime.runtime import GatedRuntime
from datalox_gated_runtime.world_backend import create_world_backend


def create_app(
    run_dir: Path,
    *,
    server_token: str | None = None,
) -> FastAPI:
    config = load_gate_config(run_dir / "gate_config.json")
    world_backend = create_world_backend(run_dir=run_dir, config=config.world)
    runtime = GatedRuntime(
        # Execution never has an upstream client. Enabling policy recognition
        # makes declared live-only routes return provider_access_forbidden
        # instead of being misreported as ordinary replay misses.
        policy=GatePolicy.from_config(config.policy),
        response_cases=config.response_cases,
        ledger=SessionLedger(path=run_dir / "ledger.jsonl"),
        world_backend=world_backend,
    )
    lock = threading.Lock()
    app = FastAPI()

    @app.get("/_datalox/health")
    async def health() -> dict[str, object]:
        payload: dict[str, object] = {
            "ok": True,
            "config_id": config.config_id,
        }
        if server_token is not None:
            payload["server_token"] = server_token
        return payload

    async def _read_request_body(request: Request) -> Any | None:
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None

        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type.lower():
            raw_body = await request.body()
            if not raw_body:
                return None
            try:
                return raw_body.decode("utf-8")
            except UnicodeDecodeError:
                return JSONResponse(
                    content={
                        "error": {
                            "code": "invalid_text_body",
                            "message": "Request body is not valid UTF-8.",
                        }
                    },
                    status_code=400,
                )

        raw_body = await request.body()
        if not raw_body:
            return None

        try:
            return json.loads(raw_body.decode("utf-8"))
        except UnicodeDecodeError:
            return JSONResponse(
                content={
                    "error": {
                        "code": "invalid_text_body",
                        "message": "Request body is not valid UTF-8.",
                    }
                },
                status_code=400,
            )
        except json.JSONDecodeError:
            return JSONResponse(
                content={
                    "error": {
                        "code": "invalid_json_body",
                        "message": "Request body is not valid JSON.",
                    }
                },
                status_code=400,
            )

    @app.api_route(
        "/{path:path}", methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    )
    async def handle_gate(path: str, request: Request) -> Response:
        body = await _read_request_body(request)
        if isinstance(body, JSONResponse):
            return body

        call_request = CallRequest(
            method=request.method,
            path="/" + path,
            query=query_from_items(request.query_params.multi_items()),
            body=body,
            headers=dict(request.headers),
        )
        with lock:
            gate_response = runtime.handle(call_request)

        headers = {
            **gate_response.headers,
            "x-datalox-event-id": gate_response.event_id,
            "x-datalox-decision": gate_response.decision.kind,
        }
        if gate_response.response_case_id is not None:
            headers["x-datalox-response-case-id"] = gate_response.response_case_id

        try:
            binary_envelope = inspect_binary_response_body(
                gate_response.body,
                headers=gate_response.headers,
                status_code=gate_response.status_code,
            )
        except BinaryResponseEnvelopeError as exc:
            json_headers = {
                name: value
                for name, value in headers.items()
                if name.lower() not in {"content-length", "content-type"}
            }
            json_headers["x-datalox-decision"] = "deny"
            return JSONResponse(
                content={
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                        "details": exc.details,
                    }
                },
                status_code=500,
                headers=json_headers,
            )
        if gate_response.status_code == 204:
            return Response(status_code=204, headers=headers)
        if binary_envelope is not None:
            binary_headers = {
                name: value for name, value in headers.items() if name.lower() != "content-type"
            }
            binary_headers["content-type"] = binary_envelope.content_type
            return Response(
                content=decode_binary_response_body(binary_envelope),
                status_code=gate_response.status_code,
                headers=binary_headers,
            )
        content_type = next(
            (value for name, value in headers.items() if name.lower() == "content-type"),
            None,
        )
        if (
            content_type is not None
            and "json" not in content_type.lower()
            and (gate_response.body is None or isinstance(gate_response.body, str))
        ):
            return Response(
                content=gate_response.body or "",
                status_code=gate_response.status_code,
                headers=headers,
            )
        return JSONResponse(
            content=gate_response.body,
            status_code=gate_response.status_code,
            headers=headers,
        )

    return app
