from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time
from typing import Any

from fastapi.testclient import TestClient
from mcp.types import LATEST_PROTOCOL_VERSION
import pytest

from datalox_gated_runtime.cli import _build_parser
from datalox_gated_runtime.public_export import (
    PUBLIC_EXPORT_SCHEMA,
    build_public_run_export,
)
from datalox_gated_runtime.remote_world_service import (
    _RemoteSession,
    create_remote_world_app,
)
from datalox_gated_runtime.session import _combined_audit_payload


EXAMPLE = "billing_support_world_v0"
TICKET_ID = "tkt_a13e9e9d3d"


def test_two_remote_mcp_sessions_isolate_world_state(tmp_path: Path) -> None:
    service = _service(tmp_path, max_sessions=2)
    with TestClient(service) as client:
        first = _create_session(client)
        second = _create_session(client)
        first_mcp = _initialize_mcp(client, first)
        second_mcp = _initialize_mcp(client, second)

        closed = _call_gate(
            client,
            first,
            first_mcp,
            method="POST",
            path=f"/support/tickets/{TICKET_ID}/close",
        )
        assert closed["body"]["data"]["status"] == "solved"

        first_ticket = _call_gate(
            client,
            first,
            first_mcp,
            method="GET",
            path=f"/support/tickets/{TICKET_ID}",
        )
        second_ticket = _call_gate(
            client,
            second,
            second_mcp,
            method="GET",
            path=f"/support/tickets/{TICKET_ID}",
        )

        assert first_ticket["body"]["data"]["status"] == "solved"
        assert second_ticket["body"]["data"]["status"] == "open"


def test_remote_service_rejects_missing_or_wrong_session_auth(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with TestClient(service) as client:
        session = _create_session(client)
        initialize = _initialize_payload()

        missing = client.post(
            session["mcp_url"],
            json=initialize,
            headers={"accept": "application/json, text/event-stream"},
        )
        wrong = client.post(
            session["mcp_url"],
            json=initialize,
            headers=_mcp_headers("wrong-token"),
        )
        finalize = client.post(f"/sessions/{session['session_id']}/finalize")
        disallowed = client.post("/sessions", json={"example": "lab_ops_stale_result"})
        invalid_host = client.post(
            session["mcp_url"],
            json=initialize,
            headers={**_mcp_headers(session["token"]), "host": "untrusted.example"},
        )

    for response in (missing, wrong, finalize):
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "remote_session_unauthorized"
    assert disallowed.status_code == 403
    assert disallowed.json()["error"]["code"] == "remote_example_not_allowed"
    assert invalid_host.status_code == 421


def test_remote_tool_catalog_does_not_expose_local_session_manifest(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with TestClient(service) as client:
        session = _create_session(client)
        mcp_session_id = _initialize_mcp(client, session)

        response = client.post(
            session["mcp_url"],
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers=_mcp_headers(session["token"], mcp_session_id),
        )
        assert response.status_code == 200
        tool_names = {tool["name"] for tool in _sse_json(response.text)["result"]["tools"]}

    assert "get_task" in tool_names
    assert "gate_request" in tool_names
    assert "get_session_manifest" not in tool_names


def test_finalize_returns_redacted_versioned_public_export(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with TestClient(service) as client:
        session = _create_session(client)
        mcp_session_id = _initialize_mcp(client, session)
        _call_gate(
            client,
            session,
            mcp_session_id,
            method="POST",
            path=f"/support/tickets/{TICKET_ID}/close",
        )

        response = client.post(
            f"/sessions/{session['session_id']}/finalize",
            headers=_auth_headers(session["token"]),
        )
        assert response.status_code == 200
        public_export = response.json()
        assert public_export["schema_version"] == PUBLIC_EXPORT_SCHEMA
        assert public_export["example"] == EXAMPLE
        assert public_export["verification"]["passed"] is False
        assert public_export["events"]
        assert (tmp_path / "runs" / session["session_id"] / "public_run_export.json").is_file()
        raw_export = json.loads(
            (tmp_path / "runs" / session["session_id"] / "run_export.json").read_text(
                encoding="utf-8"
            )
        )
        assert "shadow_state" in raw_export
        assert not (
            _private_keys(public_export)
            & {
                "state",
                "world_state",
                "faults",
                "scheduled_events",
                "hidden_verifier_inputs",
                "simulator_context",
                "shadow_state",
                "shadow_mutation",
            }
        )

        fetched = client.get(
            f"/sessions/{session['session_id']}/export",
            headers=_auth_headers(session["token"]),
        )
        assert fetched.status_code == 200
        assert fetched.json() == public_export

        mcp_after_finalize = client.post(
            session["mcp_url"],
            json=_initialize_payload(),
            headers=_mcp_headers(session["token"]),
        )
        assert mcp_after_finalize.status_code == 410
        assert mcp_after_finalize.json()["error"]["code"] == "remote_session_unavailable"


def test_max_sessions_and_ttl_cleanup(tmp_path: Path) -> None:
    runs_root = tmp_path / "runs"
    service = _service(
        tmp_path,
        max_sessions=1,
        ttl_seconds=0.08,
        cleanup_interval_seconds=0.01,
    )
    with TestClient(service) as client:
        first = _create_session(client)
        full = client.post("/sessions", json={"example": EXAMPLE})
        assert full.status_code == 429
        assert full.json()["error"]["code"] == "remote_session_capacity_reached"

        first_run = runs_root / first["session_id"]
        assert first_run.is_dir()
        deadline = time.monotonic() + 1.0
        while first_run.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not first_run.exists()

        expired = client.get(
            f"/sessions/{first['session_id']}/export",
            headers=_auth_headers(first["token"]),
        )
        assert expired.status_code == 404
        assert expired.json()["error"]["code"] == "remote_session_not_found"

        replacement = _create_session(client)
        assert replacement["session_id"] != first["session_id"]


def test_finalized_session_is_reclaimed_at_ttl(tmp_path: Path) -> None:
    runs_root = tmp_path / "runs"
    service = _service(
        tmp_path,
        ttl_seconds=0.08,
        cleanup_interval_seconds=0.01,
    )
    with TestClient(service) as client:
        session = _create_session(client)
        finalized = client.post(
            f"/sessions/{session['session_id']}/finalize",
            headers=_auth_headers(session["token"]),
        )
        assert finalized.status_code == 200

        run_dir = runs_root / session["session_id"]
        deadline = time.monotonic() + 1.0
        while run_dir.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not run_dir.exists()

        expired = client.get(
            f"/sessions/{session['session_id']}/export",
            headers=_auth_headers(session["token"]),
        )
        assert expired.status_code == 404
        assert expired.json()["error"]["code"] == "remote_session_not_found"


def test_remote_serve_cli_wires_fixed_limits_and_transport_allowlists(tmp_path: Path) -> None:
    args = _build_parser().parse_args(
        [
            "remote-serve",
            "--runs-root",
            str(tmp_path),
            "--allow-example",
            EXAMPLE,
            "--max-sessions",
            "3",
            "--ttl-seconds",
            "120",
            "--allowed-host",
            "localhost:*",
            "--allowed-origin",
            "https://example.test",
        ]
    )

    assert args.allow_example == [EXAMPLE]
    assert args.max_sessions == 3
    assert args.ttl_seconds == 120
    assert args.allowed_host == ["localhost:*"]
    assert args.allowed_origin == ["https://example.test"]
    assert not hasattr(args, "allow_live")


def test_public_export_preserves_world_checks_and_bundle_reference(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "task.json").write_text(
        json.dumps(
            {
                "task_id": "task-1",
                "title": "Run a science workflow",
                "instructions": "Run the workflow.",
                "success_criteria": ["The current result is recorded."],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "run_export.json").write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "created_at": "2026-07-26T00:00:00+00:00",
                "events": [_public_http_event()],
                "shadow_state": {"secret": True},
                "world": {
                    "schema_version": "datalox_world_run_v1",
                    "world_id": "science_world_v0",
                    "episode_id": "episode-1",
                    "bundle": {
                        "schema_version": "datalox_world_bundle_ref_v1",
                        "world_id": "science_world_v0",
                        "bundle_version": "0.1.0",
                        "episode_id": "episode-1",
                        "manifest_digest": "sha256:" + "a" * 64,
                    },
                    "state": {"hidden": True},
                },
            }
        ),
        encoding="utf-8",
    )
    world_verifier = {
        "passed": False,
        "verifier_type": "science_world_v0",
        "checks": [
            {
                "code": "science.current_result",
                "passed": False,
                "evidence_refs": ["public_evidence:#/result/job_id"],
            }
        ],
        "failure_codes": ["science.current_result"],
        "reward": 0.25,
        "reward_atoms": [
            {
                "id": "science.current_result",
                "earned": False,
                "weight": 0.75,
            }
        ],
        "public_evidence": {
            "schema_version": "science_public_evidence_v1",
            "result": {"job_id": "job-1"},
        },
    }
    audit = {
        "passed": False,
        "verifier_type": "combined_post_run_audit",
        "checks": {"no_missed_calls": True, "world.science_world_v0.science.current_result": False},
        "failure_codes": ["world.science_world_v0.science.current_result"],
        "verifiers": {
            "config": {
                "passed": True,
                "verifier_type": "config_post_run_audit",
                "checks": {"no_missed_calls": True},
                "failure_codes": [],
            },
            "world": world_verifier,
        },
    }

    public_export = build_public_run_export(run_dir, "science_world_v0", audit)

    assert public_export["world"]["bundle"]["manifest_digest"] == "sha256:" + "a" * 64
    assert (
        public_export["verification"]["checks"]["world.science_world_v0.science.current_result"]
        is False
    )
    assert public_export["verification"]["verifiers"]["world"] == world_verifier
    assert "shadow_mutation" not in public_export["events"][0]
    assert "state" not in public_export["world"]


def test_public_export_rejects_machine_paths_and_unknown_event_fields(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    task = {
        "task_id": "task-1",
        "title": "Task",
        "instructions": "Read /private/alice/private.json.",
        "success_criteria": ["Complete."],
    }
    (run_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
    (run_dir / "run_export.json").write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "created_at": "2026-07-26T00:00:00+00:00",
                "events": [],
                "shadow_state": {},
            }
        ),
        encoding="utf-8",
    )
    audit = {
        "passed": True,
        "verifier_type": "config_post_run_audit",
        "checks": {"no_missed_calls": True},
        "failure_codes": [],
    }

    with pytest.raises(ValueError, match="machine-local path"):
        build_public_run_export(run_dir, EXAMPLE, audit)

    task["instructions"] = "Complete the task."
    (run_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
    export = json.loads((run_dir / "run_export.json").read_text(encoding="utf-8"))
    export["events"] = [
        {
            **_public_http_event(),
            "initial_state": {"secret": True},
        }
    ]
    (run_dir / "run_export.json").write_text(json.dumps(export), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        build_public_run_export(run_dir, EXAMPLE, audit)


def test_combined_audit_accepts_code_passed_world_check_contract() -> None:
    combined = _combined_audit_payload(
        config_payload={
            "passed": True,
            "checks": {"no_missed_calls": True},
            "failure_codes": [],
        },
        world_payload={
            "passed": False,
            "checks": [{"code": "science.current_result", "passed": False}],
            "failure_codes": ["science.current_result"],
        },
        world_id="science_world_v0",
    )

    assert combined["checks"]["world.science_world_v0.science.current_result"] is False
    assert "world.science_world_v0.science.current_result" in combined["failure_codes"]


def test_mcp_request_does_not_hold_lifecycle_lock_while_stream_is_open(tmp_path: Path) -> None:
    async def scenario() -> None:
        service = _service(tmp_path)
        started = asyncio.Event()
        release = asyncio.Event()

        async def app(scope, receive, send) -> None:
            started.set()
            await release.wait()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        class Lifespan:
            async def close(self) -> None:
                release.set()

        session = _RemoteSession(
            session_id="session-1",
            token="token-1",
            example=EXAMPLE,
            run_dir=tmp_path / "run",
            expires_at=time.monotonic() + 30,
            mcp_app=app,
            mcp_lifespan=Lifespan(),  # type: ignore[arg-type]
        )
        service._sessions[session.session_id] = session
        sent: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/sessions/session-1/mcp",
            "raw_path": b"/sessions/session-1/mcp",
            "root_path": "",
            "headers": [(b"authorization", b"Bearer token-1")],
        }
        request = asyncio.create_task(
            service._dispatch_mcp(session.session_id, scope, receive, send)  # type: ignore[arg-type]
        )
        await started.wait()

        assert session.active_requests == 1
        assert session.operation_lock.locked() is False

        await session.mcp_lifespan.close()
        await request
        assert session.active_requests == 0
        assert session.requests_idle.is_set()
        assert sent[-1]["type"] == "http.response.body"

    asyncio.run(scenario())


def _service(
    tmp_path: Path,
    *,
    max_sessions: int = 2,
    ttl_seconds: float = 30.0,
    cleanup_interval_seconds: float = 0.1,
):
    return create_remote_world_app(
        runs_root=tmp_path / "runs",
        allowed_examples={EXAMPLE},
        max_sessions=max_sessions,
        ttl_seconds=ttl_seconds,
        cleanup_interval_seconds=cleanup_interval_seconds,
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )


def _public_http_event() -> dict[str, Any]:
    return {
        "surface": "http",
        "event_id": "event-1",
        "created_at": "2026-07-26T00:00:01+00:00",
        "request": {
            "method": "POST",
            "path": "/science/runs",
            "query": {},
            "body": {"plate": "P-1"},
            "headers": {"authorization": "[REDACTED]"},
            "operation_id": "science.start_run",
        },
        "decision": {
            "kind": "shadow_write",
            "reason_code": "science_run_started",
            "message": "science_run_started",
            "rule_id": None,
        },
        "response_status_code": 202,
        "response_body": {"job_id": "job-1"},
        "response_case_id": None,
        "shadow_mutation": {"initial_state": {"secret": True}},
    }


def _create_session(client: TestClient) -> dict[str, Any]:
    response = client.post("/sessions", json={"example": EXAMPLE})
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["live_mode"] is False
    assert payload["session_id"].startswith("rws_")
    assert payload["token"]
    return payload


def _initialize_mcp(client: TestClient, session: dict[str, Any]) -> str:
    response = client.post(
        session["mcp_url"],
        json=_initialize_payload(),
        headers=_mcp_headers(session["token"]),
    )
    assert response.status_code == 200, response.text
    message = _sse_json(response.text)
    assert message["result"]["protocolVersion"]
    mcp_session_id = response.headers.get("mcp-session-id")
    assert mcp_session_id

    initialized = client.post(
        session["mcp_url"],
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=_mcp_headers(session["token"], mcp_session_id),
    )
    assert initialized.status_code in {200, 202}
    return mcp_session_id


def _call_gate(
    client: TestClient,
    session: dict[str, Any],
    mcp_session_id: str,
    *,
    method: str,
    path: str,
) -> dict[str, Any]:
    response = client.post(
        session["mcp_url"],
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "gate_request",
                "arguments": {"method": method, "path": path},
            },
        },
        headers=_mcp_headers(session["token"], mcp_session_id),
    )
    assert response.status_code == 200, response.text
    message = _sse_json(response.text)
    assert "error" not in message
    result = message["result"]
    if isinstance(result.get("structuredContent"), dict):
        structured = result["structuredContent"]
        if isinstance(structured.get("result"), dict):
            return structured["result"]
        return structured
    content = result["content"]
    return json.loads(content[0]["text"])


def _initialize_payload() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "datalox-test", "version": "1"},
        },
    }


def _auth_headers(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def _mcp_headers(token: str, mcp_session_id: str | None = None) -> dict[str, str]:
    headers = {
        **_auth_headers(token),
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
    }
    if mcp_session_id is not None:
        headers["mcp-session-id"] = mcp_session_id
    return headers


def _sse_json(body: str) -> dict[str, Any]:
    for line in body.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[6:])
            if isinstance(payload, dict):
                return payload
    raise AssertionError(f"No JSON SSE event found: {body}")


def _private_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {nested for item in value.values() for nested in _private_keys(item)}
    if isinstance(value, list):
        return {nested for item in value for nested in _private_keys(item)}
    return set()
