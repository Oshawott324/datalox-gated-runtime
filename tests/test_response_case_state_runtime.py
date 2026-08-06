from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.mcp_server import _build_low_level_components, build_server
from response_case_state_helpers import configure_assignee_lookup, create_world_session


def _body_digest(body: object) -> str:
    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _fastmcp_payload(server, name: str, arguments: dict) -> dict:
    result = asyncio.run(server.call_tool(name, arguments))
    assert isinstance(result, list)
    assert len(result) == 1
    return json.loads(result[0].text)


def _use_fastmcp(run_dir: Path) -> None:
    config_path = run_dir / "gate_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.pop("mcp")
    config_path.write_text(json.dumps(config), encoding="utf-8")


def test_named_world_fastmcp_success_has_matching_body_digest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    _use_fastmcp(run_dir)
    server = build_server(run_dir)

    payload = _fastmcp_payload(
        server,
        "world.get_incident",
        {"incident_id": "inc-001"},
    )

    assert payload["status_code"] == 200
    assert payload["body_sha256"] == _body_digest(payload["body"])


def test_named_world_low_level_success_has_matching_structured_digest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    _, registry = _build_low_level_components(run_dir)

    result = asyncio.run(
        registry.call_tool(
            "world.get_incident",
            {"incident_id": "inc-001"},
        )
    )
    text = json.loads(result.content[0].text)

    assert result.structuredContent == text
    assert text["status_code"] == 200
    assert text["body_sha256"] == _body_digest(text["body"])


def test_named_world_low_level_argument_denial_has_matching_structured_digest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    _, registry = _build_low_level_components(run_dir)

    result = asyncio.run(
        registry.call_tool(
            "world.get_incident",
            {"incident_id": ["not", "a", "string"]},
        )
    )
    text = json.loads(result.content[0].text)

    assert result.structuredContent == text
    assert text["status_code"] == 400
    assert text["decision"]["kind"] == "deny"
    assert text["body"]["error"]["code"] == "invalid_world_request"
    assert text["body_sha256"] == _body_digest(text["body"])


def test_reset_determinism_and_integer_seed_selection(tmp_path: Path, monkeypatch) -> None:
    first = create_world_session(tmp_path, monkeypatch, name="first", seed=0)
    second = create_world_session(tmp_path, monkeypatch, name="second", seed=0)
    alternate = create_world_session(tmp_path, monkeypatch, name="alternate", seed=1)

    assert _read(first, "/incidents/inc-001")["data"]["id"] == "inc-001"
    assert _read(second, "/incidents/inc-001") == _read(first, "/incidents/inc-001")
    assert _read(alternate, "/incidents/inc-002")["data"]["id"] == "inc-002"
    first_task = json.loads((first / "task.json").read_text(encoding="utf-8"))
    alternate_task = json.loads((alternate / "task.json").read_text(encoding="utf-8"))
    assert first_task["task_id"] == "episode-task-0"
    assert alternate_task["task_id"] == "episode-task-1"
    assert first_task != alternate_task


def test_session_contains_no_world_source_artifacts_or_hidden_expected_payload(
    tmp_path: Path, monkeypatch
) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    source_names = {
        "episodes.jsonl",
        "routes.json",
        "transitions.json",
        "verifier.json",
        "tool_catalog.json",
        "sources.json",
    }

    assert not any(path.name in source_names for path in run_dir.rglob("*"))
    task = json.loads((run_dir / "task.json").read_text(encoding="utf-8"))
    assert set(task) == {"task_id", "title", "instructions", "success_criteria"}
    visible_json = "\n".join(path.read_text(encoding="utf-8") for path in run_dir.rglob("*.json"))
    assert '"expected"' not in visible_json
    assert _read(run_dir, "/incidents/inc-001")["data"]["status"] == "investigating"


def test_read_write_read_and_all_transition_operators(tmp_path: Path, monkeypatch) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    with TestClient(create_app(run_dir)) as client:
        wrong_query = client.get("/incidents/inc-001")
        assert wrong_query.status_code == 404
        assert wrong_query.headers["x-datalox-decision"] == "miss"
        original = client.get("/incidents/inc-001", params={"view": "full"}).json()
        assert original == {
            "data": {
                "id": "inc-001",
                "status": "investigating",
                "assignee": "unassigned",
                "notes": [],
            }
        }
        assign = client.patch("/incidents/inc-001/assign", json={"assignee": "owner@example.test"})
        assert assign.status_code == 201
        note = client.post("/incidents/inc-001/notes", json={"note": "Customer impact confirmed."})
        assert note.status_code == 201
        evidence = client.post("/tickets/ticket-001/evidence/fresh", json={})
        assert evidence.status_code == 204
        assert evidence.content == b""
        client.post("/tickets/ticket-001/copy-assignee", json={})

        incident = client.get("/incidents/inc-001", params={"view": "full"}).json()
        ticket = _state(run_dir, "customer_ticket")

    assert incident["data"]["assignee"] == "owner@example.test"
    assert incident["data"]["notes"] == ["Customer impact confirmed."]
    assert ticket["ticket"]["evidence"]["fresh"] is True
    assert ticket["ticket"]["owner"] == "owner@example.test"


def test_atomic_failure_rolls_back_state_and_world_event(tmp_path: Path, monkeypatch) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    before = _state(run_dir, "incident")
    before_events = _world_event_count(run_dir)

    with TestClient(create_app(run_dir)) as client:
        response = client.post("/incidents/inc-001/atomic-failure", json={})

    assert response.status_code == 400
    assert response.headers["x-datalox-decision"] == "deny"
    assert response.json()["error"]["code"] == "request_value_missing"
    assert _state(run_dir, "incident") == before
    assert _world_event_count(run_dir) == before_events
    ledger = _ledger(run_dir)
    assert ledger[-1]["shadow_mutation"] is None


def test_state_lookup_projects_visible_reference_value(tmp_path: Path, monkeypatch) -> None:
    run_dir = create_world_session(
        tmp_path,
        monkeypatch,
        configure_example=configure_assignee_lookup,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.patch(
            "/incidents/inc-001/assign",
            json={"assignee": "owner@example.test"},
        )

    assert response.status_code == 201
    assert response.json()["data"]["assignee"] == "owner@example.test"
    assert _state(run_dir, "customer_ticket")["ticket"]["owner"] == (
        "Display for owner@example.test"
    )


def test_state_lookup_not_found_rolls_back_all_effects_and_event(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = create_world_session(
        tmp_path,
        monkeypatch,
        configure_example=configure_assignee_lookup,
    )
    before = _all_state(run_dir)
    before_events = _world_event_count(run_dir)

    with TestClient(create_app(run_dir)) as client:
        response = client.patch(
            "/incidents/inc-001/assign",
            json={"assignee": "unknown@example.test"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "state_lookup_not_found"
    assert _all_state(run_dir) == before
    assert _world_event_count(run_dir) == before_events
    assert _ledger(run_dir)[-1]["shadow_mutation"] is None


def test_state_lookup_runtime_ambiguity_rolls_back_all_effects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = create_world_session(
        tmp_path,
        monkeypatch,
        configure_example=configure_assignee_lookup,
    )
    directory = _state(run_dir, "assignee_directory")
    directory["items"].append(dict(directory["items"][0]))
    _write_state(run_dir, "assignee_directory", directory)
    before = _all_state(run_dir)

    with TestClient(create_app(run_dir)) as client:
        response = client.patch(
            "/incidents/inc-001/assign",
            json={"assignee": "owner@example.test"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "state_lookup_ambiguous"
    assert _all_state(run_dir) == before


def test_state_lookup_runtime_wrong_value_type_rolls_back_all_effects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = create_world_session(
        tmp_path,
        monkeypatch,
        configure_example=configure_assignee_lookup,
    )
    directory = _state(run_dir, "assignee_directory")
    directory["items"][0]["display"] = 7
    _write_state(run_dir, "assignee_directory", directory)
    before = _all_state(run_dir)

    with TestClient(create_app(run_dir)) as client:
        response = client.patch(
            "/incidents/inc-001/assign",
            json={"assignee": "owner@example.test"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "state_lookup_value_type_mismatch"
    assert _all_state(run_dir) == before


def test_denials_and_validation_do_not_mutate_or_attempt_egress(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    before = _all_state(run_dir)
    before_events = _world_event_count(run_dir)

    def fail_egress(*args, **kwargs):
        raise AssertionError("network egress attempted")

    monkeypatch.setattr("socket.create_connection", fail_egress)
    with TestClient(create_app(run_dir)) as client:
        send = client.post("/tickets/ticket-001/send", json={})
        resolve = client.post("/incidents/inc-001/resolve", json={})
        mismatch = client.patch(
            "/incidents/not-selected/assign", json={"assignee": "owner@example.test"}
        )
        undeclared = client.post("/incidents/inc-001/inferred-action", json={})

    assert send.status_code == resolve.status_code == 403
    assert send.json()["error"]["code"] == "external_send_denied"
    assert resolve.json()["error"]["code"] == "incident_resolve_denied"
    assert mismatch.json()["error"]["code"] == "world_path_parameter_mismatch"
    assert undeclared.json()["error"]["code"] == "world_route_not_declared"
    assert _all_state(run_dir) == before
    assert _world_event_count(run_dir) == before_events
    decisions = [event["decision"]["kind"] for event in _ledger(run_dir)]
    assert decisions == ["deny", "deny", "deny", "miss"]
    assert all(event["shadow_mutation"] is None for event in _ledger(run_dir))


def test_sessions_are_isolated(tmp_path: Path, monkeypatch) -> None:
    first = create_world_session(tmp_path, monkeypatch, name="first")
    second = create_world_session(tmp_path, monkeypatch, name="second")
    with TestClient(create_app(first)) as client:
        client.patch("/incidents/inc-001/assign", json={"assignee": "owner@example.test"})

    assert _read(first, "/incidents/inc-001")["data"]["assignee"] == "owner@example.test"
    assert _read(second, "/incidents/inc-001")["data"]["assignee"] == "unassigned"


def _read(run_dir: Path, path: str) -> dict:
    with TestClient(create_app(run_dir)) as client:
        response = client.get(path, params={"view": "full"})
        assert response.status_code == 200
        return response.json()


def _db_path(run_dir: Path) -> Path:
    return run_dir / "world" / "response_case_state_v0" / "state.sqlite"


def _state(run_dir: Path, state_key: str) -> dict:
    with sqlite3.connect(_db_path(run_dir)) as connection:
        row = connection.execute(
            "SELECT value_json FROM state_views WHERE state_key = ?", (state_key,)
        ).fetchone()
    assert row is not None
    return json.loads(row[0])


def _all_state(run_dir: Path) -> dict[str, object]:
    with sqlite3.connect(_db_path(run_dir)) as connection:
        return {
            row[0]: json.loads(row[1])
            for row in connection.execute(
                "SELECT state_key, value_json FROM state_views ORDER BY state_key"
            )
        }


def _write_state(run_dir: Path, state_key: str, value: object) -> None:
    with sqlite3.connect(_db_path(run_dir)) as connection:
        connection.execute(
            "UPDATE state_views SET value_json = ? WHERE state_key = ?",
            (json.dumps(value, sort_keys=True, separators=(",", ":")), state_key),
        )


def _world_event_count(run_dir: Path) -> int:
    with sqlite3.connect(_db_path(run_dir)) as connection:
        return connection.execute("SELECT COUNT(*) FROM world_events").fetchone()[0]


def _ledger(run_dir: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in (run_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    ]
