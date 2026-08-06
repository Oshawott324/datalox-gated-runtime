import json
from pathlib import Path

from fastapi.testclient import TestClient

from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.session import create_session


def test_http_get_replays_captured_labstep_experiment(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get("/labstep/experiments/exp_current")

    assert response.status_code == 200
    assert response.json()["id"] == "exp_current"
    assert "body_sha256" not in response.json()
    assert response.headers["x-datalox-decision"] == "replay"
    assert response.headers["x-datalox-response-case-id"] == "labstep_exp_current"


def test_http_post_shadow_writes_benchling_assay_results(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.post(
            "/benchling/assay-results",
            json={
                "experiment_id": "exp_current",
                "source_result_id": "result_current",
                "value": 0.82,
            },
        )

    assert response.status_code == 202
    assert response.json()["mode"] == "shadow_write"
    assert response.headers["x-datalox-decision"] == "shadow_write"
    assert response.headers.get("x-datalox-response-case-id") is None
    assert "x-datalox-event-id" in response.headers


def test_http_post_denies_robot_live_action(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.post("/robot/move")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "live_action_not_allowed"
    assert response.headers["x-datalox-decision"] == "deny"


def test_http_post_rejects_invalid_json_body(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.post(
            "/benchling/assay-results",
            content='{"bad_json": ',
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_json_body"


def test_http_post_empty_json_body_is_accepted(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.post(
            "/benchling/assay-results",
            content="",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 202
    assert response.json()["mode"] == "shadow_write"


def test_http_post_rejects_invalid_text_body_when_non_json(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.post(
            "/benchling/assay-results",
            content=b"\xff\xfe",
            headers={"content-type": "text/plain"},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_text_body"


def test_http_server_writes_events_to_ledger(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        client.get("/labstep/experiments/exp_current")
        client.post("/benchling/assay-results")
        client.post("/robot/move")

    ledger_path = run_dir / "ledger.jsonl"
    assert ledger_path.exists()

    rows = [
        json.loads(line)
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 3
    assert rows[0]["request"]["method"] == "GET"
    assert rows[0]["request"]["path"] == "/labstep/experiments/exp_current"
    assert rows[1]["request"]["method"] == "POST"
    assert rows[1]["request"]["path"] == "/benchling/assay-results"
    assert rows[1]["decision"]["kind"] == "shadow_write"
    assert rows[2]["request"]["method"] == "POST"
    assert rows[2]["request"]["path"] == "/robot/move"
    assert rows[2]["decision"]["kind"] == "deny"


def test_health_endpoint_reports_config_id(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get("/_datalox/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True, "config_id": "lab_ops_stale_result_v0", "live": False}
