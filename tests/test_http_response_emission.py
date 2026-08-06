import json
from pathlib import Path

from fastapi.testclient import TestClient

from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.world_backend import WorldResponse


class _AdapterWorld:
    world_id = "adapter_test"

    def __init__(self) -> None:
        self.requests: list[CallRequest] = []

    def handle(self, request: CallRequest) -> WorldResponse:
        self.requests.append(request)
        if request.path == "/csv":
            return WorldResponse(
                status_code=200,
                body="document_number,title\n2026-001,Energy rule\n",
                is_mutation=False,
                headers={"content-type": "text/csv; charset=utf-8"},
            )
        if request.path == "/empty":
            return WorldResponse(status_code=204, body=None, is_mutation=False)
        if request.path == "/json-string":
            return WorldResponse(status_code=200, body="ok", is_mutation=False)
        return WorldResponse(
            status_code=200,
            body={"ok": True},
            is_mutation=False,
            headers={"content-type": "application/json"},
        )


def _write_config(run_dir: Path) -> None:
    run_dir.mkdir()
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "http_adapter_test",
                "response_cases": [],
                "audit_rules": [],
            }
        ),
        encoding="utf-8",
    )


def test_asgi_preserves_repeated_query_values_and_raw_csv(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    _write_config(run_dir)
    world = _AdapterWorld()
    monkeypatch.setattr(
        "datalox_gated_runtime.http_server.create_world_backend",
        lambda **_kwargs: world,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get(
            "/csv",
            params=[
                ("conditions[]", "climate"),
                ("conditions[]", "energy"),
                ("fields[]", "title"),
                ("page", "2"),
            ],
        )

    assert world.requests[0].query == {
        "conditions[]": ("climate", "energy"),
        "fields[]": "title",
        "page": "2",
    }
    assert response.status_code == 200
    assert response.content == b"document_number,title\n2026-001,Energy rule\n"
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.headers["x-datalox-decision"] == "replay"


def test_asgi_keeps_json_scalar_and_204_behavior(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    _write_config(run_dir)
    world = _AdapterWorld()
    monkeypatch.setattr(
        "datalox_gated_runtime.http_server.create_world_backend",
        lambda **_kwargs: world,
    )

    with TestClient(create_app(run_dir)) as client:
        json_response = client.get("/json")
        scalar_response = client.get("/json-string")
        empty_response = client.get("/empty")

    assert json_response.content == b'{"ok":true}'
    assert json_response.headers["content-type"] == "application/json"
    assert scalar_response.content == b'"ok"'
    assert scalar_response.headers["content-type"] == "application/json"
    assert empty_response.status_code == 204
    assert empty_response.content == b""
