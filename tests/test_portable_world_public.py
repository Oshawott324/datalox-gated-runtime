from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any

from fastapi.testclient import TestClient
from mcp.types import LATEST_PROTOCOL_VERSION
import pytest

from datalox_gated_runtime.harness_adapters import (
    build_harbor_adapter,
    build_hud_adapter,
)
from datalox_gated_runtime.world_package import build_world_package
from datalox_gated_runtime.world_package.entrypoint import (
    create_packaged_world_app,
    finalize_packaged_world,
)
from datalox_gated_runtime.world_v1.admission import (
    admit_world,
    write_admission_artifact,
)
from datalox_gated_runtime.world_v1.admission_runtime import runtime_admission_callbacks


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_WORLD = ROOT / "envs" / "commerce_support_ops_v0"


@pytest.fixture
def admitted_public_world(tmp_path: Path) -> Path:
    destination = tmp_path / "commerce-world"
    shutil.copytree(
        PUBLIC_WORLD,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    report = admit_world(destination, callbacks=runtime_admission_callbacks())
    assert report.admitted, report.to_dict()
    write_admission_artifact(report)
    return destination


def test_public_world_builds_one_gated_package_and_thin_harness_adapters(
    admitted_public_world: Path,
    tmp_path: Path,
) -> None:
    package_dir = tmp_path / "package"
    package = build_world_package(
        env_dir=admitted_public_world,
        out_dir=package_dir,
        project_root=ROOT,
    )
    run_dir = tmp_path / "run"
    app = create_packaged_world_app(
        package_root=package_dir,
        environ={"DATALOX_ALLOWED_HOSTS": "testserver"},
        run_dir=run_dir,
    )

    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["world_id"] == "commerce_support_ops_v0"
        assert client.post("/sessions").status_code == 404
        initialized = client.post(
            "/mcp",
            headers=_mcp_headers(),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": LATEST_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "public-package-test", "version": "1"},
                },
            },
        )
        assert initialized.status_code == 200, initialized.text
        tools = client.post(
            "/mcp",
            headers=_mcp_headers(initialized.headers["mcp-session-id"]),
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        names = {tool["name"] for tool in _sse_json(tools.text)["result"]["tools"]}
        assert {"get_task", "gate_request", "commerce.list_orders"} <= names
        assert "get_session_manifest" not in names

    verdict = finalize_packaged_world(
        package_root=package_dir,
        run_dir=run_dir,
        out_path=tmp_path / "verdict.json",
    )
    assert verdict["package_content_sha256"] == package["package_content_sha256"]
    assert verdict["world_id"] == "commerce_support_ops_v0"

    hud = build_hud_adapter(
        env_dir=admitted_public_world,
        out_dir=tmp_path / "hud",
        project_root=ROOT,
    )
    harbor = build_harbor_adapter(
        env_dir=admitted_public_world,
        out_dir=tmp_path / "harbor",
        project_root=ROOT,
    )
    assert hud["canonical_package"]["package_content_sha256"] == package["package_content_sha256"]
    assert (
        harbor["canonical_package"]["package_content_sha256"] == package["package_content_sha256"]
    )


def _mcp_headers(session_id: str | None = None) -> dict[str, str]:
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
    }
    if session_id is not None:
        headers["mcp-session-id"] = session_id
    return headers


def _sse_json(body: str) -> dict[str, Any]:
    for line in body.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[6:])
            if isinstance(payload, dict):
                return payload
    raise AssertionError(f"No JSON SSE event found: {body}")
