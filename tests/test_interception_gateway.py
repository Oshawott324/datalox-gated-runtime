from pathlib import Path

from fastapi.testclient import TestClient
from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    PROVIDER_ID,
    build_stateful_provider_bundle,
)

from datalox_gated_runtime.interception.gateway import InterceptionGateway


def _gateway(tmp_path: Path) -> InterceptionGateway:
    bundle = build_stateful_provider_bundle(tmp_path)
    return InterceptionGateway.from_bundles(
        bundle_dirs=(bundle,),
        run_root=tmp_path / "runs",
        control_token="controller-secret",
    )


def test_gateway_data_plane_uses_exact_url_and_control_plane_resets_state(
    tmp_path: Path,
) -> None:
    gateway = _gateway(tmp_path)
    headers = {"x-datalox-control-token": "controller-secret"}
    try:
        with TestClient(gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as agent:
            created = agent.post(
                "/counter",
                json={"amount": 2},
                headers={"authorization": "Bearer simulated-provider-token"},
            )
            assert created.status_code == 200
            assert created.json()["counter"] == 3
            readback = agent.get("/counter")
            assert readback.status_code == 200
            assert readback.json()["counter"] == 3
            assert "x-datalox-event-id" not in created.headers

            provider_control_probe = agent.get("/_datalox/health")
            assert provider_control_probe.status_code == 404

        with TestClient(gateway.control_app) as controller:
            assert controller.get("/health").status_code == 401
            exported = controller.get(f"/v1/providers/{PROVIDER_ID}/export", headers=headers).json()
            assert exported["call_evidence"]["events"]
            assert "authorization" not in {
                name.lower()
                for name in exported["call_evidence"]["events"][0]["request"]["headers"]
            }
            reset = controller.post(f"/v1/providers/{PROVIDER_ID}/reset", headers=headers).json()
            assert reset["call_evidence"]["events"] == []

        with TestClient(gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as agent:
            after_reset = agent.get("/counter")
            assert after_reset.status_code == 200
            assert after_reset.json()["counter"] == 1
    finally:
        gateway.close()
