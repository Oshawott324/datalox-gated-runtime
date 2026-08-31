import json
from dataclasses import dataclass, field

from fastapi.testclient import TestClient

from datalox_gated_runtime.data_plane import ProviderBinding, create_data_plane_app
from datalox_gated_runtime.models import CallRequest, GateDecision, GateResponse


@dataclass
class RecordingProvider:
    requests: list[CallRequest] = field(default_factory=list)

    def handle(self, request: CallRequest) -> GateResponse:
        self.requests.append(request)
        if request.path == "/_datalox/health":
            return self._response(404, {"error": {"type": "resource_missing"}})
        return self._response(
            201,
            {"id": "cus_local", "name": (request.body or {}).get("name")},
            headers={"request-id": "req_local"},
        )

    @staticmethod
    def _response(
        status: int, body: dict, *, headers: dict[str, str] | None = None
    ) -> GateResponse:
        return GateResponse(
            status_code=status,
            body=body,
            decision=GateDecision(
                kind="shadow_write",
                reason_code="local_transition",
                message="local",
            ),
            event_id="evt_control_only",
            headers=headers or {},
        )


def test_data_plane_routes_unchanged_provider_authority_and_form_body() -> None:
    provider = RecordingProvider()
    app = create_data_plane_app({"api.stripe.com": ProviderBinding(provider)})

    with TestClient(app, base_url="https://api.stripe.com") as client:
        response = client.post(
            "/v1/customers?expand%5B%5D=invoice",
            content="name=Unmodified+SDK",
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "authorization": "Bearer sk_test_agent_visible",
            },
        )

    assert response.status_code == 201
    assert response.json() == {"id": "cus_local", "name": "Unmodified SDK"}
    assert response.headers["request-id"] == "req_local"
    assert not any(name.startswith("x-datalox") for name in response.headers)
    assert provider.requests[0].authority == "api.stripe.com"
    assert provider.requests[0].path == "/v1/customers"
    assert provider.requests[0].query == {"expand[]": "invoice"}


def test_data_plane_fails_closed_for_unknown_authority() -> None:
    provider = RecordingProvider()
    app = create_data_plane_app({"api.stripe.com": ProviderBinding(provider)})

    with TestClient(app, base_url="https://api.other.example") as client:
        response = client.get("/v1/customers")

    assert response.status_code == 421
    assert response.json()["error"]["code"] == "authority_not_configured"
    assert provider.requests == []


def test_data_plane_does_not_expose_control_routes_on_provider_authority() -> None:
    provider = RecordingProvider()
    app = create_data_plane_app({"api.stripe.com": ProviderBinding(provider)})

    with TestClient(app, base_url="https://api.stripe.com") as client:
        response = client.get("/_datalox/health")

    assert response.status_code == 404
    assert json.loads(response.content) == {"error": {"type": "resource_missing"}}
    assert provider.requests[0].path == "/_datalox/health"
