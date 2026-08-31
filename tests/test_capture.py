import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from datalox_gated_runtime.authoring_runtime import AuthoringGatedRuntime
from datalox_gated_runtime.capture import (
    CaptureStore,
    LiveCaptureClient,
    load_captures,
)
from datalox_gated_runtime.cli import _serve
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.models import (
    CallRequest,
    LiveAuthHeader,
    LiveGateConfig,
    LiveUpstream,
    PolicyConfig,
    RouteRule,
)
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.runtime import GatedRuntime


def _write_gate_config(tmp_path: Path, raw: dict) -> Path:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(json.dumps(raw), encoding="utf-8")
    return config_path


def _base_config(*, policy: dict | None = None, live: dict | None = None) -> dict:
    raw = {
        "config_id": "capture_test",
        "response_cases": [],
        "audit_rules": [],
    }
    if policy is not None:
        raw["policy"] = policy
    if live is not None:
        raw["live"] = live
    return raw


def test_live_get_is_captured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_GH_TOKEN", "tok-123")
    upstream_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(
            200,
            json={"full_name": "o/r"},
            headers={"content-type": "application/json"},
        )

    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/github/", method="GET")]),
        allow_live=True,
    )
    capture_store = CaptureStore(tmp_path / "captures.jsonl")
    runtime = AuthoringGatedRuntime(
        policy=policy,
        capture_client=LiveCaptureClient(
            LiveGateConfig(
                upstreams={
                    "github": LiveUpstream(
                        base_url="https://api.github.test",
                        auth_env="TEST_GH_TOKEN",
                    )
                }
            ),
            transport=httpx.MockTransport(handler),
        ),
        capture_store=capture_store,
    )

    response = runtime.handle(
        CallRequest(
            method="GET",
            path="/github/repos/o/r",
            query={"per_page": "5"},
            headers={"authorization": "Bearer agent-secret"},
        )
    )

    assert response.status_code == 200
    assert response.body == {"full_name": "o/r"}
    assert response.decision.kind == "live_capture"
    assert len(upstream_requests) == 1
    upstream_request = upstream_requests[0]
    assert str(upstream_request.url) == "https://api.github.test/repos/o/r?per_page=5"
    assert upstream_request.headers["authorization"] == "Bearer tok-123"
    assert "agent-secret" not in str(upstream_request.headers)

    captures = load_captures(tmp_path / "captures.jsonl")
    assert len(captures) == 1
    captured = captures[0]
    assert captured.method == "GET"
    assert captured.path == "/github/repos/o/r"
    assert captured.query == {"per_page": "5"}
    assert captured.status_code == 200
    assert captured.body == {"full_name": "o/r"}
    assert captured.evidence_ref is not None
    assert captured.evidence_ref.startswith("live:github:")
    assert response.response_case_id == captured.case_id


def test_live_get_forwards_and_captures_repeated_query_values(tmp_path: Path) -> None:
    upstream_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"count": 2})

    runtime = AuthoringGatedRuntime(
        policy=GatePolicy.from_config(
            PolicyConfig(live_capture=[RouteRule(path_prefix="/records/", method="GET")]),
            allow_live=True,
        ),
        capture_client=LiveCaptureClient(
            LiveGateConfig(upstreams={"records": LiveUpstream(base_url="https://records.test")}),
            transport=httpx.MockTransport(handler),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(
        CallRequest(
            method="GET",
            path="/records/documents",
            query={
                "conditions[]": ["climate", "energy"],
                "fields[]": ["title"],
                "page": "2",
            },
        )
    )

    assert response.status_code == 200
    assert upstream_requests[0].url.params.multi_items() == [
        ("conditions[]", "climate"),
        ("conditions[]", "energy"),
        ("fields[]", "title"),
        ("page", "2"),
    ]
    assert load_captures(tmp_path / "captures.jsonl")[0].query == {
        "conditions[]": ("climate", "energy"),
        "fields[]": "title",
        "page": "2",
    }


def test_live_capture_preserves_upstream_trailing_slash(tmp_path: Path) -> None:
    upstream_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200, json={"ok": True})

    runtime = AuthoringGatedRuntime(
        policy=GatePolicy.from_config(
            PolicyConfig(
                live_capture=[
                    RouteRule(path_prefix="/woocommerce/wp-json/", method="GET", exact=True)
                ]
            ),
            allow_live=True,
        ),
        capture_client=LiveCaptureClient(
            LiveGateConfig(upstreams={"woocommerce": LiveUpstream(base_url="https://woo.test")}),
            transport=httpx.MockTransport(handler),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(CallRequest(method="GET", path="/woocommerce/wp-json/"))

    assert response.status_code == 200
    assert str(upstream_requests[0].url) == "https://woo.test/wp-json/"


def test_missing_auth_env_fails_at_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_GH_TOKEN", raising=False)

    with pytest.raises(ValueError, match="TEST_GH_TOKEN"):
        LiveCaptureClient(
            LiveGateConfig(
                upstreams={
                    "github": LiveUpstream(
                        base_url="https://api.github.test",
                        auth_env="TEST_GH_TOKEN",
                    )
                }
            )
        )


def test_unknown_upstream_segment_returns_structured_error(tmp_path: Path) -> None:
    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/gitlab/", method="GET")]),
        allow_live=True,
    )
    runtime = AuthoringGatedRuntime(
        policy=policy,
        capture_client=LiveCaptureClient(
            LiveGateConfig(upstreams={"github": LiveUpstream(base_url="https://api.github.test")}),
            transport=httpx.MockTransport(lambda request: httpx.Response(500)),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(CallRequest(method="GET", path="/gitlab/projects/1"))

    assert response.status_code == 502
    assert response.decision.kind == "deny"
    assert response.body["error"]["code"] == "live_upstream_not_configured"
    assert not (tmp_path / "captures.jsonl").exists()


def test_live_invalid_json_response_records_structured_error(tmp_path: Path) -> None:
    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/github/", method="GET")]),
        allow_live=True,
    )
    runtime = AuthoringGatedRuntime(
        policy=policy,
        capture_client=LiveCaptureClient(
            LiveGateConfig(upstreams={"github": LiveUpstream(base_url="https://api.github.test")}),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    content=b"{",
                    headers={"content-type": "application/json"},
                )
            ),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(CallRequest(method="GET", path="/github/repos/o/r"))

    assert response.status_code == 502
    assert response.decision.kind == "deny"
    assert response.body["error"]["code"] == "live_upstream_invalid_response"
    assert len(runtime.ledger.events) == 1
    event = runtime.ledger.events[0]
    assert event.decision.kind == "deny"
    assert event.response_status_code == 502
    assert event.response_body == response.body
    assert not (tmp_path / "captures.jsonl").exists()


def test_live_capture_store_failure_records_structured_error() -> None:
    class FailingCaptureStore:
        def append(self, response_case) -> None:
            raise OSError("disk full")

    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/github/", method="GET")]),
        allow_live=True,
    )
    runtime = AuthoringGatedRuntime(
        policy=policy,
        capture_client=LiveCaptureClient(
            LiveGateConfig(upstreams={"github": LiveUpstream(base_url="https://api.github.test")}),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    json={"full_name": "o/r"},
                    headers={"content-type": "application/json"},
                )
            ),
        ),
        capture_store=FailingCaptureStore(),
    )

    response = runtime.handle(CallRequest(method="GET", path="/github/repos/o/r"))

    assert response.status_code == 502
    assert response.decision.kind == "deny"
    assert response.body["error"]["code"] == "live_capture_store_failed"
    assert len(runtime.ledger.events) == 1
    event = runtime.ledger.events[0]
    assert event.decision.kind == "deny"
    assert event.response_status_code == 502
    assert event.response_body == response.body


def test_live_decision_without_client_is_structured_error() -> None:
    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/github/", method="GET")]),
        allow_live=True,
    )
    runtime = GatedRuntime(policy=policy)

    response = runtime.handle(CallRequest(method="GET", path="/github/repos/o/r"))

    assert response.status_code == 403
    assert response.decision.kind == "deny"
    assert response.body["error"]["code"] == "provider_access_forbidden"


def test_allow_live_false_does_not_capture(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("transport should not be called")

    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/github/", method="GET")]),
        allow_live=False,
    )
    runtime = AuthoringGatedRuntime(
        policy=policy,
        capture_client=LiveCaptureClient(
            LiveGateConfig(upstreams={"github": LiveUpstream(base_url="https://api.github.test")}),
            transport=httpx.MockTransport(handler),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(CallRequest(method="GET", path="/github/repos/o/r"))

    assert response.status_code == 404
    assert response.decision.kind == "miss"
    assert not (tmp_path / "captures.jsonl").exists()


def test_execution_http_app_has_no_live_provider_option(tmp_path: Path) -> None:
    _write_gate_config(
        tmp_path,
        _base_config(policy={"live_capture": [{"path_prefix": "/github/"}]}),
    )

    with pytest.raises(TypeError, match="unexpected keyword argument 'allow_live'"):
        create_app(tmp_path, allow_live=True)


def test_execution_http_app_ignores_authoring_config_and_stays_offline(tmp_path: Path) -> None:
    _write_gate_config(
        tmp_path,
        _base_config(
            policy={"live_capture": [{"path_prefix": "/gitlab/"}]},
            live={"upstreams": {"github": {"base_url": "https://api.github.test"}}},
        ),
    )

    with TestClient(create_app(tmp_path)) as client:
        response = client.get("/gitlab/projects/1")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "provider_access_forbidden"


def test_serve_constructs_provider_offline_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, object] = {}

    def fake_create_app(run_dir: Path, *, server_token: str | None = None):
        observed["run_dir"] = run_dir
        observed["server_token"] = server_token
        return object()

    def fake_run(app, *, host: str, port: int) -> None:
        observed["app"] = app
        observed["host"] = host
        observed["port"] = port

    monkeypatch.setattr("datalox_gated_runtime.cli.create_app", fake_create_app)
    monkeypatch.setitem(
        __import__("sys").modules, "uvicorn", type("Uvicorn", (), {"run": fake_run})
    )

    class Args:
        run = str(tmp_path)
        server_token = "server-token"
        host = "127.0.0.1"
        port = 8765

    assert _serve(Args()) == 0
    assert observed["run_dir"] == tmp_path
    assert observed["server_token"] == "server-token"
    assert observed["host"] == "127.0.0.1"
    assert observed["port"] == 8765


def test_live_config_parses_upstreams(tmp_path: Path) -> None:
    config = load_gate_config(
        _write_gate_config(
            tmp_path,
            _base_config(
                live={
                    "upstreams": {
                        "github": {
                            "base_url": "https://api.github.test",
                            "auth_env": "TEST_GH_TOKEN",
                            "auth_header": "X-Token",
                            "auth_scheme": "Token",
                        }
                    }
                }
            ),
        )
    )

    assert config.live is not None
    assert config.live.upstreams["github"] == LiveUpstream(
        base_url="https://api.github.test",
        auth_env="TEST_GH_TOKEN",
        auth_header="X-Token",
        auth_scheme="Token",
        auth_profile="legacy_github_auth",
    )
    assert config.auth_profiles.profiles["legacy_github_auth"].inject[0].env == "TEST_GH_TOKEN"


def test_live_config_accepts_bare_auth_scheme_and_extra_auth(tmp_path: Path) -> None:
    config = load_gate_config(
        _write_gate_config(
            tmp_path,
            _base_config(
                live={
                    "upstreams": {
                        "alpaca": {
                            "base_url": "https://paper-api.alpaca.test",
                            "auth_env": "ALPACA_KEY_ID",
                            "auth_header": "APCA-API-KEY-ID",
                            "auth_scheme": "",
                            "extra_auth": [
                                {
                                    "header": "APCA-API-SECRET-KEY",
                                    "env": "ALPACA_SECRET_KEY",
                                    "scheme": "",
                                },
                                {
                                    "header": "X-Partner-Token",
                                    "env": "PARTNER_TOKEN",
                                },
                            ],
                        }
                    }
                }
            ),
        )
    )

    assert config.live is not None
    assert config.live.upstreams["alpaca"] == LiveUpstream(
        base_url="https://paper-api.alpaca.test",
        auth_env="ALPACA_KEY_ID",
        auth_header="APCA-API-KEY-ID",
        auth_scheme="",
        extra_auth=[
            LiveAuthHeader(
                header="APCA-API-SECRET-KEY",
                env="ALPACA_SECRET_KEY",
                scheme="",
            ),
            LiveAuthHeader(
                header="X-Partner-Token",
                env="PARTNER_TOKEN",
                scheme="Bearer",
            ),
        ],
        auth_profile="legacy_alpaca_auth",
    )
    assert [
        injection.env for injection in config.auth_profiles.profiles["legacy_alpaca_auth"].inject
    ] == ["ALPACA_KEY_ID", "ALPACA_SECRET_KEY", "PARTNER_TOKEN"]


def test_live_config_accepts_static_non_secret_headers(tmp_path: Path) -> None:
    config = load_gate_config(
        _write_gate_config(
            tmp_path,
            _base_config(
                live={
                    "upstreams": {
                        "opentrons": {
                            "base_url": "http://127.0.0.1:31950",
                            "static_headers": {"opentrons-version": "*"},
                        }
                    }
                }
            ),
        )
    )

    assert config.live is not None
    assert config.live.upstreams["opentrons"] == LiveUpstream(
        base_url="http://127.0.0.1:31950",
        static_headers={"opentrons-version": "*"},
    )


def test_live_config_accepts_auth_profile_for_upstream(tmp_path: Path) -> None:
    config = load_gate_config(
        _write_gate_config(
            tmp_path,
            {
                **_base_config(
                    live={
                        "upstreams": {
                            "github": {
                                "base_url": "https://api.github.test",
                                "auth_profile": "github_token",
                            }
                        }
                    }
                ),
                "auth_profiles": {
                    "github_token": {
                        "kind": "env_static",
                        "inject": [
                            {
                                "in": "header",
                                "name": "Authorization",
                                "env": "TEST_GH_TOKEN",
                                "scheme": "Bearer",
                            }
                        ],
                    }
                },
            },
        )
    )

    assert config.auth_profiles.profiles["github_token"].inject[0].env == "TEST_GH_TOKEN"
    assert config.live is not None
    assert config.live.upstreams["github"].auth_profile == "github_token"


def test_live_config_rejects_unknown_auth_profile_reference(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="auth_profile"):
        load_gate_config(
            _write_gate_config(
                tmp_path,
                _base_config(
                    live={
                        "upstreams": {
                            "github": {
                                "base_url": "https://api.github.test",
                                "auth_profile": "missing_profile",
                            }
                        }
                    }
                ),
            )
        )


def test_live_config_rejects_auth_profile_mixed_with_legacy_auth_header(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="legacy auth fields"):
        load_gate_config(
            _write_gate_config(
                tmp_path,
                {
                    **_base_config(
                        live={
                            "upstreams": {
                                "github": {
                                    "auth_header": "X-Token",
                                    "auth_profile": "github_token",
                                    "base_url": "https://api.github.test",
                                }
                            }
                        }
                    ),
                    "auth_profiles": {
                        "github_token": {
                            "kind": "env_static",
                            "inject": [
                                {"in": "header", "name": "Authorization", "env": "TEST_GH_TOKEN"}
                            ],
                        }
                    },
                },
            )
        )


def test_live_capture_injects_auth_profile_query_without_persisting_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EXAMPLE_API_KEY", "query-secret")
    upstream_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_urls.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    config = load_gate_config(
        _write_gate_config(
            tmp_path,
            {
                **_base_config(
                    live={
                        "upstreams": {
                            "example": {
                                "base_url": "https://api.example.test",
                                "auth_profile": "example_key",
                            }
                        }
                    }
                ),
                "auth_profiles": {
                    "example_key": {
                        "kind": "env_static",
                        "inject": [{"in": "query", "name": "api_key", "env": "EXAMPLE_API_KEY"}],
                    }
                },
            },
        )
    )
    assert config.live is not None
    runtime = AuthoringGatedRuntime(
        policy=GatePolicy.from_config(
            PolicyConfig(live_capture=[RouteRule(path_prefix="/example/", method="GET")]),
            allow_live=True,
        ),
        capture_client=LiveCaptureClient(
            config.live,
            auth_profiles=config.auth_profiles,
            transport=httpx.MockTransport(handler),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(
        CallRequest(method="GET", path="/example/v1/items", query={"limit": "1"})
    )

    assert response.status_code == 200
    assert upstream_urls == ["https://api.example.test/v1/items?limit=1&api_key=query-secret"]
    captures = load_captures(tmp_path / "captures.jsonl")
    assert captures[0].query == {"limit": "1"}
    run_text = (tmp_path / "captures.jsonl").read_text(encoding="utf-8")
    assert "query-secret" not in run_text


def test_live_capture_blocks_auth_profile_query_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EXAMPLE_API_KEY", "query-secret")

    config = load_gate_config(
        _write_gate_config(
            tmp_path,
            {
                **_base_config(
                    live={
                        "upstreams": {
                            "example": {
                                "base_url": "https://api.example.test",
                                "auth_profile": "example_key",
                            }
                        }
                    }
                ),
                "auth_profiles": {
                    "example_key": {
                        "kind": "env_static",
                        "inject": [{"in": "query", "name": "api_key", "env": "EXAMPLE_API_KEY"}],
                    }
                },
            },
        )
    )
    assert config.live is not None
    runtime = AuthoringGatedRuntime(
        policy=GatePolicy.from_config(
            PolicyConfig(live_capture=[RouteRule(path_prefix="/example/", method="GET")]),
            allow_live=True,
        ),
        capture_client=LiveCaptureClient(
            config.live,
            auth_profiles=config.auth_profiles,
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(
        CallRequest(method="GET", path="/example/v1/items", query={"api_key": "agent-secret"})
    )

    assert response.status_code == 502
    assert response.body["error"]["code"] == "auth_query_collision"
    assert not (tmp_path / "captures.jsonl").exists()


def test_live_extra_auth_envs_are_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALPACA_KEY_ID", "key-id")
    monkeypatch.delenv("ALPACA_SECRET_KEY", raising=False)

    with pytest.raises(ValueError, match="ALPACA_SECRET_KEY"):
        LiveCaptureClient(
            LiveGateConfig(
                upstreams={
                    "alpaca": LiveUpstream(
                        base_url="https://paper-api.alpaca.test",
                        auth_env="ALPACA_KEY_ID",
                        auth_header="APCA-API-KEY-ID",
                        auth_scheme="",
                        extra_auth=[
                            LiveAuthHeader(
                                header="APCA-API-SECRET-KEY",
                                env="ALPACA_SECRET_KEY",
                                scheme="",
                            )
                        ],
                    )
                }
            )
        )


def test_live_capture_forwards_only_configured_auth_headers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALPACA_KEY_ID", "key-id")
    monkeypatch.setenv("ALPACA_SECRET_KEY", "secret-key")
    upstream_headers: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_headers.append(request.headers)
        return httpx.Response(200, json={"account": "ok"})

    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/alpaca/", method="GET")]),
        allow_live=True,
    )
    runtime = AuthoringGatedRuntime(
        policy=policy,
        capture_client=LiveCaptureClient(
            LiveGateConfig(
                upstreams={
                    "alpaca": LiveUpstream(
                        base_url="https://paper-api.alpaca.test",
                        auth_env="ALPACA_KEY_ID",
                        auth_header="APCA-API-KEY-ID",
                        auth_scheme="",
                        extra_auth=[
                            LiveAuthHeader(
                                header="APCA-API-SECRET-KEY",
                                env="ALPACA_SECRET_KEY",
                                scheme="",
                            )
                        ],
                    )
                }
            ),
            transport=httpx.MockTransport(handler),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(
        CallRequest(
            method="GET",
            path="/alpaca/v2/account",
            headers={
                "authorization": "Bearer agent-secret",
                "cookie": "session=agent-secret",
                "x-api-secret": "agent-secret",
            },
        )
    )

    assert response.status_code == 200
    assert len(upstream_headers) == 1
    headers = upstream_headers[0]
    assert headers["APCA-API-KEY-ID"] == "key-id"
    assert headers["APCA-API-SECRET-KEY"] == "secret-key"
    assert "authorization" not in headers
    assert "cookie" not in headers
    assert "agent-secret" not in str(headers)


def test_live_capture_forwards_static_headers_without_agent_overrides(
    tmp_path: Path,
) -> None:
    upstream_headers: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        upstream_headers.append(request.headers)
        return httpx.Response(200, json={"health": "ok"})

    policy = GatePolicy.from_config(
        PolicyConfig(live_capture=[RouteRule(path_prefix="/opentrons/", method="GET")]),
        allow_live=True,
    )
    runtime = AuthoringGatedRuntime(
        policy=policy,
        capture_client=LiveCaptureClient(
            LiveGateConfig(
                upstreams={
                    "opentrons": LiveUpstream(
                        base_url="http://opentrons.test",
                        static_headers={"opentrons-version": "*"},
                    )
                }
            ),
            transport=httpx.MockTransport(handler),
        ),
        capture_store=CaptureStore(tmp_path / "captures.jsonl"),
    )

    response = runtime.handle(
        CallRequest(
            method="GET",
            path="/opentrons/health",
            headers={"opentrons-version": "agent-supplied"},
        )
    )

    assert response.status_code == 200
    assert len(upstream_headers) == 1
    assert upstream_headers[0]["opentrons-version"] == "*"


@pytest.mark.parametrize(
    ("live", "match"),
    [
        ({}, r"live\.upstreams must be a non-empty object"),
        ({"upstreams": []}, r"live\.upstreams must be a non-empty object"),
        ({"upstreams": {"": {"base_url": "https://api.github.test"}}}, r"live\.upstreams key"),
        (
            {"upstreams": {"git/hub": {"base_url": "https://api.github.test"}}},
            r"live\.upstreams key",
        ),
        ({"upstreams": {"github": {"base_url": ""}}}, r"live\.upstreams\.github\.base_url"),
        ({"upstreams": {"github": {"base_url": "ftp://api.github.test"}}}, r"http\(s\) URL"),
        (
            {"upstreams": {"github": {"base_url": "https://user:secret@api.github.test"}}},
            r"http\(s\) URL",
        ),
        (
            {"upstreams": {"github": {"base_url": "https://api.github.test?api_key=secret"}}},
            r"http\(s\) URL",
        ),
        (
            {"upstreams": {"github": {"base_url": "https://api.github.test#secret"}}},
            r"http\(s\) URL",
        ),
        (
            {"upstreams": {"github": {"base_url": "https://api.github.test", "auth_env": ""}}},
            r"auth_env",
        ),
        (
            {"upstreams": {"github": {"base_url": "https://api.github.test", "auth_header": ""}}},
            r"auth_header",
        ),
        (
            {"upstreams": {"github": {"base_url": "https://api.github.test", "auth_scheme": 1}}},
            r"auth_scheme",
        ),
        (
            {
                "upstreams": {
                    "github": {
                        "base_url": "https://api.github.test",
                        "static_headers": {"Authorization": "Bearer secret"},
                    }
                }
            },
            r"static_headers\.Authorization",
        ),
        (
            {
                "upstreams": {
                    "github": {
                        "base_url": "https://api.github.test",
                        "extra_auth": [{"header": "", "env": "TOKEN"}],
                    }
                }
            },
            r"extra_auth\[0\]\.header",
        ),
        (
            {
                "upstreams": {
                    "github": {
                        "base_url": "https://api.github.test",
                        "extra_auth": [{"header": "X-Token", "env": ""}],
                    }
                }
            },
            r"extra_auth\[0\]\.env",
        ),
        (
            {
                "upstreams": {
                    "github": {
                        "base_url": "https://api.github.test",
                        "extra_auth": [{"header": "X-Token", "env": "TOKEN", "scheme": 1}],
                    }
                }
            },
            r"extra_auth\[0\]\.scheme",
        ),
    ],
)
def test_live_config_validation(tmp_path: Path, live: dict, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        load_gate_config(_write_gate_config(tmp_path, _base_config(live=live)))
