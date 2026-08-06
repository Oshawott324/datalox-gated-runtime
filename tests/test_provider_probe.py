from __future__ import annotations

import json
import os
import shlex
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request

from datalox_gated_runtime.provider_probe import (
    ProbeConfigError,
    load_probe_config,
    rollup_probe_reports,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_TIMEOUT_SECONDS = 60


@dataclass
class FakeProvider:
    base_url: str
    requests: list[dict[str, Any]]
    server: uvicorn.Server
    thread: threading.Thread

    def close(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise AssertionError("fake provider did not stop")


def test_probe_config_rejects_out_of_prefix_request(tmp_path: Path) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "alpaca",
            "base_url": "https://paper-api.alpaca.test",
            "auth_env": None,
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 2, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/v2/"],
            "probe_requests": [{"method": "GET", "path": "/v1/account", "query": {}}],
        },
    )

    with pytest.raises(ProbeConfigError) as error:
        load_probe_config(config_path)

    assert error.value.code == "probe_request_out_of_safe_prefix"
    assert "before session start" in error.value.message
    assert not (tmp_path / "run" / "session_manifest.json").exists()


def test_probe_config_rejects_base_url_userinfo(tmp_path: Path) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "provider",
            "base_url": "https://user:secret@api.provider.test",
            "auth_env": None,
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/v1/"],
            "probe_requests": [{"method": "GET", "path": "/v1/resource", "query": {}}],
        },
    )

    with pytest.raises(ProbeConfigError) as error:
        load_probe_config(config_path)

    assert error.value.code == "invalid_base_url"


def test_probe_config_rejects_more_requests_than_rate_budget(tmp_path: Path) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "provider",
            "base_url": "https://api.provider.test",
            "auth_env": None,
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/v1/"],
            "probe_requests": [
                {"method": "GET", "path": "/v1/one", "query": {}},
                {"method": "GET", "path": "/v1/two", "query": {}},
            ],
        },
    )

    with pytest.raises(ProbeConfigError) as error:
        load_probe_config(config_path)

    assert error.value.code == "probe_requests_exceed_rate_budget"


def test_probe_config_rejects_zero_rate_interval(tmp_path: Path) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "provider",
            "base_url": "https://api.provider.test",
            "auth_env": None,
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0},
            "safe_read_prefixes": ["/v1/"],
            "probe_requests": [{"method": "GET", "path": "/v1/resource", "query": {}}],
        },
    )

    with pytest.raises(ProbeConfigError) as error:
        load_probe_config(config_path)

    assert error.value.code == "invalid_rate_budget"


@pytest.mark.parametrize(
    "base_url",
    [
        "https://api.provider.test?api_key=secret",
        "https://api.provider.test#secret",
    ],
)
def test_probe_config_rejects_base_url_query_or_fragment(
    tmp_path: Path,
    base_url: str,
) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "provider",
            "base_url": base_url,
            "auth_env": None,
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/v1/"],
            "probe_requests": [{"method": "GET", "path": "/v1/resource", "query": {}}],
        },
    )

    with pytest.raises(ProbeConfigError) as error:
        load_probe_config(config_path)

    assert error.value.code == "invalid_base_url"


def test_probe_extra_auth_without_scheme_inherits_primary_scheme(tmp_path: Path) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "alpaca",
            "base_url": "https://paper-api.alpaca.test",
            "auth_env": "ALPACA_KEY_ID",
            "auth_header": "APCA-API-KEY-ID",
            "auth_scheme": "",
            "extra_auth": [{"header": "APCA-API-SECRET-KEY", "env": "ALPACA_SECRET_KEY"}],
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/v2/"],
            "probe_requests": [{"method": "GET", "path": "/v2/account", "query": {}}],
        },
    )

    config = load_probe_config(config_path)

    assert config.extra_auth[0].scheme == ""


def test_probe_config_accepts_static_headers(tmp_path: Path) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "opentrons_local",
            "base_url": "http://127.0.0.1:31950",
            "auth_env": None,
            "static_headers": {"opentrons-version": "*"},
            "access_class": "self_hosted",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/health"],
            "probe_requests": [{"method": "GET", "path": "/health", "query": {}}],
        },
    )

    config = load_probe_config(config_path)

    assert config.static_headers == {"opentrons-version": "*"}


def test_probe_config_rejects_auth_profile_mixed_with_legacy_auth_header(tmp_path: Path) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "provider",
            "base_url": "https://api.provider.test",
            "auth_header": "X-Token",
            "auth_profile": "provider_token",
            "auth_profiles": {
                "provider_token": {
                    "kind": "env_static",
                    "inject": [{"in": "header", "name": "Authorization", "env": "PROVIDER_TOKEN"}],
                }
            },
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/v1/"],
            "probe_requests": [{"method": "GET", "path": "/v1/resource", "query": {}}],
        },
    )

    with pytest.raises(ProbeConfigError) as error:
        load_probe_config(config_path)

    assert error.value.code == "auth_profile_legacy_mix"


def test_missing_auth_env_writes_blocked_report_without_session(tmp_path: Path) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "alpaca",
            "base_url": "https://paper-api.alpaca.test",
            "auth_env": "ALPACA_KEY_ID",
            "auth_header": "APCA-API-KEY-ID",
            "auth_scheme": "",
            "extra_auth": [{"header": "APCA-API-SECRET-KEY", "env": "ALPACA_SECRET_KEY"}],
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/v2/"],
            "probe_requests": [{"method": "GET", "path": "/v2/account", "query": {}}],
        },
    )
    env = os.environ.copy()
    env.pop("ALPACA_KEY_ID", None)
    env.pop("ALPACA_SECRET_KEY", None)
    out_dir = tmp_path / "probe-run"

    result = _run_cli(
        ["provider", "probe", "--config", str(config_path), "--out", str(out_dir), "--json"],
        env=env,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == "missing_auth_env"
    assert payload["blocker"]["missing_env"] == ["ALPACA_KEY_ID", "ALPACA_SECRET_KEY"]
    report = json.loads((out_dir / "probe_report.json").read_text(encoding="utf-8"))
    assert report == payload
    assert not (out_dir / "session_manifest.json").exists()


def test_provider_probe_routes_gate_paths_to_upstream_relative_paths(tmp_path: Path) -> None:
    with _fake_provider() as provider:
        config_path = _write_probe_config(
            tmp_path,
            {
                "provider_id": "alpaca",
                "base_url": provider.base_url,
                "auth_env": "ALPACA_KEY_ID",
                "auth_header": "APCA-API-KEY-ID",
                "auth_scheme": "",
                "static_headers": {"opentrons-version": "*"},
                "extra_auth": [
                    {"header": "APCA-API-SECRET-KEY", "env": "ALPACA_SECRET_KEY", "scheme": ""}
                ],
                "access_class": "instant_sandbox",
                "probe_status": "allowed",
                "rate_budget": {"max_requests": 5, "min_interval_seconds": 0.01},
                "safe_read_prefixes": ["/v2/"],
                "probe_requests": [
                    {
                        "method": "GET",
                        "path": "/v2/account",
                        "query": {"status": ["active", "pending"]},
                    },
                    {"method": "GET", "path": "/v2/orders", "query": {}},
                ],
            },
        )
        env = os.environ.copy()
        env["ALPACA_KEY_ID"] = "key-id"
        env["ALPACA_SECRET_KEY"] = "secret-key"
        out_dir = tmp_path / "probe-run"

        result = _run_cli(
            ["provider", "probe", "--config", str(config_path), "--out", str(out_dir), "--json"],
            env=env,
        )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"
    assert payload["counts"] == {
        "attempted": 2,
        "captured": 2,
        "2xx": 2,
        "4xx": 0,
        "429": 0,
        "5xx": 0,
        "errors": 0,
    }
    assert [item["path"] for item in payload["requests"]] == ["/v2/account", "/v2/orders"]
    assert [item["gate_path"] for item in payload["requests"]] == [
        "/alpaca/v2/account",
        "/alpaca/v2/orders",
    ]
    assert [item["upstream_path"] for item in payload["requests"]] == [
        "/v2/account",
        "/v2/orders",
    ]
    assert {item["decision"] for item in payload["requests"]} == {"live_capture"}
    assert all(item["case_id"] for item in payload["requests"])
    assert payload["requests"][0]["query"] == {"status": ["active", "pending"]}
    assert payload["pagination_signals"] == [{"path": "/v2/orders", "signals": ["next_cursor"]}]
    assert payload["hygiene"]["secret_scan_passed"] is True
    assert (out_dir / "captures.jsonl").exists()
    assert json.loads((out_dir / "audit.json").read_text(encoding="utf-8"))["passed"] is True
    assert provider.requests == [
        {
            "path": "/v2/account",
            "query": "status=active&status=pending",
            "key_id": "key-id",
            "secret_key": "secret-key",
            "authorization": "",
            "opentrons_version": "*",
        },
        {
            "path": "/v2/orders",
            "query": "",
            "key_id": "key-id",
            "secret_key": "secret-key",
            "authorization": "",
            "opentrons_version": "*",
        },
    ]
    run_text = "\n".join(
        path.read_text(encoding="utf-8") for path in out_dir.rglob("*") if path.is_file()
    )
    assert "key-id" not in run_text
    assert "secret-key" not in run_text
    assert "body" not in payload["requests"][0]


def test_provider_auth_preflight_reports_missing_profile_env_without_session(
    tmp_path: Path,
) -> None:
    config_path = _write_probe_config(
        tmp_path,
        {
            "provider_id": "market_data",
            "base_url": "https://api.market.test",
            "auth_profile": "market_key",
            "auth_profiles": {
                "market_key": {
                    "kind": "env_static",
                    "inject": [{"in": "query", "name": "apiKey", "env": "MARKET_API_KEY"}],
                }
            },
            "access_class": "instant_sandbox",
            "probe_status": "allowed",
            "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
            "safe_read_prefixes": ["/v1/"],
            "probe_requests": [{"method": "GET", "path": "/v1/tickers", "query": {}}],
        },
    )
    env = os.environ.copy()
    env.pop("MARKET_API_KEY", None)

    result = _run_cli(
        ["provider", "auth-preflight", "--config", str(config_path), "--json"],
        env=env,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == "missing_auth_env"
    assert payload["blocker"]["missing_env"] == ["MARKET_API_KEY"]
    assert payload["auth_preflight"]["status"] == "failed"
    assert payload["auth_preflight"]["requirements"] == [
        {
            "env": "MARKET_API_KEY",
            "present": False,
            "profile_id": "market_key",
            "target": {"in": "query", "name": "apiKey"},
        }
    ]
    assert not (tmp_path / "session_manifest.json").exists()


def test_provider_probe_uses_auth_profile_headers_and_query_without_persisting_secrets(
    tmp_path: Path,
) -> None:
    with _fake_provider() as provider:
        config_path = _write_probe_config(
            tmp_path,
            {
                "provider_id": "alpaca",
                "base_url": provider.base_url,
                "auth_profile": "alpaca_profile",
                "auth_profiles": {
                    "alpaca_profile": {
                        "kind": "env_static",
                        "inject": [
                            {
                                "in": "header",
                                "name": "APCA-API-KEY-ID",
                                "env": "ALPACA_KEY_ID",
                                "scheme": "",
                            },
                            {
                                "in": "header",
                                "name": "APCA-API-SECRET-KEY",
                                "env": "ALPACA_SECRET_KEY",
                                "scheme": "",
                            },
                            {"in": "query", "name": "feed", "env": "ALPACA_FEED"},
                        ],
                    }
                },
                "access_class": "instant_sandbox",
                "probe_status": "allowed",
                "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
                "safe_read_prefixes": ["/v2/"],
                "probe_requests": [
                    {"method": "GET", "path": "/v2/account", "query": {"status": "active"}}
                ],
            },
        )
        env = os.environ.copy()
        env["ALPACA_KEY_ID"] = "key-id"
        env["ALPACA_SECRET_KEY"] = "secret-key"
        env["ALPACA_FEED"] = "sip-secret"
        out_dir = tmp_path / "probe-run"

        result = _run_cli(
            ["provider", "probe", "--config", str(config_path), "--out", str(out_dir), "--json"],
            env=env,
        )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert payload["auth_schema"] == "auth_broker_v0"
    assert payload["auth_preflight"]["status"] == "passed"
    assert payload["counts"]["captured"] == 1
    assert provider.requests == [
        {
            "path": "/v2/account",
            "query": "status=active&feed=sip-secret",
            "key_id": "key-id",
            "secret_key": "secret-key",
            "authorization": "",
            "opentrons_version": "",
        }
    ]
    run_text = "\n".join(
        path.read_text(encoding="utf-8") for path in out_dir.rglob("*") if path.is_file()
    )
    assert "key-id" not in run_text
    assert "secret-key" not in run_text
    assert "sip-secret" not in run_text


def test_provider_probe_returns_nonzero_when_no_responses_are_captured(tmp_path: Path) -> None:
    with _fake_provider() as provider:
        config_path = _write_probe_config(
            tmp_path,
            {
                "provider_id": "alpaca",
                "base_url": provider.base_url,
                "auth_env": "ALPACA_KEY_ID",
                "auth_header": "APCA-API-KEY-ID",
                "auth_scheme": "",
                "extra_auth": [
                    {"header": "APCA-API-SECRET-KEY", "env": "ALPACA_SECRET_KEY", "scheme": ""}
                ],
                "access_class": "instant_sandbox",
                "probe_status": "allowed",
                "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
                "safe_read_prefixes": ["/v2/"],
                "probe_requests": [{"method": "GET", "path": "/v2/broken", "query": {}}],
            },
        )
        env = os.environ.copy()
        env["ALPACA_KEY_ID"] = "key-id"
        env["ALPACA_SECRET_KEY"] = "secret-key"
        out_dir = tmp_path / "probe-run"

        result = _run_cli(
            ["provider", "probe", "--config", str(config_path), "--out", str(out_dir), "--json"],
            env=env,
        )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == "probe_capture_incomplete"
    assert payload["counts"]["attempted"] == 1
    assert payload["counts"]["captured"] == 0


def test_provider_probe_blocks_when_all_captured_responses_are_5xx(tmp_path: Path) -> None:
    with _fake_provider() as provider:
        config_path = _write_probe_config(
            tmp_path,
            {
                "provider_id": "alpaca",
                "base_url": provider.base_url,
                "auth_env": "ALPACA_KEY_ID",
                "auth_header": "APCA-API-KEY-ID",
                "auth_scheme": "",
                "extra_auth": [
                    {"header": "APCA-API-SECRET-KEY", "env": "ALPACA_SECRET_KEY", "scheme": ""}
                ],
                "access_class": "instant_sandbox",
                "probe_status": "allowed",
                "rate_budget": {"max_requests": 1, "min_interval_seconds": 0.01},
                "safe_read_prefixes": ["/v2/"],
                "probe_requests": [{"method": "GET", "path": "/v2/unavailable", "query": {}}],
            },
        )
        env = os.environ.copy()
        env["ALPACA_KEY_ID"] = "key-id"
        env["ALPACA_SECRET_KEY"] = "secret-key"
        out_dir = tmp_path / "probe-run"

        result = _run_cli(
            ["provider", "probe", "--config", str(config_path), "--out", str(out_dir), "--json"],
            env=env,
        )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == "probe_no_usable_response"
    assert payload["counts"]["captured"] == 1
    assert payload["counts"]["5xx"] == 1


def test_probe_rollup_aggregates_fixture_reports(tmp_path: Path) -> None:
    _write_report(
        tmp_path / "alpaca" / "probe_report.json",
        {
            "provider_id": "alpaca",
            "status": "completed",
            "access_class": "instant_sandbox",
            "counts": {
                "attempted": 2,
                "captured": 2,
                "2xx": 1,
                "4xx": 0,
                "429": 1,
                "5xx": 0,
                "errors": 0,
            },
            "pagination_signals": [{"path": "/v2/orders", "signals": ["next_cursor"]}],
            "promoted_env": "envs/probed_alpaca_v0",
            "verify_replay": {"fidelity_passed": True},
        },
    )
    _write_report(
        tmp_path / "benchling" / "probe_report.json",
        {
            "provider_id": "benchling",
            "status": "blocked",
            "access_class": "approval_gated",
            "counts": {
                "attempted": 0,
                "captured": 0,
                "2xx": 0,
                "4xx": 0,
                "429": 0,
                "5xx": 0,
                "errors": 0,
            },
            "blocker": {"code": "missing_auth_env", "missing_env": ["BENCHLING_API_KEY"]},
            "pagination_signals": [],
        },
    )

    payload = rollup_probe_reports(tmp_path)

    assert payload == {
        "providers_probed": 2,
        "providers_blocked": [{"provider_id": "benchling", "reason": "missing_auth_env"}],
        "requests_attempted": 2,
        "responses_captured": 2,
        "status_histogram": {"2xx": 1, "4xx": 0, "429": 1, "5xx": 0, "errors": 0},
        "pagination_signals_by_provider": {
            "alpaca": [{"path": "/v2/orders", "signals": ["next_cursor"]}]
        },
        "promotable_providers": ["alpaca"],
        "promoted_envs": ["envs/probed_alpaca_v0"],
        "verify_replay_green": ["alpaca"],
        "access_class_breakdown": {"approval_gated": 1, "instant_sandbox": 1},
    }


def test_probe_rollup_cli_outputs_json(tmp_path: Path) -> None:
    _write_report(
        tmp_path / "hapi" / "probe_report.json",
        {
            "provider_id": "hapi_fhir",
            "status": "completed",
            "access_class": "open_public",
            "counts": {
                "attempted": 1,
                "captured": 1,
                "2xx": 1,
                "4xx": 0,
                "429": 0,
                "5xx": 0,
                "errors": 0,
            },
            "pagination_signals": [],
        },
    )

    result = _run_cli(
        ["provider", "probe-rollup", "--runs", str(tmp_path), "--json"], env=os.environ.copy()
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["access_class_breakdown"] == {"open_public": 1}


@contextmanager
def _fake_provider() -> Iterator[FakeProvider]:
    port = _free_port()
    requests: list[dict[str, Any]] = []
    app = FastAPI()

    @app.get("/_health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/v2/account")
    async def account(request: Request) -> dict[str, str]:
        _record_provider_request(request, requests)
        return {"id": "acct-1", "status": "active"}

    @app.get("/v2/orders")
    async def orders(request: Request) -> dict[str, object]:
        _record_provider_request(request, requests)
        return {"orders": [], "next_cursor": "cursor-2"}

    @app.get("/v2/broken")
    async def broken(request: Request) -> Any:
        from fastapi.responses import Response

        _record_provider_request(request, requests)
        return Response(content=b"{", media_type="application/json")

    @app.get("/v2/unavailable")
    async def unavailable(request: Request) -> Any:
        from fastapi.responses import JSONResponse

        _record_provider_request(request, requests)
        return JSONResponse({"error": "temporary"}, status_code=503)

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    provider = FakeProvider(
        base_url=f"http://127.0.0.1:{port}",
        requests=requests,
        server=server,
        thread=thread,
    )
    try:
        _wait_for_provider_health(provider)
        yield provider
    finally:
        provider.close()


def _record_provider_request(request: Request, requests: list[dict[str, Any]]) -> None:
    requests.append(
        {
            "path": request.url.path,
            "query": request.url.query,
            "key_id": request.headers.get("APCA-API-KEY-ID", ""),
            "secret_key": request.headers.get("APCA-API-SECRET-KEY", ""),
            "authorization": request.headers.get("authorization", ""),
            "opentrons_version": request.headers.get("opentrons-version", ""),
        }
    )


def _write_probe_config(tmp_path: Path, payload: dict[str, Any]) -> Path:
    path = tmp_path / "probe_config.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _write_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _run_cli(args: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-m", "datalox_gated_runtime.cli", *args]
    try:
        return subprocess.run(
            command,
            check=False,
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=CLI_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            "\n".join(
                [
                    f"CLI subprocess timed out after {CLI_TIMEOUT_SECONDS}s: {shlex.join(command)}",
                    f"stdout:\n{_timeout_output(exc.stdout)}",
                    f"stderr:\n{_timeout_output(exc.stderr)}",
                ]
            )
        ) from exc


def _timeout_output(output: str | bytes | None) -> str:
    if output is None:
        return "<empty>"
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace") or "<empty>"
    return output or "<empty>"


def _wait_for_provider_health(provider: FakeProvider) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        if not provider.thread.is_alive():
            raise AssertionError("fake provider exited before health check passed")
        try:
            response = httpx.get(f"{provider.base_url}/_health", timeout=0.5)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.05)
    raise AssertionError("fake provider did not become healthy")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
