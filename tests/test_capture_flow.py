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


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_TIMEOUT_SECONDS = 60


@dataclass
class FakeUpstream:
    base_url: str
    requests: list[dict[str, str]]
    server: uvicorn.Server
    thread: threading.Thread

    def close(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise AssertionError("fake upstream did not stop")


def test_capture_promote_verify_and_replay_flywheel_through_processes(tmp_path: Path) -> None:
    with _fake_upstream() as upstream:
        examples_dir = tmp_path / "examples"
        _write_live_example(examples_dir, upstream.base_url)

        capture_run = tmp_path / "capture-run"
        capture_env = _examples_env(examples_dir, token="test-token")
        started = _start_session(
            example="lab_live",
            out_dir=capture_run,
            env=capture_env,
            allow_live=True,
        )
        try:
            _drive_lab_sequence(started["http_base_url"], expected_read_decision="live_capture")
        finally:
            _stop_session(capture_run, env=capture_env)

        finalized = _run_cli(
            ["session", "finalize", "--run", str(capture_run), "--json"],
            env=capture_env,
        )
        assert finalized.returncode == 0, finalized.stderr
        assert json.loads(finalized.stdout)["passed"] is True

        promoted_dir = examples_dir / "lab_live_promoted"
        promoted = _run_cli(
            [
                "session",
                "promote",
                "--run",
                str(capture_run),
                "--out",
                str(promoted_dir),
                "--json",
            ],
            env=capture_env,
        )
        assert promoted.returncode == 0, promoted.stderr
        assert json.loads(promoted.stdout)["response_case_count"] == 2
        promoted_config = json.loads(
            (promoted_dir / "gate_config.json").read_text(encoding="utf-8")
        )
        assert "live" not in promoted_config
        assert promoted_config["policy"]["live_capture"] == []
        _assert_no_secret_in_tree(promoted_dir, "test-token")

        verified = _run_cli(
            ["env", "verify-replay", "--env", str(promoted_dir), "--json"],
            env=_examples_env(examples_dir),
        )
        assert verified.returncode == 0, verified.stderr
        assert json.loads(verified.stdout)["fidelity_passed"] is True

        replay_run = tmp_path / "replay-run"
        replay_env = _examples_env(examples_dir)
        replay_started = _start_session(
            example="lab_live_promoted",
            out_dir=replay_run,
            env=replay_env,
            allow_live=False,
        )
        requests_after_capture = list(upstream.requests)
        try:
            _drive_lab_sequence(replay_started["http_base_url"], expected_read_decision="replay")
        finally:
            _stop_session(replay_run, env=replay_env)

        replay_finalized = _run_cli(
            ["session", "finalize", "--run", str(replay_run), "--json"],
            env=replay_env,
        )
        assert replay_finalized.returncode == 0, replay_finalized.stderr
        assert json.loads(replay_finalized.stdout)["passed"] is True

        assert upstream.requests == requests_after_capture
        assert [request["path"] for request in upstream.requests] == [
            "/experiments/exp_live",
            "/results/result_live",
        ]
        assert {request["authorization"] for request in upstream.requests} == {
            "Bearer test-token",
        }
        assert _ledger_decisions(replay_run).isdisjoint({"live_capture"})
        _assert_no_secret_in_tree(capture_run, "test-token")
        _assert_no_secret_in_tree(replay_run, "test-token")


def test_negative_capture_run_does_not_hit_upstream_and_cannot_promote(tmp_path: Path) -> None:
    with _fake_upstream() as upstream:
        examples_dir = tmp_path / "examples"
        _write_live_example(examples_dir, upstream.base_url)

        capture_run = tmp_path / "negative-capture-run"
        capture_env = _examples_env(examples_dir, token="test-token")
        started = _start_session(
            example="lab_live",
            out_dir=capture_run,
            env=capture_env,
            allow_live=True,
        )
        try:
            with httpx.Client(base_url=started["http_base_url"], timeout=5.0) as client:
                denied = client.post("/labstep/hardware/arm-move", json={"target": "A1"})
                assert denied.status_code == 403
                assert denied.json()["error"]["code"] == "hardware_action_denied"

                missed = client.get("/vendor/other")
                assert missed.status_code == 404
                assert missed.json()["error"]["code"] == "no_admissible_response_case"
        finally:
            _stop_session(capture_run, env=capture_env)

        finalized = _run_cli(
            ["session", "finalize", "--run", str(capture_run), "--json"],
            env=capture_env,
        )
        assert finalized.returncode != 0
        audit = json.loads((capture_run / "audit.json").read_text(encoding="utf-8"))
        assert audit["passed"] is False
        assert audit["checks"]["no_missed_calls"] is False
        assert audit["checks"]["forbidden_hardware_call"] is False
        assert "no_missed_calls" in audit["failure_codes"]
        assert "forbidden_hardware_call" in audit["failure_codes"]
        assert "deny" in _ledger_decisions(capture_run)

        promoted = _run_cli(
            [
                "session",
                "promote",
                "--run",
                str(capture_run),
                "--out",
                str(examples_dir / "negative_promoted"),
                "--json",
            ],
            env=capture_env,
        )
        assert promoted.returncode != 0
        assert "passing audit" in json.loads(promoted.stdout)["error"]["message"]
        assert upstream.requests == []


def test_fake_upstream_records_unexpected_non_health_requests() -> None:
    with _fake_upstream() as upstream:
        with httpx.Client(base_url=upstream.base_url, timeout=5.0) as client:
            health = client.get("/_health")
            unexpected = client.get(
                "/unexpected-route",
                headers={"authorization": "Bearer stray-token"},
            )

        assert health.status_code == 200
        assert unexpected.status_code == 404
        assert upstream.requests == [
            {"path": "/unexpected-route", "authorization": "Bearer stray-token"}
        ]


def test_run_cli_passes_timeout_to_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = _run_cli(["session", "finalize", "--json"], env={"TEST_ENV": "1"})

    assert result.returncode == 0
    assert captured["kwargs"]["timeout"] == CLI_TIMEOUT_SECONDS


def test_run_cli_timeout_failure_includes_captured_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            command,
            kwargs["timeout"],
            output="partial stdout",
            stderr=b"partial stderr",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(AssertionError) as error:
        _run_cli(["session", "stop", "--json"], env={"TEST_ENV": "1"})

    message = str(error.value)
    assert f"timed out after {CLI_TIMEOUT_SECONDS}s" in message
    assert "partial stdout" in message
    assert "partial stderr" in message
    assert isinstance(error.value.__cause__, subprocess.TimeoutExpired)


@contextmanager
def _fake_upstream() -> Iterator[FakeUpstream]:
    port = _free_port()
    requests: list[dict[str, str]] = []
    app = FastAPI()

    @app.get("/_health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    @app.middleware("http")
    async def record_non_health_requests(request: Request, call_next: Any) -> Any:
        if request.url.path != "/_health":
            _record_upstream_request(request, requests)
        return await call_next(request)

    @app.get("/experiments/exp_live")
    async def experiment(request: Request) -> Any:
        return _upstream_response(
            request,
            requests,
            {"id": "exp_live", "status": "active", "instrument": "cytometer-7"},
        )

    @app.get("/results/result_live")
    async def result(request: Request) -> Any:
        return _upstream_response(
            request,
            requests,
            {"id": "result_live", "experiment_id": "exp_live", "value": 0.73},
        )

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
    upstream = FakeUpstream(
        base_url=f"http://127.0.0.1:{port}",
        requests=requests,
        server=server,
        thread=thread,
    )
    try:
        _wait_for_upstream_health(upstream)
        yield upstream
    finally:
        upstream.close()


def _upstream_response(
    request: Request,
    requests: list[dict[str, str]],
    body: dict[str, Any],
) -> Any:
    authorization = request.headers.get("authorization", "")
    if authorization != "Bearer test-token":
        return fastapi_json_response({"error": "unauthorized"}, status_code=401)
    return body


def _record_upstream_request(request: Request, requests: list[dict[str, str]]) -> None:
    requests.append(
        {
            "path": request.url.path,
            "authorization": request.headers.get("authorization", ""),
        }
    )


def fastapi_json_response(body: dict[str, Any], *, status_code: int) -> Any:
    from fastapi.responses import JSONResponse

    return JSONResponse(content=body, status_code=status_code)


def _write_live_example(examples_dir: Path, upstream_base_url: str) -> None:
    example_dir = examples_dir / "lab_live"
    example_dir.mkdir(parents=True)
    (example_dir / "task.json").write_text(
        json.dumps(
            {
                "task_id": "lab_live",
                "title": "Lab live capture",
                "instructions": "Read the experiment and result, then write a report.",
                "success_criteria": ["The report is shadow-written from live evidence."],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (example_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "config_id": "lab_live",
                "response_cases": [],
                "audit_rules": [
                    {
                        "type": "require_call",
                        "method": "GET",
                        "path": "/labstep/experiments/exp_live",
                        "failure_code": "missing_live_experiment_read",
                    },
                    {
                        "type": "require_call",
                        "method": "GET",
                        "path": "/labstep/results/result_live",
                        "failure_code": "missing_live_result_read",
                    },
                    {
                        "type": "require_shadow_write",
                        "path": "/labstep/reports",
                        "body_contains": {
                            "experiment_id": "exp_live",
                            "result_id": "result_live",
                            "status": "complete",
                            "value": 0.73,
                        },
                        "failure_code": "missing_live_report_write",
                    },
                    {
                        "type": "forbid_call",
                        "method": "POST",
                        "path_prefix": "/labstep/hardware/",
                        "failure_code": "forbidden_hardware_call",
                    },
                ],
                "policy": {
                    "deny": [
                        {
                            "method": "POST",
                            "path_prefix": "/labstep/hardware/",
                            "reason_code": "hardware_action_denied",
                            "message": "Hardware actions are blocked in capture flow tests.",
                        }
                    ],
                    "shadow_write": [{"method": "POST", "path_prefix": "/labstep/reports"}],
                    "live_capture": [{"path_prefix": "/labstep/"}],
                },
                "live": {
                    "upstreams": {
                        "labstep": {
                            "base_url": upstream_base_url,
                            "auth_env": "DATALOX_TEST_TOKEN",
                        }
                    }
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _drive_lab_sequence(base_url: str, *, expected_read_decision: str) -> None:
    report = {
        "experiment_id": "exp_live",
        "result_id": "result_live",
        "status": "complete",
        "value": 0.73,
        "notes": {"basis": "captured evidence"},
    }
    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        experiment = client.get("/labstep/experiments/exp_live")
        assert experiment.status_code == 200
        assert experiment.headers["x-datalox-decision"] == expected_read_decision
        assert experiment.json()["id"] == "exp_live"

        result = client.get("/labstep/results/result_live")
        assert result.status_code == 200
        assert result.headers["x-datalox-decision"] == expected_read_decision
        assert result.json()["id"] == "result_live"

        write = client.post("/labstep/reports", json=report)
        assert write.status_code == 202
        assert write.headers["x-datalox-decision"] == "shadow_write"

        read = client.get("/labstep/reports")
        assert read.status_code == 200
        assert read.headers["x-datalox-decision"] == "shadow_read"
        assert read.json() == report


def _start_session(
    *,
    example: str,
    out_dir: Path,
    env: dict[str, str],
    allow_live: bool,
) -> dict[str, Any]:
    args = ["session", "start", "--example", example, "--out", str(out_dir), "--json"]
    if allow_live:
        args.append("--allow-live")
    result = _run_cli(args, env=env)
    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert payload["server"]["pid"] > 0
    return payload


def _stop_session(run_dir: Path, *, env: dict[str, str]) -> None:
    stopped = _run_cli(["session", "stop", "--run", str(run_dir), "--json"], env=env)
    assert stopped.returncode == 0, stopped.stderr or stopped.stdout


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


def _examples_env(examples_dir: Path, *, token: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["DATALOX_GATE_EXAMPLES_DIR"] = str(examples_dir)
    if token is None:
        env.pop("DATALOX_TEST_TOKEN", None)
    else:
        env["DATALOX_TEST_TOKEN"] = token
    return env


def _ledger_decisions(run_dir: Path) -> set[str]:
    decisions: set[str] = set()
    with (run_dir / "ledger.jsonl").open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            if raw_line.strip():
                event = json.loads(raw_line)
                decisions.add(event["decision"]["kind"])
    return decisions


def _assert_no_secret_in_tree(root: Path, secret: str) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        assert secret.encode("utf-8") not in data, f"secret leaked into {path}"


def _wait_for_upstream_health(upstream: FakeUpstream) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        if not upstream.thread.is_alive():
            raise AssertionError("fake upstream exited before health check passed")
        try:
            response = httpx.get(f"{upstream.base_url}/_health", timeout=0.5)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.05)
    raise AssertionError("fake upstream did not become healthy")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
