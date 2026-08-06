import json
import os
import signal
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from datalox_gated_runtime import server_control


REPO_ROOT = Path(__file__).resolve().parents[1]
RESPONSE_CASE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "response_case_state_v0" / "example"


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "datalox_gated_runtime.cli", *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


def test_session_start_serves_and_stop_terminates(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"

    started = _cli(
        "session",
        "start",
        "--example",
        "lab_ops_stale_result",
        "--out",
        str(run_dir),
        "--json",
    )
    assert started.returncode == 0, started.stderr
    payload = json.loads(started.stdout)
    base_url = payload["http_base_url"]
    try:
        assert payload["server"]["pid"] > 0
        assert payload["server"]["allow_live"] is False
        assert Path(payload["server"]["log_path"]) == run_dir / "server.log"
        assert isinstance(payload["server"]["server_token"], str)
        assert len(payload["server"]["server_token"]) == 32
        assert (run_dir / "server.json").exists()
        assert (run_dir / "server.log").exists()

        state = json.loads((run_dir / "server.json").read_text(encoding="utf-8"))
        assert state["server_token"] == payload["server"]["server_token"]

        health = httpx.get(f"{base_url}/_datalox/health", timeout=2.0)
        assert health.status_code == 200
        assert health.json()["server_token"] == payload["server"]["server_token"]

        stopped = _cli("session", "stop", "--run", str(run_dir), "--json")
        assert stopped.returncode == 0, stopped.stderr
        assert json.loads(stopped.stdout)["stopped"] is True
        assert not (run_dir / "server.json").exists()

        try:
            after_stop = httpx.get(f"{base_url}/_datalox/health", timeout=0.5)
        except httpx.HTTPError:
            after_stop = None
        assert after_stop is None or after_stop.status_code != 200
    finally:
        _cli("session", "stop", "--run", str(run_dir))


def test_session_create_and_start_seed_select_distinct_immutable_world_episodes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    examples_dir = tmp_path / "examples"
    example_dir = examples_dir / "response-case"
    shutil.copytree(RESPONSE_CASE_FIXTURE, example_dir)
    source_before = {
        path.relative_to(example_dir): path.read_bytes()
        for path in example_dir.rglob("*")
        if path.is_file()
    }
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(examples_dir))
    created_run = tmp_path / "created"
    started_run = tmp_path / "started"

    created = _cli(
        "session",
        "create",
        "--example",
        "response-case",
        "--out",
        str(created_run),
        "--port",
        "8765",
        "--seed",
        "0",
        "--json",
    )
    started = _cli(
        "session",
        "start",
        "--example",
        "response-case",
        "--out",
        str(started_run),
        "--seed",
        "1",
        "--json",
    )

    assert created.returncode == 0, created.stderr
    assert started.returncode == 0, started.stderr
    started_payload = json.loads(started.stdout)
    try:
        created_task = json.loads((created_run / "task.json").read_text(encoding="utf-8"))
        started_task = json.loads((started_run / "task.json").read_text(encoding="utf-8"))
        assert created_task["task_id"] == "episode-task-0"
        assert started_task["task_id"] == "episode-task-1"
        assert json.loads((created_run / "gate_config.json").read_text())["world"]["seed"] == 0
        assert json.loads((started_run / "gate_config.json").read_text())["world"]["seed"] == 1

        selected_state = httpx.get(
            f"{started_payload['http_base_url']}/incidents/inc-002",
            params={"view": "full"},
            timeout=2.0,
        )
        assert selected_state.status_code == 200
        assert selected_state.json()["data"]["id"] == "inc-002"
    finally:
        _cli("session", "stop", "--run", str(started_run), "--json")

    source_after = {
        path.relative_to(example_dir): path.read_bytes()
        for path in example_dir.rglob("*")
        if path.is_file()
    }
    assert source_after == source_before


@pytest.mark.parametrize(
    ("example", "seed", "error_code"),
    [
        ("response-case", "-1", "invalid_seed"),
        ("lab_ops_stale_result", "0", "seed_not_supported"),
    ],
)
def test_session_seed_errors_are_stable_and_agent_readable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    example: str,
    seed: str,
    error_code: str,
) -> None:
    examples_dir = tmp_path / "examples"
    shutil.copytree(RESPONSE_CASE_FIXTURE, examples_dir / "response-case")
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(examples_dir))
    run_dir = tmp_path / f"run-{error_code}"

    result = _cli(
        "session",
        "create",
        "--example",
        example,
        "--out",
        str(run_dir),
        "--port",
        "8765",
        "--seed",
        seed,
        "--json",
    )

    assert result.returncode == 1
    assert json.loads(result.stdout)["error"]["code"] == error_code
    assert not run_dir.exists()


def test_session_stop_is_idempotent(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    started = _cli(
        "session", "start", "--example", "lab_ops_stale_result", "--out", str(run_dir), "--json"
    )
    assert started.returncode == 0, started.stderr
    try:
        first = _cli("session", "stop", "--run", str(run_dir), "--json")
        assert first.returncode == 0, first.stderr

        second = _cli("session", "stop", "--run", str(run_dir), "--json")

        assert second.returncode == 0
        payload = json.loads(second.stdout)
        assert payload["stopped"] is False
        assert payload["already_stopped"] is True
    finally:
        _cli("session", "stop", "--run", str(run_dir))


def test_session_start_refuses_running_session(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    started = _cli(
        "session", "start", "--example", "lab_ops_stale_result", "--out", str(run_dir), "--json"
    )
    assert started.returncode == 0, started.stderr
    try:
        again = _cli(
            "session", "start", "--example", "lab_ops_stale_result", "--out", str(run_dir), "--json"
        )
        assert again.returncode == 1
        assert "already" in json.loads(again.stdout)["error"]["message"]
    finally:
        _cli("session", "stop", "--run", str(run_dir))


def test_session_start_rejects_occupied_port_without_misleading_state(tmp_path: Path) -> None:
    first_run_dir = tmp_path / "first"
    second_run_dir = tmp_path / "second"
    first = _cli(
        "session",
        "start",
        "--example",
        "lab_ops_stale_result",
        "--out",
        str(first_run_dir),
        "--json",
    )
    assert first.returncode == 0, first.stderr
    first_payload = json.loads(first.stdout)
    try:
        second = _cli(
            "session",
            "start",
            "--example",
            "lab_ops_stale_result",
            "--out",
            str(second_run_dir),
            "--port",
            str(first_payload["server"]["port"]),
            "--json",
        )

        assert second.returncode == 1
        assert "port" in json.loads(second.stdout)["error"]["message"]
        assert not (second_run_dir / "server.json").exists()
    finally:
        _cli("session", "stop", "--run", str(first_run_dir))
        _cli("session", "stop", "--run", str(second_run_dir))


def test_session_stop_removes_stale_state_without_signaling_mismatched_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "server.json").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(server_control.os, "kill", lambda pid, sig: signals.append((pid, sig)))

    stopped = server_control.stop_server(run_dir)

    assert stopped == {"stopped": False, "already_stopped": True}
    assert signals == []
    assert not (run_dir / "server.json").exists()


def test_session_stop_preserves_state_when_sigkill_does_not_terminate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state_path = run_dir / "server.json"
    state_path.write_text(json.dumps({"pid": 12345}), encoding="utf-8")
    monkeypatch.setattr(
        server_control, "_server_state_matches_process", lambda state, run_dir: True
    )
    monkeypatch.setattr(server_control, "_pid_is_alive", lambda pid: True)
    monkeypatch.setattr(server_control, "STOP_DEADLINE_SECONDS", 0.01)
    monkeypatch.setattr(server_control, "POLL_INTERVAL_SECONDS", 0.001)
    monkeypatch.setattr(server_control.os, "kill", lambda pid, sig: None)

    with pytest.raises(ValueError, match="did not terminate"):
        server_control.stop_server(run_dir)

    assert state_path.exists()


def test_session_stop_rechecks_pid_identity_before_sigkill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state_path = run_dir / "server.json"
    state_path.write_text(
        json.dumps(
            {
                "pid": 12345,
                "run_dir": str(run_dir.resolve()),
                "server_token": "token",
            }
        ),
        encoding="utf-8",
    )
    identity_matches = iter([True, False])
    monkeypatch.setattr(
        server_control,
        "_server_state_matches_process",
        lambda state, run_dir: next(identity_matches),
    )
    monkeypatch.setattr(server_control, "_pid_is_alive", lambda pid: True)
    monkeypatch.setattr(server_control, "STOP_DEADLINE_SECONDS", 0.01)
    monkeypatch.setattr(server_control, "POLL_INTERVAL_SECONDS", 0.001)
    signals: list[tuple[int, signal.Signals]] = []

    def fake_kill(pid: int, sig: signal.Signals) -> None:
        signals.append((pid, sig))
        if sig == signal.SIGKILL:
            raise AssertionError("stop_server must recheck pid identity before SIGKILL")

    monkeypatch.setattr(server_control.os, "kill", fake_kill)

    stopped = server_control.stop_server(run_dir)

    assert stopped == {"stopped": False, "already_stopped": True}
    assert signals == [(12345, signal.SIGTERM)]
    assert not state_path.exists()


def test_stop_server_treats_process_lookup_during_sigterm_as_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state_path = run_dir / "server.json"
    state_path.write_text(json.dumps({"pid": 12345}), encoding="utf-8")
    monkeypatch.setattr(
        server_control, "_server_state_matches_process", lambda state, run_dir: True
    )

    def fake_kill(pid: int, sig: int) -> None:
        if sig == signal.SIGTERM:
            raise ProcessLookupError

    monkeypatch.setattr(server_control.os, "kill", fake_kill)

    stopped = server_control.stop_server(run_dir)

    assert stopped == {"stopped": False, "already_stopped": True}
    assert not state_path.exists()


def test_stop_server_does_not_trust_health_token_for_pid_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state_path = run_dir / "server.json"
    state_path.write_text(
        json.dumps(
            {
                "pid": 12345,
                "run_dir": str(run_dir.resolve()),
                "server_token": "token",
                "base_url": "http://127.0.0.1:1",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(server_control, "_pid_is_alive", lambda pid: True)
    monkeypatch.setattr(server_control, "_process_command_contains_token", lambda pid, token: False)
    monkeypatch.setattr(
        server_control, "urlopen", lambda url, timeout: _HealthResponse({"server_token": "token"})
    )

    def fail_if_signaled(pid: int, sig: int) -> None:
        if sig in {signal.SIGTERM, signal.SIGKILL}:
            raise AssertionError("stop_server must not signal a pid with unverified argv identity")

    monkeypatch.setattr(server_control.os, "kill", fail_if_signaled)

    stopped = server_control.stop_server(run_dir)

    assert stopped == {"stopped": False, "already_stopped": True}
    assert not state_path.exists()


def test_running_server_pid_does_not_trust_health_token_for_pid_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "server.json").write_text(
        json.dumps(
            {
                "pid": 12345,
                "run_dir": str(run_dir.resolve()),
                "server_token": "token",
                "base_url": "http://127.0.0.1:1",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(server_control, "_pid_is_alive", lambda pid: True)
    monkeypatch.setattr(server_control, "_process_command_contains_token", lambda pid, token: False)
    monkeypatch.setattr(
        server_control, "urlopen", lambda url, timeout: _HealthResponse({"server_token": "token"})
    )

    assert server_control.running_server_pid(run_dir) is None


def test_wait_for_health_rejects_wrong_server_token(monkeypatch: pytest.MonkeyPatch) -> None:
    child = _PollingChild([None, None, 17])

    monkeypatch.setattr(server_control, "POLL_INTERVAL_SECONDS", 0.001)
    monkeypatch.setattr(
        server_control, "urlopen", lambda url, timeout: _HealthResponse({"server_token": "wrong"})
    )

    with pytest.raises(ValueError, match="exit code 17"):
        server_control._wait_for_health(
            child=child,
            base_url="http://127.0.0.1:8765",
            expected_server_token="expected",
            deadline_seconds=1.0,
        )


def test_process_command_token_match_rejects_substring_overlap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="python -m server --server-token prefixabc123suffix"
        )

    monkeypatch.setattr(server_control.subprocess, "run", fake_run)

    assert server_control._process_command_contains_token(123, "abc123") is False


@dataclass
class _PollingChild:
    returncodes: list[int | None]

    def poll(self) -> int | None:
        if len(self.returncodes) == 1:
            return self.returncodes[0]
        return self.returncodes.pop(0)


class _HealthResponse:
    status = 200

    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> "_HealthResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None
