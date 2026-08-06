"""POSIX-only subprocess lifecycle helpers for local gate servers.

This module records a single server process in ``server.json`` under a run
directory and uses POSIX signals for liveness and termination.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


SERVER_STATE_NAME = "server.json"
SERVER_LOG_NAME = "server.log"
HEALTH_DEADLINE_SECONDS = 10.0
STOP_DEADLINE_SECONDS = 10.0
POLL_INTERVAL_SECONDS = 0.1


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_server(*, run_dir: Path, port: int, allow_live: bool = False) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    state_path = run_dir / SERVER_STATE_NAME
    log_path = run_dir / SERVER_LOG_NAME
    server_token = uuid.uuid4().hex
    command = _server_command(
        run_dir=run_dir, port=port, allow_live=allow_live, server_token=server_token
    )
    existing = _read_server_state(state_path)
    if existing is not None:
        pid = existing.get("pid")
        if isinstance(pid, int) and _server_state_matches_process(existing, run_dir=run_dir):
            raise ValueError(f"server already running for run directory: pid {pid}")
        state_path.unlink(missing_ok=True)

    _ensure_port_available(port)
    run_dir.mkdir(parents=True, exist_ok=True)

    with log_path.open("ab") as log_file:
        child = subprocess.Popen(
            command,
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
        )

    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_health(
            child=child,
            base_url=base_url,
            expected_server_token=server_token,
            deadline_seconds=HEALTH_DEADLINE_SECONDS,
        )
    except ValueError as exc:
        _terminate_child(child)
        raise ValueError(f"{exc}; server log: {log_path}") from exc

    state = {
        "pid": child.pid,
        "port": port,
        "allow_live": allow_live,
        "command": command,
        "run_dir": str(run_dir),
        "started_at": datetime.now(UTC).isoformat(),
        "base_url": base_url,
        "log_path": str(log_path),
        "server_token": server_token,
    }
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    return state


def stop_server(run_dir: Path) -> dict[str, Any]:
    resolved_run_dir = run_dir.resolve()
    state_path = resolved_run_dir / SERVER_STATE_NAME
    state = _read_server_state(state_path)
    if state is None:
        return {"stopped": False, "already_stopped": True}

    pid = state.get("pid")
    if not isinstance(pid, int) or not _server_state_matches_process(
        state, run_dir=resolved_run_dir
    ):
        state_path.unlink(missing_ok=True)
        return {"stopped": False, "already_stopped": True}

    if not _signal_process(pid, signal.SIGTERM):
        state_path.unlink(missing_ok=True)
        return {"stopped": False, "already_stopped": True}

    deadline = time.monotonic() + STOP_DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if not _pid_is_alive(pid):
            state_path.unlink(missing_ok=True)
            return {"stopped": True, "already_stopped": False}
        time.sleep(POLL_INTERVAL_SECONDS)

    if _pid_is_alive(pid):
        if not _server_state_matches_process(state, run_dir=resolved_run_dir):
            state_path.unlink(missing_ok=True)
            return {"stopped": False, "already_stopped": True}
        if not _signal_process(pid, signal.SIGKILL):
            state_path.unlink(missing_ok=True)
            return {"stopped": False, "already_stopped": True}
        kill_deadline = time.monotonic() + 2.0
        while _pid_is_alive(pid) and time.monotonic() < kill_deadline:
            time.sleep(POLL_INTERVAL_SECONDS)
        if _pid_is_alive(pid):
            raise ValueError(f"server process did not terminate after SIGKILL: pid {pid}")

    state_path.unlink(missing_ok=True)
    return {"stopped": True, "already_stopped": False}


def running_server_pid(run_dir: Path) -> int | None:
    run_dir = run_dir.resolve()
    state = _read_server_state(run_dir / SERVER_STATE_NAME)
    if state is None:
        return None
    pid = state.get("pid")
    if isinstance(pid, int) and _server_state_matches_process(state, run_dir=run_dir):
        return pid
    return None


def _read_server_state(state_path: Path) -> dict[str, Any] | None:
    if not state_path.exists():
        return None
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid server state json: {state_path}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"server state must be an object: {state_path}")
    return raw


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_process(pid: int, sig: signal.Signals) -> bool:
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return False
    return True


def _wait_for_health(
    *,
    child: subprocess.Popen[bytes],
    base_url: str,
    expected_server_token: str,
    deadline_seconds: float,
) -> None:
    deadline = time.monotonic() + deadline_seconds
    health_url = f"{base_url}/_datalox/health"
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        returncode = child.poll()
        if returncode is not None:
            raise ValueError(
                f"server process exited before becoming healthy: exit code {returncode}"
            )
        try:
            with urlopen(health_url, timeout=0.5) as response:
                payload = json.loads(response.read().decode("utf-8"))
                if (
                    response.status == 200
                    and isinstance(payload, dict)
                    and payload.get("server_token") == expected_server_token
                ):
                    return
        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            last_error = exc
        time.sleep(POLL_INTERVAL_SECONDS)
    detail = f": {last_error}" if last_error is not None else ""
    raise ValueError(f"server did not become healthy within {deadline_seconds:.0f}s{detail}")


def _server_command(*, run_dir: Path, port: int, allow_live: bool, server_token: str) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "datalox_gated_runtime.cli",
        "serve",
        "--run",
        str(run_dir),
        "--port",
        str(port),
        "--server-token",
        server_token,
    ]
    if allow_live:
        command.append("--allow-live")
    return command


def _ensure_port_available(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ValueError(f"port is already in use: {port}") from exc


def _server_state_matches_process(state: dict[str, Any], *, run_dir: Path) -> bool:
    pid = state.get("pid")
    state_run_dir = state.get("run_dir")
    server_token = state.get("server_token")
    if not isinstance(pid, int):
        return False
    if not isinstance(server_token, str) or not server_token:
        return False
    if state_run_dir != str(run_dir):
        return False
    if not _pid_is_alive(pid):
        return False
    return _process_command_contains_token(pid, server_token)


def _process_command_contains_token(pid: int, server_token: str) -> bool:
    result = subprocess.run(
        ["ps", "-ww", "-p", str(pid), "-o", "command="],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False
    command_line = result.stdout.strip()
    if not command_line:
        return False
    try:
        argv = shlex.split(command_line)
    except ValueError:
        return False
    return server_token in argv


def _terminate_child(child: subprocess.Popen[bytes]) -> None:
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=2.0)
