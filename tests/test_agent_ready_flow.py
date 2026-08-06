import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx


def test_agent_ready_http_flow(tmp_path: Path) -> None:
    port = _free_port()
    run_dir = tmp_path / "run"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "create",
            "--example",
            "lab_ops_stale_result",
            "--out",
            str(run_dir),
            "--port",
            str(port),
        ],
        check=True,
    )

    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "serve",
            "--run",
            str(run_dir),
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_health(port, server)
        with httpx.Client(base_url=f"http://127.0.0.1:{port}") as client:
            assert client.get("/labstep/experiments/exp_current").status_code == 200
            assert client.get("/instrument/results/result_current").status_code == 200
            assert (
                client.post(
                    "/benchling/assay-results",
                    json={
                        "experiment_id": "exp_current",
                        "source_result_id": "result_current",
                        "value": 0.82,
                    },
                ).status_code
                == 202
            )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "datalox_gated_runtime.cli",
                "session",
                "finalize",
                "--run",
                str(run_dir),
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        audit = json.loads(result.stdout)
        assert audit["passed"] is True
    finally:
        _stop_server(server)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_health(port: int, server: subprocess.Popen[str]) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        if server.poll() is not None:
            stdout, stderr = server.communicate()
            raise AssertionError(
                "server exited before becoming healthy\n"
                f"exit_code: {server.returncode}\n"
                f"stdout:\n{stdout}\n"
                f"stderr:\n{stderr}"
            )
        try:
            response = httpx.get(f"http://127.0.0.1:{port}/_datalox/health", timeout=0.5)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.1)
    stdout, stderr = _stop_server(server)
    raise AssertionError(
        "server did not become healthy\n"
        f"exit_code: {server.returncode}\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}"
    )


def _stop_server(server: subprocess.Popen[str]) -> tuple[str, str]:
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)
    return server.communicate()
