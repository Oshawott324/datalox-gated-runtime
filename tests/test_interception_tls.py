import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from provider_runtime_helpers import PROVIDER_ID, build_stateful_provider_bundle

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl is required for TLS DNS override")
def test_real_tls_listener_serves_exact_provider_url_and_unix_control_socket() -> None:
    temporary = TemporaryDirectory(prefix="datalox-tls-", dir="/tmp")
    tmp_path = Path(temporary.name)
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    authority = f"api.provider.example:{port}"
    bundle = build_stateful_provider_bundle(tmp_path, authority=authority)
    run_dir = tmp_path / "run"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "intercept",
            "serve",
            "--bundle",
            str(bundle),
            "--run",
            str(run_dir),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        url = f"https://{authority}/counter"
        response: subprocess.CompletedProcess[str] | None = None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ca_path = run_dir / "certificates/ca.pem"
            if ca_path.is_file():
                response = subprocess.run(
                    [
                        "curl",
                        "--silent",
                        "--show-error",
                        "--noproxy",
                        "*",
                        "--resolve",
                        f"{authority}:127.0.0.1",
                        "--cacert",
                        str(ca_path),
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if response.returncode == 0:
                    break
            if process.poll() is not None:
                break
            time.sleep(0.05)
        assert response is not None and response.returncode == 0, (
            response.stderr if response is not None else process.stderr.read()
        )
        assert json.loads(response.stdout)["counter"] == 1
        assert (run_dir / "control.sock").stat().st_mode & 0o777 == 0o600

        token = (run_dir / "control-token").read_text(encoding="ascii").strip()
        health = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--unix-socket",
                str(run_dir / "control.sock"),
                "-H",
                f"x-datalox-control-token: {token}",
                "http://localhost/health",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert health.returncode == 0, health.stderr
        assert json.loads(health.stdout) == {"ok": True, "providers": [PROVIDER_ID]}

        ready = subprocess.run(
            [
                sys.executable,
                "-m",
                "datalox_gated_runtime.cli",
                "intercept",
                "ready",
                "--run",
                str(run_dir),
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert ready.returncode == 0, ready.stderr
        assert json.loads(ready.stdout) == {"ok": True, "providers": [PROVIDER_ID]}
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        temporary.cleanup()
