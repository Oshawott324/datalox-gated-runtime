import json
import subprocess
import sys
from pathlib import Path

from datalox_gated_runtime.session import create_session


def test_session_check_reports_manifest_and_config(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(example="lab_ops_stale_result", out_dir=run_dir, http_port=8765)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "check",
            "--run",
            str(run_dir),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0

    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["manifest_exists"] is True
    assert payload["gate_config_valid"] is True
    assert payload["response_case_count"] == 3
    assert payload["expected_surfaces"] == ["http", "mcp"]
    assert payload["http_base_url"] == "http://127.0.0.1:8765"
    assert payload["commands"]["check"].endswith("--json")
    assert payload["commands"]["serve"].startswith("datalox-gate serve")


def test_session_check_non_json_prints_session_ready(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(example="lab_ops_stale_result", out_dir=run_dir, http_port=8765)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "check",
            "--run",
            str(run_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Session ready" in result.stdout


def test_session_check_missing_run_returns_command_failed(tmp_path: Path) -> None:
    missing_run = tmp_path / "missing_run"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "check",
            "--run",
            str(missing_run),
            "--json",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "command_failed"


def test_session_check_missing_run_non_json_returns_command_failed(tmp_path: Path) -> None:
    missing_run = tmp_path / "missing_run"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "check",
            "--run",
            str(missing_run),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stderr.startswith("error:")
    assert "Traceback" not in result.stderr


def test_session_check_invalid_gate_config_reports_not_ready_json(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(example="lab_ops_stale_result", out_dir=run_dir, http_port=8765)
    (run_dir / "gate_config.json").write_text("{", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "check",
            "--run",
            str(run_dir),
            "--json",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["manifest_exists"] is True
    assert payload["gate_config_valid"] is False
    assert payload["error"]["code"] == "invalid_gate_config"
    assert "invalid gate config json" in payload["error"]["message"]


def test_session_check_invalid_gate_config_non_json_returns_command_failed(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    create_session(example="lab_ops_stale_result", out_dir=run_dir, http_port=8765)
    (run_dir / "gate_config.json").write_text("{", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "check",
            "--run",
            str(run_dir),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stderr.startswith("error:")
    assert "invalid gate config json" in result.stderr
