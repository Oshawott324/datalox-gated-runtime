import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from datalox_gated_runtime.cli import _build_parser
from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.session import create_session

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "datalox_gated_runtime.cli", *args],
        check=False,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )


def test_session_create_json_prints_manifest_and_http_base_url(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"

    result = _run_cli(
        [
            "session",
            "create",
            "--example",
            "lab_ops_stale_result",
            "--out",
            str(run_dir),
            "--port",
            "8765",
            "--json",
        ]
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["run_dir"] == str(run_dir.resolve())
    assert payload["http_base_url"] == "http://127.0.0.1:8765"
    assert (run_dir / "session_manifest.json").exists()


def test_session_create_non_json_prints_manifest_path(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"

    result = _run_cli(
        [
            "session",
            "create",
            "--example",
            "lab_ops_stale_result",
            "--out",
            str(run_dir),
            "--port",
            "8765",
        ]
    )

    assert result.returncode == 0
    manifest_path = str(run_dir.resolve() / "session_manifest.json")
    assert manifest_path in result.stdout


def test_session_finalize_json_reports_missing_current_experiment_read_and_writes_audit(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    result = _run_cli(
        [
            "session",
            "finalize",
            "--run",
            str(run_dir),
            "--json",
        ]
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["passed"] is False
    assert "missing_current_experiment_read" in payload["failure_codes"]
    assert (run_dir / "audit.json").exists()


def test_session_finalize_with_real_ledger_writes_run_export_and_passes(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        client.get("/labstep/experiments/exp_current")
        client.get("/instrument/results/result_current")
        response = client.post(
            "/benchling/assay-results",
            json={"experiment_id": "exp_current", "source_result_id": "result_current"},
        )
        assert response.status_code == 202

    result = _run_cli(
        [
            "session",
            "finalize",
            "--run",
            str(run_dir),
            "--json",
        ]
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["checks"]["missing_current_experiment_read"] is True
    assert payload["checks"]["missing_current_result_read"] is True
    assert (run_dir / "run_export.json").exists()
    assert (run_dir / "audit.json").exists()

    run_export = json.loads((run_dir / "run_export.json").read_text(encoding="utf-8"))
    assert run_export["run_id"].startswith("run_")
    assert run_export["events"][0]["request"]["path"] == "/labstep/experiments/exp_current"


def test_session_finalize_fails_when_ledger_contains_missed_call(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        client.get("/labstep/experiments/exp_current")
        client.get("/instrument/results/result_current")
        client.get("/unknown/source")
        response = client.post(
            "/benchling/assay-results",
            json={"experiment_id": "exp_current", "source_result_id": "result_current"},
        )
        assert response.status_code == 202

    result = _run_cli(
        [
            "session",
            "finalize",
            "--run",
            str(run_dir),
            "--json",
        ]
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["passed"] is False
    assert payload["checks"]["no_missed_calls"] is False
    assert "no_missed_calls" in payload["failure_codes"]


def test_session_finalize_fails_when_denied_hardware_call_was_attempted(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    with TestClient(create_app(run_dir)) as client:
        client.get("/labstep/experiments/exp_current")
        client.get("/instrument/results/result_current")
        denied = client.post("/robot/move", json={"axis": "x"})
        response = client.post(
            "/benchling/assay-results",
            json={"experiment_id": "exp_current", "source_result_id": "result_current"},
        )
        assert denied.status_code == 403
        assert response.status_code == 202

    result = _run_cli(
        [
            "session",
            "finalize",
            "--run",
            str(run_dir),
            "--json",
        ]
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["passed"] is False
    assert payload["checks"]["hardware_live_action_attempted"] is False
    assert "hardware_live_action_attempted" in payload["failure_codes"]


def test_serve_parser_defaults_host(tmp_path: Path) -> None:
    parser = _build_parser()
    args = parser.parse_args(["serve", "--run", str(tmp_path), "--port", "8765"])

    assert args.command == "serve"
    assert args.host == "127.0.0.1"
    assert args.port == 8765


def test_serve_parser_rejects_runtime_live_provider_flag(tmp_path: Path) -> None:
    result = _run_cli(
        [
            "serve",
            "--run",
            str(tmp_path),
            "--port",
            "8765",
            "--allow-live",
        ]
    )

    assert result.returncode == 2
    assert "unrecognized arguments: --allow-live" in result.stderr


def test_session_auth_preflight_reports_missing_live_auth_env(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    run_dir.mkdir()
    (run_dir / "gate_config.json").write_text(
        json.dumps(
            {
                "auth_profiles": {
                    "github_token": {
                        "kind": "env_static",
                        "inject": [
                            {
                                "in": "header",
                                "name": "Authorization",
                                "env": "DATALOX_TEST_MISSING_GITHUB_TOKEN",
                                "scheme": "Bearer",
                            }
                        ],
                    }
                },
                "audit_rules": [],
                "config_id": "session_auth_preflight_test",
                "live": {
                    "upstreams": {
                        "github": {
                            "auth_profile": "github_token",
                            "base_url": "https://api.github.test",
                        }
                    }
                },
                "response_cases": [],
            }
        ),
        encoding="utf-8",
    )

    result = _run_cli(["session", "auth-preflight", "--run", str(run_dir), "--json"])

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == "missing_auth_env"
    assert payload["blocker"]["missing_env"] == ["DATALOX_TEST_MISSING_GITHUB_TOKEN"]
    assert payload["auth_preflight"]["status"] == "failed"


def test_create_invalid_example_json_returns_command_failed_payload(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"

    result = _run_cli(
        [
            "session",
            "create",
            "--example",
            "not_real_example",
            "--out",
            str(run_dir),
            "--port",
            "8765",
            "--json",
        ]
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "command_failed"
    assert "Unknown example" in payload["error"]["message"]
    assert "Traceback" not in result.stdout


def test_create_invalid_example_non_json_prints_error_to_stderr(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"

    result = _run_cli(
        [
            "session",
            "create",
            "--example",
            "not_real_example",
            "--out",
            str(run_dir),
            "--port",
            "8765",
        ]
    )

    assert result.returncode == 1
    assert result.stderr.startswith("error:")
    assert "Unknown example" in result.stderr
    assert "Traceback" not in result.stderr
