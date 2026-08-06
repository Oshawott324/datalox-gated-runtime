import argparse
import json
from pathlib import Path
import shlex

import pytest
from fastapi.testclient import TestClient

from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.session import create_session, load_session_manifest


ROOT = Path(__file__).resolve().parents[1]


def test_create_session_writes_agent_manifest(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"

    manifest = create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    assert manifest.run_dir == str(run_dir)
    assert manifest.http_base_url == "http://127.0.0.1:8765"
    assert "datalox-gate serve" in manifest.commands["serve"]
    assert manifest.commands["check"].endswith("--json")
    assert (run_dir / "task.json").exists()
    assert (run_dir / "gate_config.json").exists()
    assert (run_dir / "session_manifest.json").exists()

    loaded = load_session_manifest(run_dir)
    assert loaded == manifest


def test_create_session_unknown_example_raises_value_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown example: not_real_example"):
        create_session(example="not_real_example", out_dir=tmp_path / "run", http_port=8765)


def test_create_session_manifest_paths_are_absolute(tmp_path: Path) -> None:
    run_dir = tmp_path / "run with space"
    manifest = create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    assert Path(manifest.run_dir).is_absolute()
    assert Path(manifest.task_path).is_absolute()
    assert Path(manifest.gate_config_path).is_absolute()
    assert Path(manifest.ledger_path).is_absolute()
    assert Path(manifest.run_export_path).is_absolute()
    assert Path(manifest.audit_path).is_absolute()


def test_manifest_commands_quote_run_dir_with_space(tmp_path: Path) -> None:
    run_dir = tmp_path / "run with space"
    manifest = create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    quoted = shlex.quote(str(run_dir.resolve()))
    assert quoted in manifest.commands["serve"]
    assert quoted in manifest.commands["check"]
    assert quoted in manifest.commands["finalize"]
    assert quoted in manifest.commands["mcp"]


def test_create_session_rejects_reusing_finalized_run_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
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

    from datalox_gated_runtime.cli import _session_finalize

    assert _session_finalize(argparse.Namespace(run=str(run_dir), json=True)) == 0
    original_ledger = (run_dir / "ledger.jsonl").read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="output directory already contains runtime artifacts"):
        create_session(
            example="lab_ops_stale_result",
            out_dir=run_dir,
            http_port=8765,
        )

    assert (run_dir / "ledger.jsonl").read_text(encoding="utf-8") == original_ledger


def test_load_session_manifest_invalid_json_raises_value_error(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    (run_dir / "session_manifest.json").write_text("{", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid session manifest json"):
        load_session_manifest(run_dir)


def test_load_session_manifest_non_object_json_raises_value_error(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    (run_dir / "session_manifest.json").write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="session manifest must be an object"):
        load_session_manifest(run_dir)


def test_load_session_manifest_missing_field_raises_value_error(tmp_path: Path) -> None:
    manifest = {
        "session_id": "sess_test",
        "run_dir": "/tmp/run",
        "task_path": "/tmp/run/task.json",
        "gate_config_path": "/tmp/run/gate_config.json",
        "ledger_path": "/tmp/run/ledger.jsonl",
        "run_export_path": "/tmp/run/run_export.json",
        "audit_path": "/tmp/run/audit.json",
        "http_base_url": "http://127.0.0.1:8765",
        "commands": {
            "serve": "datalox-gate serve --run /tmp/run",
            "check": "datalox-gate session check --run /tmp/run --json",
            "finalize": "datalox-gate session finalize --run /tmp/run --json",
            "mcp": "datalox-gate mcp --run /tmp/run",
        },
        # missing expected_surfaces
    }
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    (run_dir / "session_manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing required field expected_surfaces"):
        load_session_manifest(run_dir)


def test_load_session_manifest_unknown_field_raises_value_error(tmp_path: Path) -> None:
    manifest = {
        "session_id": "sess_test",
        "run_dir": "/tmp/run",
        "task_path": "/tmp/run/task.json",
        "gate_config_path": "/tmp/run/gate_config.json",
        "ledger_path": "/tmp/run/ledger.jsonl",
        "run_export_path": "/tmp/run/run_export.json",
        "audit_path": "/tmp/run/audit.json",
        "http_base_url": "http://127.0.0.1:8765",
        "commands": {
            "serve": "datalox-gate serve --run /tmp/run",
            "check": "datalox-gate session check --run /tmp/run --json",
            "finalize": "datalox-gate session finalize --run /tmp/run --json",
            "mcp": "datalox-gate mcp --run /tmp/run",
        },
        "expected_surfaces": ["http", "mcp"],
        "bogus": "bad",
    }
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    (run_dir / "session_manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="bogus"):
        load_session_manifest(run_dir)


def test_create_session_requires_task_and_gate_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    example_root = tmp_path / "examples"
    example_root.mkdir()
    example_dir = example_root / "incomplete"
    example_dir.mkdir()
    (example_dir / "task.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(example_root))

    with pytest.raises(ValueError, match="example is incomplete"):
        create_session(
            example="incomplete",
            out_dir=tmp_path / "run",
            http_port=8765,
        )
