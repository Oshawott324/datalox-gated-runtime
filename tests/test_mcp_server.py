import asyncio
import hashlib
import json
import subprocess
import sys
from inspect import Parameter
from pathlib import Path
from types import UnionType
from typing import get_args, get_origin

from datalox_gated_runtime.cli import _build_parser
from datalox_gated_runtime.mcp_server import _signature_from_schema, build_server
from datalox_gated_runtime.session import create_session

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "datalox_gated_runtime.cli", *args],
        check=False,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=5,
    )


def _call_tool_json(server, name: str, arguments: dict) -> dict:
    result = asyncio.run(server.call_tool(name, arguments))
    content_blocks = result[0] if isinstance(result, tuple) else result
    assert len(content_blocks) == 1
    return json.loads(content_blocks[0].text)


def _body_digest(body: object) -> str:
    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def test_build_server_returns_expected_fastmcp_name(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )

    server = build_server(run_dir)
    assert server.name == "datalox-gated-runtime"


def test_signature_from_schema_supports_nullable_json_type_union() -> None:
    signature = _signature_from_schema(
        {
            "type": "object",
            "properties": {"protocolId": {"type": ["string", "null"], "format": "uuid"}},
        }
    )

    parameter = signature.parameters["protocolId"]
    assert parameter.default is None
    assert parameter.kind is Parameter.KEYWORD_ONLY
    assert get_origin(parameter.annotation) is UnionType
    assert set(get_args(parameter.annotation)) == {str, type(None)}


def test_mcp_cli_parser_accepts_run_argument(tmp_path: Path) -> None:
    parser = _build_parser()

    args = parser.parse_args(["mcp", "--run", str(tmp_path)])

    assert args.command == "mcp"
    assert args.run == str(tmp_path)


def test_mcp_cli_parser_accepts_allow_live_flag(tmp_path: Path) -> None:
    parser = _build_parser()

    args = parser.parse_args(["mcp", "--run", str(tmp_path), "--allow-live"])

    assert args.command == "mcp"
    assert args.run == str(tmp_path)
    assert args.allow_live is True


def test_gate_request_returns_replay_response_and_appends_ledger(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )
    server = build_server(run_dir)

    result = _call_tool_json(
        server,
        "gate_request",
        {"method": "GET", "path": "/labstep/experiments/exp_current"},
    )

    assert result["status_code"] == 200
    assert result["body"]["id"] == "exp_current"
    assert result["body_sha256"] == _body_digest(result["body"])
    ledger_lines = (run_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(ledger_lines) == 1
    event = json.loads(ledger_lines[0])
    assert event["request"]["method"] == "GET"
    assert event["request"]["path"] == "/labstep/experiments/exp_current"


def test_gate_request_denial_includes_body_digest(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )
    server = build_server(run_dir)

    result = _call_tool_json(
        server,
        "gate_request",
        {"method": "POST", "path": "/robot/move"},
    )

    assert result["status_code"] == 403
    assert result["decision"]["kind"] == "deny"
    assert result["body_sha256"] == _body_digest(result["body"])


def test_gate_request_accepts_non_object_body(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )
    server = build_server(run_dir)

    result = _call_tool_json(
        server,
        "gate_request",
        {"method": "POST", "path": "/benchling/assay-results", "body": ["result_current"]},
    )

    assert result["status_code"] == 202
    event = json.loads((run_dir / "ledger.jsonl").read_text(encoding="utf-8"))
    assert event["request"]["body"] == ["result_current"]
    assert event["shadow_mutation"]["body"] == ["result_current"]


def test_get_task_returns_structured_error_for_missing_json(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )
    (run_dir / "task.json").unlink()
    server = build_server(run_dir)

    result = _call_tool_json(server, "get_task", {})

    assert result == {
        "error": {
            "code": "task_unavailable",
            "message": f"task json not found: {run_dir / 'task.json'}",
        }
    }


def test_get_session_manifest_returns_structured_error_for_corrupt_json(tmp_path: Path) -> None:
    run_dir = tmp_path / "session-run"
    create_session(
        example="lab_ops_stale_result",
        out_dir=run_dir,
        http_port=8765,
    )
    (run_dir / "session_manifest.json").write_text("{", encoding="utf-8")
    server = build_server(run_dir)

    result = _call_tool_json(server, "get_session_manifest", {})

    assert result == {
        "error": {
            "code": "session_manifest_unavailable",
            "message": "invalid session manifest json",
        }
    }


def test_mcp_bad_run_exits_nonzero_without_traceback(tmp_path: Path) -> None:
    result = _run_cli(["mcp", "--run", str(tmp_path / "missing-run")])

    assert result.returncode == 1
    assert result.stderr.startswith("error:")
    assert "Traceback" not in result.stderr
