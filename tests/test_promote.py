import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from datalox_gated_runtime.capture import CaptureStore, LiveCaptureClient
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.promote import promote_session
from datalox_gated_runtime.runtime import GatedRuntime

REPO_ROOT = Path(__file__).resolve().parents[1]


def _build_capture_run(
    run_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    extra_shadow_writes: list[tuple[str, object]] | None = None,
) -> None:
    run_dir.mkdir(parents=True)
    source_config = {
        "config_id": "capture_source",
        "metadata": {"source": "test"},
        "response_cases": [],
        "audit_rules": [],
        "policy": {
            "deny": [
                {
                    "method": "POST",
                    "path_prefix": "/danger/",
                    "reason_code": "danger_denied",
                    "message": "Dangerous writes are denied.",
                }
            ],
            "shadow_write": [{"method": "POST", "path_prefix": "/github/issues/"}],
            "live_capture": [{"path_prefix": "/github/"}],
        },
        "live": {
            "upstreams": {
                "github": {
                    "base_url": "https://api.github.test",
                    "auth_env": "TEST_GITHUB_TOKEN",
                }
            }
        },
    }
    (run_dir / "gate_config.json").write_text(
        json.dumps(source_config, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (run_dir / "task.json").write_text(
        json.dumps(
            {
                "task_id": "capture_task",
                "title": "Capture task",
                "instructions": "Use the gated API.",
                "success_criteria": ["Evidence is captured."],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("TEST_GITHUB_TOKEN", "tok-test")
    config = load_gate_config(run_dir / "gate_config.json")
    assert config.live is not None

    call_counts: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        key = str(request.url)
        call_counts[key] = call_counts.get(key, 0) + 1
        if request.url.path == "/repos/o/r" and request.url.params.get("page") == "1":
            body = {
                "id": "repo-1",
                "name": "latest-page-1" if call_counts[key] == 2 else "first-page-1",
            }
        elif request.url.path == "/repos/o/r" and request.url.params.get("page") == "2":
            body = {"id": "repo-2", "name": "page-2"}
        else:
            body = {"path": request.url.path}
        return httpx.Response(200, json=body, headers={"content-type": "application/json"})

    runtime = GatedRuntime(
        policy=GatePolicy.from_config(config.policy, allow_live=True),
        capture_client=LiveCaptureClient(config.live, transport=httpx.MockTransport(handler)),
        capture_store=CaptureStore(run_dir / "captures.jsonl"),
        ledger=SessionLedger(path=run_dir / "ledger.jsonl"),
    )

    runtime.handle(CallRequest(method="GET", path="/github/repos/o/r", query={"page": "1"}))
    runtime.handle(
        CallRequest(
            method="GET",
            path="/github/repos/o/r",
            query={"page": "2", "label": ["bug", "help wanted"]},
        )
    )
    runtime.handle(CallRequest(method="GET", path="/github/repos/o/r", query={"page": "1"}))
    runtime.handle(
        CallRequest(
            method="POST",
            path="/github/issues/1",
            body={
                "state": "closed",
                "count": 1,
                "verified": True,
                "nested": {"ignored": True},
            },
        )
    )
    runtime.handle(CallRequest(method="GET", path="/github/issues/1"))
    for path, body in extra_shadow_writes or []:
        runtime.handle(CallRequest(method="POST", path=path, body=body))
    runtime.handle(CallRequest(method="POST", path="/danger/payments", body={"amount": 99}))

    (run_dir / "audit.json").write_text(
        json.dumps(
            {
                "passed": True,
                "verifier_type": "config_post_run_audit",
                "checks": {"no_missed_calls": True},
                "failure_codes": [],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_promote_emits_loadable_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_capture_run(run_dir, monkeypatch)

    summary = promote_session(run_dir=run_dir, out_dir=out_dir)

    config = load_gate_config(out_dir / "gate_config.json")
    assert config.config_id == "capture_source_promoted"
    assert config.live is None
    assert config.policy is not None
    assert config.policy.live_capture == []
    assert len(config.policy.deny) == 1
    assert len(config.response_cases) == 2
    assert {case.query["page"] for case in config.response_cases} == {"1", "2"}
    assert next(case for case in config.response_cases if case.query["page"] == "2").query == {
        "label": ("bug", "help wanted"),
        "page": "2",
    }
    assert any(
        case.body == {"id": "repo-1", "name": "latest-page-1"} for case in config.response_cases
    )
    assert all(
        case.evidence_ref is not None and case.evidence_ref.startswith("live:")
        for case in config.response_cases
    )
    assert all(rule["draft"] is True for rule in config.audit_rules)
    assert {rule["type"] for rule in config.audit_rules} >= {
        "require_call",
        "require_shadow_write",
        "forbid_call",
    }
    assert any(
        rule["type"] == "require_shadow_write"
        and rule["body_contains"] == {"state": "closed", "count": 1, "verified": True}
        for rule in config.audit_rules
    )

    replay_script = json.loads((out_dir / "replay_script.json").read_text(encoding="utf-8"))
    assert replay_script[0]["method"] == "GET"
    assert replay_script[0]["query"] == {"page": "1"}
    assert replay_script[1]["query"] == {"label": ["bug", "help wanted"], "page": "2"}
    assert "body" in replay_script[0]
    assert len(replay_script) == 6

    task = json.loads((out_dir / "task.json").read_text(encoding="utf-8"))
    assert task["task_id"] == "capture_task_promoted"
    assert task["title"].startswith("[DRAFT] ")

    assert summary == {
        "response_case_count": 2,
        "mcp_response_case_count": 0,
        "draft_rule_count": len(config.audit_rules),
        "replay_step_count": 6,
        "out_dir": str(out_dir),
    }


def test_promote_refuses_non_empty_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "run"
    _build_capture_run(run_dir, monkeypatch)

    for filename in ("gate_config.json", "task.json", "replay_script.json"):
        out_dir = tmp_path / filename
        out_dir.mkdir()
        (out_dir / filename).write_text("{}", encoding="utf-8")

        with pytest.raises(ValueError, match="already contains"):
            promote_session(run_dir=run_dir, out_dir=out_dir)


def test_promote_skips_unsatisfiable_shadow_write_rule_for_non_dict_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    shadow_bodies = [
        ("/github/issues/list-body", ["closed", "verified"]),
        ("/github/issues/string-body", "closed"),
        ("/github/issues/null-body", None),
    ]
    _build_capture_run(run_dir, monkeypatch, extra_shadow_writes=shadow_bodies)

    promote_session(run_dir=run_dir, out_dir=out_dir)

    config = load_gate_config(out_dir / "gate_config.json")
    require_shadow_write_paths = {
        rule["path"] for rule in config.audit_rules if rule["type"] == "require_shadow_write"
    }
    assert "/github/issues/1" in require_shadow_write_paths
    for path, _body in shadow_bodies:
        assert path not in require_shadow_write_paths

    replay_script = json.loads((out_dir / "replay_script.json").read_text(encoding="utf-8"))
    replay_writes_by_path = {
        step["path"]: step["body"]
        for step in replay_script
        if step["method"] == "POST" and step["path"] in {path for path, _body in shadow_bodies}
    }
    assert replay_writes_by_path == dict(shadow_bodies)


def test_promote_requires_captures(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "gate_config.json").write_text(
        json.dumps({"config_id": "empty", "response_cases": [], "audit_rules": []}),
        encoding="utf-8",
    )
    (run_dir / "task.json").write_text(
        json.dumps({"task_id": "t", "title": "T"}),
        encoding="utf-8",
    )
    (run_dir / "ledger.jsonl").write_text("", encoding="utf-8")
    (run_dir / "audit.json").write_text(json.dumps({"passed": True}), encoding="utf-8")

    with pytest.raises(ValueError, match="no captures"):
        promote_session(run_dir=run_dir, out_dir=tmp_path / "env")


def test_promote_requires_passing_finalized_run(tmp_path: Path) -> None:
    for passed in (None, False):
        run_dir = tmp_path / f"run-{passed}"
        run_dir.mkdir()
        (run_dir / "gate_config.json").write_text(
            json.dumps({"config_id": "blocked", "response_cases": [], "audit_rules": []}),
            encoding="utf-8",
        )
        (run_dir / "task.json").write_text(
            json.dumps({"task_id": "t", "title": "T"}),
            encoding="utf-8",
        )
        (run_dir / "ledger.jsonl").write_text("", encoding="utf-8")
        if passed is not None:
            (run_dir / "audit.json").write_text(json.dumps({"passed": passed}), encoding="utf-8")

        with pytest.raises(ValueError, match="passing audit"):
            promote_session(run_dir=run_dir, out_dir=tmp_path / f"env-{passed}")


def test_promote_cli_json_outputs_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "run"
    out_dir = tmp_path / "env"
    _build_capture_run(run_dir, monkeypatch)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "promote",
            "--run",
            str(run_dir),
            "--out",
            str(out_dir),
            "--json",
        ],
        check=False,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["response_case_count"] == 2
    assert payload["draft_rule_count"] > 0
    assert payload["replay_step_count"] == 6
    assert payload["out_dir"] == str(out_dir)


def test_promote_cli_existing_file_target_returns_json_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "run"
    out_path = tmp_path / "env"
    _build_capture_run(run_dir, monkeypatch)
    out_path.write_text("not a directory", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "session",
            "promote",
            "--run",
            str(run_dir),
            "--out",
            str(out_path),
            "--json",
        ],
        check=False,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "command_failed"
    assert (
        str(out_path) in payload["error"]["message"]
        or "not a directory" in payload["error"]["message"]
    )
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr
