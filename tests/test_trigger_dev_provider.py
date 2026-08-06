from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from datalox_gated_runtime.provider_probe import load_probe_config


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "probes" / "trigger_dev.json"
HELPER = ROOT / "scripts" / "providers" / "trigger-dev-sandbox.sh"
CANONICAL_API_URL = "https://api.trigger.dev"
ENVIRONMENT_SECRET = "tr_dev_test_secret"
PAT_SECRET = "tr_pat_test_access"


def test_probe_json_and_helper_validation_agree() -> None:
    payload = _probe_payload()
    config = load_probe_config(PROBE)

    result = _run_helper("validate")

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt == {
        "get_only": True,
        "kind": "trigger_dev_probe_validation_v0",
        "request_counts": {"base": 13, "fixture": 12, "pat": 2},
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "trigger_dev"
    assert payload["base_url"] == config.base_url == CANONICAL_API_URL
    assert len(config.probe_requests) == config.rate_budget.max_requests == 13


def test_all_probe_sections_are_get_only_and_use_only_official_routes() -> None:
    payload = _probe_payload()
    sections = {
        "base": payload["probe_requests"],
        "fixture": payload["fixture_expansions"]["probe_requests"],
        "pat": payload["pat_capture"]["probe_requests"],
    }

    assert {name: len(requests) for name, requests in sections.items()} == {
        "base": 13,
        "fixture": 12,
        "pat": 2,
    }
    for requests in sections.values():
        assert requests
        assert {request["method"] for request in requests} == {"GET"}
        assert all(isinstance(request["query"], dict) for request in requests)

    paths = {request["path"] for requests in sections.values() for request in requests}
    assert paths == {
        "/api/v1/batches/{batch_id}",
        "/api/v1/batches/{batch_id}/results",
        "/api/v1/deployments",
        "/api/v1/deployments/latest",
        "/api/v1/deployments/{deployment_id}",
        "/api/v1/errors",
        "/api/v1/errors/{error_id}",
        "/api/v1/projects/{project_ref}/envvars/dev",
        "/api/v1/projects/{project_ref}/envvars/dev/{envvar_name}",
        "/api/v1/query/dashboards",
        "/api/v1/query/schema",
        "/api/v1/queues",
        "/api/v1/queues/{queue_param}",
        "/api/v1/runs",
        "/api/v1/runs/{run_id}/events",
        "/api/v1/runs/{run_id}/result",
        "/api/v1/runs/{run_id}/trace",
        "/api/v1/schedules",
        "/api/v1/schedules/{schedule_id}",
        "/api/v1/sessions",
        "/api/v1/sessions/{session_id}",
        "/api/v1/timezones",
        "/api/v1/waitpoints/tokens",
        "/api/v1/waitpoints/tokens/{waitpoint_id}",
        "/api/v3/runs/{run_id}",
    }

    guessed_routes = (
        "/attempts",
        "/metadata",
        "/tags",
        "/api/v2/batches",
        "/whoami",
    )
    assert not any(route in path for path in paths for route in guessed_routes)
    assert "/api/v1/projects" not in paths
    assert not any(re.fullmatch(r"/api/v1/projects/[^/]+", path) for path in paths)
    assert not any("/projects/" in path and path.endswith("/environments") for path in paths)


@pytest.mark.parametrize(
    ("auth_kind", "credential_name", "secret", "expected_profile", "expected_count"),
    [
        ("environment", "TRIGGER_SECRET_KEY", ENVIRONMENT_SECRET, "trigger_dev_environment", 13),
        ("pat", "TRIGGER_ACCESS_TOKEN", PAT_SECRET, "trigger_dev_pat", 1),
    ],
)
def test_render_selects_auth_without_persisting_secrets(
    tmp_path: Path,
    auth_kind: str,
    credential_name: str,
    secret: str,
    expected_profile: str,
    expected_count: int,
) -> None:
    out_path = tmp_path / f"{auth_kind}.json"
    env = {
        credential_name: secret,
        "TRIGGER_PROJECT_REF": "proj_test",
    }

    result = _run_helper(
        "render",
        "--auth-kind",
        auth_kind,
        "--out",
        str(out_path),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    rendered = json.loads(out_path.read_text(encoding="utf-8"))
    receipt = json.loads(result.stdout)
    assert receipt["probe_request_count"] == expected_count
    assert rendered["auth_profile"] == expected_profile
    assert rendered["rate_budget"]["max_requests"] == expected_count
    assert "fixture_expansions" not in rendered
    assert "pat_capture" not in rendered
    assert secret not in result.stdout
    assert secret not in result.stderr
    assert secret not in out_path.read_text(encoding="utf-8")


def test_environment_render_substitutes_all_seed_fixture_ids(tmp_path: Path) -> None:
    project_ref = "proj_fixture"
    fixture_ids = {
        "run_id": "run-fixture",
        "batch_id": "batch-fixture",
        "deployment_id": "deployment-fixture",
        "error_id": "error-fixture",
        "queue_param": "queue-fixture",
        "schedule_id": "schedule-fixture",
        "session_id": "session-fixture",
        "waitpoint_id": "waitpoint-fixture",
        "envvar_name": "FIXTURE_ENVVAR",
    }
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "api_url": CANONICAL_API_URL,
                "ids": fixture_ids,
                "kind": "trigger_dev_probe_seed_v0",
                "project_ref": project_ref,
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "rendered.json"

    result = _run_helper(
        "render",
        "--out",
        str(out_path),
        "--seed-manifest",
        str(seed_path),
        env={"TRIGGER_PROJECT_REF": project_ref, "TRIGGER_SECRET_KEY": ENVIRONMENT_SECRET},
    )

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 25
    _assert_no_placeholders(rendered["probe_requests"])
    assert all(
        value in rendered_text for name, value in fixture_ids.items() if name != "envvar_name"
    )
    assert ENVIRONMENT_SECRET not in rendered_text


def test_pat_render_with_fixture_ids_has_exact_budget_and_no_placeholders(tmp_path: Path) -> None:
    fixture_ids = {
        "run_id": "run-fixture",
        "batch_id": "batch-fixture",
        "deployment_id": "deployment-fixture",
        "error_id": "error-fixture",
        "queue_param": "queue-fixture",
        "schedule_id": "schedule-fixture",
        "session_id": "session-fixture",
        "waitpoint_id": "waitpoint-fixture",
        "envvar_name": "FIXTURE_ENVVAR",
    }
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "api_url": CANONICAL_API_URL,
                "ids": fixture_ids,
                "kind": "trigger_dev_probe_seed_v0",
                "project_ref": "proj_fixture",
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "pat.json"

    result = _run_helper(
        "render",
        "--auth-kind",
        "pat",
        "--out",
        str(out_path),
        "--seed-manifest",
        str(seed_path),
        env={"TRIGGER_PROJECT_REF": "proj_fixture", "TRIGGER_ACCESS_TOKEN": PAT_SECRET},
    )

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 2
    _assert_no_placeholders(rendered["probe_requests"])
    assert fixture_ids["envvar_name"] in rendered_text
    assert PAT_SECRET not in rendered_text


@pytest.mark.parametrize(
    ("args", "env", "expected_code"),
    [
        (
            ("render", "--out", "rendered.json"),
            {
                "TRIGGER_API_URL": f"https://user:{ENVIRONMENT_SECRET}@api.trigger.dev",
                "TRIGGER_SECRET_KEY": ENVIRONMENT_SECRET,
            },
            "unsupported_trigger_api_url",
        ),
        (
            ("auth-preflight", "--auth-kind", "pat"),
            {"TRIGGER_PROJECT_REF": "proj_test", "TRIGGER_SECRET_KEY": ENVIRONMENT_SECRET},
            "missing_env",
        ),
    ],
)
def test_render_and_auth_failures_are_structured_without_secret_echo(
    tmp_path: Path,
    args: tuple[str, ...],
    env: dict[str, str],
    expected_code: str,
) -> None:
    resolved_args = tuple(str(tmp_path / arg) if arg == "rendered.json" else arg for arg in args)

    result = _run_helper(*resolved_args, env=env)

    assert result.returncode == 1
    payload = json.loads(result.stderr)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == expected_code
    assert ENVIRONMENT_SECRET not in result.stdout
    assert ENVIRONMENT_SECRET not in result.stderr
    assert not (tmp_path / "rendered.json").exists()


@pytest.mark.parametrize(
    ("auth_kind", "credential_name", "malformed_secret"),
    [
        ("environment", "TRIGGER_SECRET_KEY", "tr_pat_wrong_environment_prefix"),
        ("pat", "TRIGGER_ACCESS_TOKEN", "tr_dev_wrong_pat_prefix"),
    ],
)
def test_malformed_credential_prefixes_are_rejected_without_echo(
    auth_kind: str,
    credential_name: str,
    malformed_secret: str,
) -> None:
    result = _run_helper(
        "auth-preflight",
        "--auth-kind",
        auth_kind,
        env={credential_name: malformed_secret, "TRIGGER_PROJECT_REF": "proj_test"},
    )

    assert result.returncode == 1
    payload = json.loads(result.stderr)
    assert payload["status"] == "blocked"
    assert malformed_secret not in result.stdout
    assert malformed_secret not in result.stderr


def test_helper_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(HELPER)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_embedded_sdk_javascript_has_valid_syntax(tmp_path: Path) -> None:
    helper_text = HELPER.read_text(encoding="utf-8")
    match = re.search(
        r"SDK_SEED_PROGRAM\s*=\s*r(?P<quote>\"\"\"|''')(?P<body>.*?)(?P=quote)",
        helper_text,
        flags=re.DOTALL,
    )
    assert match is not None

    script_path = tmp_path / "sdk-seed-program.mjs"
    script_path.write_text(match.group("body"), encoding="utf-8")
    result = subprocess.run(
        ["node", "--check", str(script_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _assert_no_placeholders(value: Any) -> None:
    if isinstance(value, str):
        assert "{" not in value and "}" not in value
    elif isinstance(value, dict):
        for item in value.values():
            _assert_no_placeholders(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_placeholders(item)


def _probe_payload() -> dict[str, Any]:
    payload = json.loads(PROBE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _run_helper(
    *args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    child_env = os.environ.copy()
    for name in (
        "TRIGGER_ACCESS_TOKEN",
        "TRIGGER_API_URL",
        "TRIGGER_PROJECT_REF",
        "TRIGGER_SECRET_KEY",
    ):
        child_env.pop(name, None)
    child_env.update(env or {})
    return subprocess.run(
        ["bash", str(HELPER), *args],
        cwd=ROOT,
        env=child_env,
        text=True,
        capture_output=True,
        check=False,
    )
