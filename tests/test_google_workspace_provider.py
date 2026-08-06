from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from datalox_gated_runtime.provider_probe import load_probe_config


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "probes" / "google_workspace.json"
HELPER = ROOT / "scripts" / "providers" / "google-workspace-sandbox.sh"
TEST_TOKEN = "google-workspace-test-token-that-must-not-be-echoed"
FIXTURE_IDS = {
    "calendar_event_id": "event_fixture_101",
    "document_id": "document_fixture_202",
    "drive_folder_id": "folder_fixture_303",
    "gmail_draft_id": "draft_fixture_404",
    "gmail_message_id": "message_fixture_505",
    "gmail_thread_id": "thread_fixture_606",
    "spreadsheet_id": "spreadsheet_fixture_707",
}
EXPECTED_COUNTS = {
    "docs": {"base": 1, "fixture": 0},
    "drive-calendar": {"base": 9, "fixture": 10},
    "gmail": {"base": 5, "fixture": 3},
    "sheets": {"base": 1, "fixture": 0},
}


def test_tracked_probe_schema_and_helper_validation_agree() -> None:
    payload = _probe_payload()
    config = load_probe_config(PROBE)

    result = _run_helper("validate")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "get_only": True,
        "kind": "google_workspace_probe_validation_v0",
        "request_counts": EXPECTED_COUNTS,
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "google_workspace"
    assert payload["base_url"] == config.base_url == "https://www.googleapis.com"
    assert len(config.probe_requests) == config.rate_budget.max_requests == 9


def test_all_manifest_sections_are_get_only_on_discovery_document_hosts() -> None:
    payload = _probe_payload()
    sections = {
        "drive-calendar": payload,
        **payload["service_probes"],
    }
    contracts = {
        "drive-calendar": ("https://www.googleapis.com", ("/calendar/v3", "/drive/v3")),
        "gmail": ("https://gmail.googleapis.com", ("/gmail/v1/users/me",)),
        "docs": ("https://docs.googleapis.com", ("/v1/documents",)),
        "sheets": ("https://sheets.googleapis.com", ("/v4/spreadsheets",)),
    }

    for app, section in sections.items():
        base_url, prefixes = contracts[app]
        assert section["base_url"] == base_url
        requests = [*section["probe_requests"]]
        requests.extend(section.get("fixture_expansions", {}).get("probe_requests", []))
        assert {request["method"] for request in requests} == {"GET"}
        assert all(request["path"].startswith(prefixes) for request in requests)
        assert all(isinstance(request["query"], dict) for request in requests)

    rendered = json.dumps(payload, sort_keys=True).lower()
    assert "admin.googleapis.com" not in rendered
    assert "/admin/directory/" not in rendered
    assert payload["oauth"]["token_acquisition"] == "external_operator_step"
    assert payload["oauth"]["capture_scopes"] == [
        "https://www.googleapis.com/auth/calendar.readonly",
        "https://www.googleapis.com/auth/documents.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/spreadsheets.readonly",
    ]


@pytest.mark.parametrize(
    ("app", "expected_count"),
    [("drive-calendar", 9), ("gmail", 5)],
)
def test_base_render_has_exact_budget_mode_0600_and_no_secret(
    tmp_path: Path,
    app: str,
    expected_count: int,
) -> None:
    out_path = tmp_path / f"{app}.json"

    result = _run_helper(
        "render",
        "--app",
        app,
        "--out",
        str(out_path),
        env={"GOOGLE_WORKSPACE_ACCESS_TOKEN": TEST_TOKEN},
    )

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert (
        len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == expected_count
    )
    assert "fixture_expansions" not in rendered
    assert "service_probes" not in rendered
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_no_placeholders(rendered["probe_requests"])
    _assert_secret_absent(result, rendered_text)


@pytest.mark.parametrize(
    ("app", "expected_count"),
    [("drive-calendar", 19), ("gmail", 8), ("docs", 1), ("sheets", 1)],
)
def test_fixture_render_expands_complete_cross_app_graph(
    tmp_path: Path,
    app: str,
    expected_count: int,
) -> None:
    fixture_path = _write_fixture_manifest(tmp_path / "fixture.json")
    out_path = tmp_path / f"{app}.json"

    result = _run_helper(
        "render",
        "--app",
        app,
        "--fixture-manifest",
        str(fixture_path),
        "--out",
        str(out_path),
        env={"GOOGLE_WORKSPACE_ACCESS_TOKEN": TEST_TOKEN},
    )

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert (
        len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == expected_count
    )
    _assert_no_placeholders(rendered["probe_requests"])
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


@pytest.mark.parametrize("app", ["docs", "sheets"])
def test_metadata_apps_require_fixture_manifest(tmp_path: Path, app: str) -> None:
    result = _run_helper(
        "render",
        "--app",
        app,
        "--out",
        str(tmp_path / f"{app}.json"),
    )

    _assert_structured_error(result, "fixture_manifest_required")


@pytest.mark.parametrize("manifest_case", ["missing", "wrong_kind", "partial_ids", "unsafe_id"])
def test_invalid_fixture_manifest_is_structured(
    tmp_path: Path,
    manifest_case: str,
) -> None:
    fixture_path = tmp_path / "fixture.json"
    payload: dict[str, Any] = {
        "ids": dict(FIXTURE_IDS),
        "kind": "google_workspace_probe_fixture_v0",
        "workspace_user": "probe-user@example.test",
    }
    expected_code = (
        "invalid_json_file" if manifest_case == "missing" else "invalid_fixture_manifest"
    )
    if manifest_case == "wrong_kind":
        payload["kind"] = "other"
    elif manifest_case == "partial_ids":
        payload["ids"].pop("document_id")
    elif manifest_case == "unsafe_id":
        payload["ids"]["document_id"] = "unsafe/id"
    if manifest_case != "missing":
        fixture_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run_helper(
        "render",
        "--app",
        "docs",
        "--fixture-manifest",
        str(fixture_path),
        "--out",
        str(tmp_path / "docs.json"),
    )

    _assert_structured_error(result, expected_code)


def test_auth_preflight_uses_external_env_token_without_echo(tmp_path: Path) -> None:
    config_path = tmp_path / "gmail.json"
    render = _run_helper("render", "--app", "gmail", "--out", str(config_path))
    assert render.returncode == 0, render.stderr

    missing = _run_helper(
        "auth-preflight",
        "--app",
        "gmail",
        "--config",
        str(config_path),
    )
    assert missing.returncode == 1
    assert json.loads(missing.stdout)["blocker"]["code"] == "missing_auth_env"

    completed = _run_helper(
        "auth-preflight",
        "--app",
        "gmail",
        "--config",
        str(config_path),
        env={"GOOGLE_WORKSPACE_ACCESS_TOKEN": TEST_TOKEN},
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "completed"
    _assert_secret_absent(completed, config_path.read_text(encoding="utf-8"))


def test_rendered_config_rejects_arbitrary_host(tmp_path: Path) -> None:
    config_path = tmp_path / "gmail.json"
    result = _run_helper("render", "--app", "gmail", "--out", str(config_path))
    assert result.returncode == 0, result.stderr
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    payload["base_url"] = "https://example.com"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run_helper("validate", "--config", str(config_path))

    _assert_structured_error(result, "unsupported_google_api_host")


def test_helper_only_routes_get_only_probe_actions_and_has_no_oauth_acquisition() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert 'if args.command in {"auth-preflight", "probe"}:' in source
    assert "run_datalox(" in source
    assert "GOOGLE_WORKSPACE_AUTHOR_ACCESS_TOKEN" not in source
    assert "client_secret" not in source.lower()
    assert "refresh_token" not in source.lower()
    assert 'request.get("method") != "GET"' in source
    assert '"POST"' not in source
    assert '"PUT"' not in source
    assert '"PATCH"' not in source
    assert '"DELETE"' not in source


def test_helper_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(HELPER)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def _probe_payload() -> dict[str, Any]:
    payload = json.loads(PROBE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _write_fixture_manifest(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "ids": FIXTURE_IDS,
                "kind": "google_workspace_probe_fixture_v0",
                "workspace_user": "probe-user@example.test",
            }
        ),
        encoding="utf-8",
    )
    return path


def _assert_secret_absent(
    result: subprocess.CompletedProcess[str],
    rendered_text: str = "",
) -> None:
    assert TEST_TOKEN not in result.stdout
    assert TEST_TOKEN not in result.stderr
    assert TEST_TOKEN not in rendered_text


def _assert_no_placeholders(value: Any) -> None:
    assert re.search(r"\{[a-z][a-z0-9_]*\}", json.dumps(value, sort_keys=True)) is None


def _assert_structured_error(
    result: subprocess.CompletedProcess[str],
    expected_code: str,
) -> None:
    assert result.returncode == 1
    payload = json.loads(result.stderr)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == expected_code


def _run_helper(
    *args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    child_env = os.environ.copy()
    child_env.pop("GOOGLE_WORKSPACE_ACCESS_TOKEN", None)
    child_env.update(env or {})
    return subprocess.run(
        ["bash", str(HELPER), *args],
        cwd=ROOT,
        env=child_env,
        text=True,
        capture_output=True,
        check=False,
    )
