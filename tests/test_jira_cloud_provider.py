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
PROBE = ROOT / "probes" / "jira_cloud.json"
HELPER = ROOT / "scripts" / "providers" / "jira-cloud-sandbox.sh"
SITE_URL = "https://datalox-fixture.atlassian.net"
TEST_TOKEN = "jira-cloud-test-token-that-must-not-be-echoed"
FIXTURE_IDS = {
    "account_id": "account-fixture-101",
    "approval_id": "201",
    "group_id": "group-fixture-202",
    "issue_key": "DLX-101",
    "issue_type_id": "10001",
    "jira_comment_id": "301",
    "project_id": "10000",
    "project_key": "DLX",
    "queue_id": "401",
    "request_comment_id": "501",
    "request_key": "DLX-102",
    "request_type_id": "601",
    "service_desk_id": "701",
    "sla_metric_id": "801",
    "status_id": "901",
    "workflow_scheme_id": "1001",
}


def test_probe_schema_and_helper_validation_agree_on_exact_counts() -> None:
    payload = _probe_payload()
    config = load_probe_config(PROBE)

    result = _run_helper("validate")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "get_only": True,
        "kind": "jira_cloud_probe_validation_v0",
        "request_counts": {"base": 12, "fixture": 35},
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "jira_cloud"
    assert payload["base_url"] == config.base_url == "https://{jira_site}.atlassian.net"
    assert len(config.probe_requests) == config.rate_budget.max_requests == 12


def test_all_requests_are_get_only_and_core_jira_and_jsm_families_are_present() -> None:
    payload = _probe_payload()
    requests = [
        *payload["probe_requests"],
        *payload["fixture_expansions"]["probe_requests"],
    ]

    assert len(requests) == 47
    assert {request["method"] for request in requests} == {"GET"}
    assert all(isinstance(request["query"], dict) for request in requests)
    paths = {request["path"] for request in requests}
    required_paths = {
        "/rest/api/3/project/search",
        "/rest/api/3/issuetype/project",
        "/rest/api/3/field/search",
        "/rest/api/3/users/search",
        "/rest/api/3/group/bulk",
        "/rest/api/3/group/member",
        "/rest/api/3/search/jql",
        "/rest/api/3/issue/{issue_key}",
        "/rest/api/3/issue/{issue_key}/comment",
        "/rest/api/3/issue/{issue_key}/transitions",
        "/rest/api/3/statuses/search",
        "/rest/api/3/workflows/search",
        "/rest/api/3/workflowscheme/project",
        "/rest/servicedeskapi/servicedesk",
        "/rest/servicedeskapi/servicedesk/{service_desk_id}/requesttype",
        "/rest/servicedeskapi/servicedesk/{service_desk_id}/queue",
        "/rest/servicedeskapi/request",
        "/rest/servicedeskapi/request/{request_key}/comment",
        "/rest/servicedeskapi/request/{request_key}/approval",
        "/rest/servicedeskapi/request/{request_key}/sla",
    }
    assert required_paths.issubset(paths)


def test_pagination_parameters_match_jira_and_jsm_families() -> None:
    payload = _probe_payload()
    requests = [
        *payload["probe_requests"],
        *payload["fixture_expansions"]["probe_requests"],
    ]

    jira_pages = [
        request
        for request in requests
        if request["path"].startswith("/rest/api/3")
        and ("startAt" in request["query"] or request["path"] == "/rest/api/3/search/jql")
    ]
    jsm_pages = [
        request
        for request in requests
        if request["path"].startswith("/rest/servicedeskapi") and "start" in request["query"]
    ]
    assert jira_pages
    assert all("limit" not in request["query"] for request in jira_pages)
    assert jsm_pages
    assert all({"start", "limit"}.issubset(request["query"]) for request in jsm_pages)
    search = next(request for request in requests if request["path"] == "/rest/api/3/search/jql")
    assert "startAt" not in search["query"]
    assert search["query"]["maxResults"] == "50"


def test_render_base_is_concrete_get_only_private_and_secret_free(tmp_path: Path) -> None:
    out_path = tmp_path / "jira-base.json"

    result = _run_helper("render", "--out", str(out_path), env={"JIRA_CLOUD_SITE_URL": SITE_URL})

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert rendered["base_url"] == SITE_URL
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 12
    assert "fixture_expansions" not in rendered
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


def test_render_full_manifest_resolves_every_detail_with_exact_budget(tmp_path: Path) -> None:
    manifest = tmp_path / "ids.json"
    manifest.write_text(
        json.dumps({"kind": "jira_cloud_probe_seed_v0", "ids": FIXTURE_IDS}),
        encoding="utf-8",
    )
    out_path = tmp_path / "jira-full.json"

    result = _run_helper(
        "render",
        "--out",
        str(out_path),
        "--seed-manifest",
        str(manifest),
        env={"JIRA_CLOUD_SITE_URL": SITE_URL},
    )

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 47
    assert {request["method"] for request in rendered["probe_requests"]} == {"GET"}
    assert all(value in rendered_text for value in FIXTURE_IDS.values())
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


@pytest.mark.parametrize(
    "url",
    [
        "http://fixture.atlassian.net",
        "https://example.com",
        "https://fixture.atlassian.net.example.com",
        "https://user:secret@fixture.atlassian.net",
        "https://fixture.atlassian.net/path",
        "https://fixture.atlassian.net?token=secret",
    ],
)
def test_non_origin_or_non_atlassian_site_urls_are_rejected(tmp_path: Path, url: str) -> None:
    result = _run_helper(
        "render",
        "--out",
        str(tmp_path / "blocked.json"),
        env={"JIRA_CLOUD_SITE_URL": url},
    )

    _assert_structured_error(result, "unsupported_jira_cloud_site_url")
    _assert_secret_absent(result)


def test_invalid_seed_manifest_is_rejected_without_secret_echo(tmp_path: Path) -> None:
    manifest = tmp_path / "invalid.json"
    manifest.write_text(
        json.dumps({"kind": "jira_cloud_probe_seed_v0", "ids": {"invented_id": "x"}}),
        encoding="utf-8",
    )

    result = _run_helper(
        "render",
        "--out",
        str(tmp_path / "blocked.json"),
        "--seed-manifest",
        str(manifest),
        env={"JIRA_CLOUD_SITE_URL": SITE_URL},
    )

    _assert_structured_error(result, "invalid_seed_manifest")
    _assert_secret_absent(result)


def test_helper_has_no_direct_write_or_author_command() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert not re.search(r"method\s*=\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]", source)
    assert not re.search(r"\.request\(\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]", source)
    assert 'args.command in {"auth-preflight", "probe"}' in source
    assert 'subparsers.add_parser("author"' not in source


def test_helper_is_executable_and_has_valid_bash_syntax() -> None:
    assert os.access(HELPER, os.X_OK)
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


def _assert_no_placeholders(value: Any) -> None:
    assert PLACEHOLDER_PATTERN.search(json.dumps(value, sort_keys=True)) is None


PLACEHOLDER_PATTERN = re.compile(r"\{[a-z][a-z0-9_]*\}")


def _assert_secret_absent(
    result: subprocess.CompletedProcess[str], rendered_text: str = ""
) -> None:
    assert TEST_TOKEN not in result.stdout
    assert TEST_TOKEN not in result.stderr
    assert TEST_TOKEN not in rendered_text


def _assert_structured_error(result: subprocess.CompletedProcess[str], expected_code: str) -> None:
    assert result.returncode == 1
    payload = json.loads(result.stderr)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == expected_code


def _run_helper(
    *args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    child_env = os.environ.copy()
    for name in (
        "JIRA_CLOUD_API_TOKEN",
        "JIRA_CLOUD_EMAIL",
        "JIRA_CLOUD_GROUP_ID",
        "JIRA_CLOUD_ISSUE_TYPE_ID",
        "JIRA_CLOUD_PROJECT_KEY",
        "JIRA_CLOUD_QUEUE_ID",
        "JIRA_CLOUD_REQUEST_TYPE_ID",
        "JIRA_CLOUD_SERVICE_DESK_ID",
        "JIRA_CLOUD_SITE_URL",
    ):
        child_env.pop(name, None)
    child_env["JIRA_CLOUD_API_TOKEN"] = TEST_TOKEN
    child_env.update(env or {})
    return subprocess.run(
        ["bash", str(HELPER), *args],
        cwd=ROOT,
        env=child_env,
        text=True,
        capture_output=True,
        check=False,
    )
