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
PROBE = ROOT / "probes" / "posthog.json"
HELPER = ROOT / "scripts" / "providers" / "posthog-sandbox.sh"
TEMPLATE_API_URL = "https://{posthog_region}.posthog.com/api"
TEST_TOKEN = "posthog-test-token-that-must-not-be-echoed"
ORGANIZATION_ID = "org-fixture-101"
PROJECT_ID = "project-fixture-202"
FIXTURE_IDS = {
    "person_id": "person-101",
    "group_key": "group-202",
    "event_id": "event-303",
    "action_id": "action-404",
    "annotation_id": "annotation-505",
    "cohort_id": "cohort-606",
    "dashboard_id": "dashboard-707",
    "insight_id": "insight-808",
    "feature_flag_id": "flag-909",
    "experiment_id": "experiment-1010",
    "survey_id": "survey-1111",
    "recording_id": "recording-1212",
    "early_access_feature_id": "early-access-1313",
    "batch_export_id": "batch-export-1414",
    "hog_function_id": "hog-function-1515",
    "issue_id": "issue-1616",
    "query_id": "query-1717",
}


def test_probe_schema_and_helper_validation_agree_on_exact_counts() -> None:
    payload = _probe_payload()
    config = load_probe_config(PROBE)

    result = _run_helper("validate")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "get_only": True,
        "kind": "posthog_probe_validation_v0",
        "request_counts": {"base": 24, "fixture": 30},
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "posthog"
    assert payload["base_url"] == config.base_url == TEMPLATE_API_URL
    assert len(config.probe_requests) == config.rate_budget.max_requests == 24


def test_all_requests_are_get_only_and_core_families_are_present() -> None:
    payload = _probe_payload()
    sections = {
        "base": payload["probe_requests"],
        "fixture": payload["fixture_expansions"]["probe_requests"],
    }

    assert {name: len(requests) for name, requests in sections.items()} == {
        "base": 24,
        "fixture": 30,
    }
    requests = [request for section in sections.values() for request in section]
    assert {request["method"] for request in requests} == {"GET"}
    assert all(isinstance(request["query"], dict) for request in requests)

    paths = {request["path"] for request in requests}
    assert all(path.startswith(("/organizations/", "/projects/")) for path in paths)
    for core_family in (
        "/organizations/",
        "/persons/",
        "/groups",
        "/events/",
        "/actions/",
        "/annotations/",
        "/cohorts/",
        "/dashboards/",
        "/insights/",
        "/feature_flags/",
        "/experiments/",
        "/surveys/",
        "/session_recordings/",
        "/early_access_feature/",
        "/batch_exports/",
        "/hog_functions/",
        "/error_tracking/issues/",
        "/query/",
    ):
        assert any(core_family in path for path in paths), core_family


def test_render_base_has_exact_budget_mode_and_no_secrets_or_placeholders(
    tmp_path: Path,
) -> None:
    out_path = tmp_path / "posthog-base.json"

    result = _run_helper("render", "--out", str(out_path), env=_valid_env())

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    receipt = json.loads(result.stdout)
    assert receipt["probe_request_count"] == 24
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 24
    assert "fixture_expansions" not in rendered
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


def test_render_fixture_uses_all_config_seed_ids_with_budget_54_and_mode_0600(
    tmp_path: Path,
) -> None:
    seed_path = _write_seed_manifest(tmp_path / "seed.json")
    out_path = tmp_path / "posthog-fixture.json"

    result = _run_helper(
        "render",
        "--out",
        str(out_path),
        "--seed-manifest",
        str(seed_path),
        env=_valid_env(),
    )

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    receipt = json.loads(result.stdout)
    assert receipt["probe_request_count"] == 54
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 54
    assert "fixture_expansions" not in rendered
    assert set(FIXTURE_IDS) == _config_seed_id_keys()
    assert all(value in rendered_text for value in FIXTURE_IDS.values())
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


@pytest.mark.parametrize("region", ["us", "eu"])
def test_supported_regions_are_accepted(tmp_path: Path, region: str) -> None:
    out_path = tmp_path / f"posthog-{region}.json"
    env = _valid_env()
    env["POSTHOG_API_URL"] = f"https://{region}.posthog.com/api"

    result = _run_helper("render", "--out", str(out_path), env=env)

    assert result.returncode == 0, result.stderr
    assert json.loads(out_path.read_text(encoding="utf-8"))["base_url"] == env["POSTHOG_API_URL"]


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/api",
        "https://us.posthog.com.example.com/api",
        "http://us.posthog.com/api",
        "https://us.posthog.com/api/",
    ],
)
def test_arbitrary_or_insecure_hosts_are_rejected_without_secret_echo(
    tmp_path: Path,
    url: str,
) -> None:
    env = _valid_env()
    env["POSTHOG_API_URL"] = url

    result = _run_helper("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_structured_error(result, "unsupported_posthog_api_url")
    _assert_secret_absent(result)


@pytest.mark.parametrize(
    "missing_name",
    ["POSTHOG_PERSONAL_API_KEY", "POSTHOG_ORGANIZATION_ID", "POSTHOG_PROJECT_ID"],
)
def test_missing_required_env_is_rejected_without_secret_echo(
    tmp_path: Path,
    missing_name: str,
) -> None:
    env = _valid_env()
    env.pop(missing_name)

    result = _run_helper("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_structured_error(result, "missing_env")
    _assert_secret_absent(result)


@pytest.mark.parametrize("manifest_case", ["missing", "malformed_json", "malformed_schema"])
def test_invalid_manifest_is_rejected_without_secret_echo(
    tmp_path: Path,
    manifest_case: str,
) -> None:
    seed_path = tmp_path / "seed.json"
    if manifest_case == "malformed_json":
        seed_path.write_text("{not-json", encoding="utf-8")
        expected_code = "invalid_json_file"
    elif manifest_case == "malformed_schema":
        seed_path.write_text(
            json.dumps({"kind": "posthog_probe_seed_v0", "ids": {"unknown_id": "x"}}),
            encoding="utf-8",
        )
        expected_code = "invalid_seed_manifest"
    else:
        expected_code = "invalid_json_file"

    result = _run_helper(
        "render",
        "--out",
        str(tmp_path / "blocked.json"),
        "--seed-manifest",
        str(seed_path),
        env=_valid_env(),
    )

    _assert_structured_error(result, expected_code)
    _assert_secret_absent(result)


def test_helper_uses_runtime_cli_without_provider_residue() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert '"datalox_gated_runtime.cli"' in source
    assert 'if args.command in {"auth-preflight", "probe"}:' in source
    assert "return run_datalox(args.command, args)" in source
    assert "sentry" not in source.lower()
    assert ".requests" not in source
    assert "provider-cli" not in source


def test_helper_only_routes_read_actions_through_datalox() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert not re.search(
        r"run_datalox\(\s*['\"](?:post|put|patch|delete|write)", source, re.IGNORECASE
    )
    assert not re.search(r"['\"](?:POST|PUT|PATCH|DELETE)['\"]", source)


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


def _config_seed_id_keys() -> set[str]:
    base_context = {
        "posthog_region",
        "organization_id",
        "project_id",
        "person_search",
        "group_type_index",
        "event_name",
        "date_from",
        "date_to",
    }
    placeholders = set(re.findall(r"\{([a-z][a-z0-9_]*)\}", json.dumps(_probe_payload())))
    return placeholders - base_context


def _valid_env() -> dict[str, str]:
    return {
        "POSTHOG_PERSONAL_API_KEY": TEST_TOKEN,
        "POSTHOG_ORGANIZATION_ID": ORGANIZATION_ID,
        "POSTHOG_PROJECT_ID": PROJECT_ID,
    }


def _write_seed_manifest(path: Path) -> Path:
    path.write_text(
        json.dumps({"kind": "posthog_probe_seed_v0", "ids": FIXTURE_IDS}),
        encoding="utf-8",
    )
    return path


def _assert_no_placeholders(value: Any) -> None:
    assert re.search(r"\{[a-z][a-z0-9_]*\}", json.dumps(value, sort_keys=True)) is None


def _assert_secret_absent(
    result: subprocess.CompletedProcess[str],
    rendered_text: str = "",
) -> None:
    assert TEST_TOKEN not in result.stdout
    assert TEST_TOKEN not in result.stderr
    assert TEST_TOKEN not in rendered_text


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
    for name in (
        "POSTHOG_API_URL",
        "POSTHOG_PERSONAL_API_KEY",
        "POSTHOG_ORGANIZATION_ID",
        "POSTHOG_PROJECT_ID",
        "POSTHOG_PERSON_SEARCH",
        "POSTHOG_GROUP_TYPE_INDEX",
        "POSTHOG_EVENT_NAME",
        "POSTHOG_DATE_FROM",
        "POSTHOG_DATE_TO",
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
