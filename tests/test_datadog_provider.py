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
PROBE = ROOT / "probes" / "datadog.json"
HELPER = ROOT / "scripts" / "providers" / "datadog-sandbox.sh"
TEMPLATE_API_URL = "https://api.{dd_site}"
TEST_API_KEY = "datadog-api-key-that-must-not-be-echoed"
TEST_APP_KEY = "datadog-app-key-that-must-not-be-echoed"
SITE_URLS = {
    "datadoghq.com": "https://api.datadoghq.com",
    "us3.datadoghq.com": "https://api.us3.datadoghq.com",
    "us5.datadoghq.com": "https://api.us5.datadoghq.com",
    "datadoghq.eu": "https://api.datadoghq.eu",
    "ap1.datadoghq.com": "https://api.ap1.datadoghq.com",
    "ap2.datadoghq.com": "https://api.ap2.datadoghq.com",
    "uk1.datadoghq.com": "https://api.uk1.datadoghq.com",
    "ddog-gov.com": "https://api.ddog-gov.com",
    "us2.ddog-gov.com": "https://api.us2.ddog-gov.com",
}
FIXTURE_IDS = {
    "dashboard_id": "dashboard-101",
    "dashboard_list_id": "dashboard-list-102",
    "downtime_id": "downtime-103",
    "event_id": "event-104",
    "incident_field_id": "incident-field-105",
    "incident_id": "incident-106",
    "incident_notification_rule_id": "incident-rule-107",
    "incident_notification_template_id": "incident-template-108",
    "incident_postmortem_template_id": "postmortem-template-109",
    "incident_service_id": "incident-service-110",
    "incident_team_id": "incident-team-111",
    "incident_todo_id": "incident-todo-112",
    "incident_type_id": "incident-type-113",
    "log_index_name": "main",
    "log_metric_id": "logs.metric.fixture",
    "log_pipeline_id": "pipeline-116",
    "metric_name": "system.cpu.user",
    "monitor_id": "118",
    "monitor_policy_id": "monitor-policy-119",
    "monitor_template_id": "monitor-template-120",
    "notebook_id": "121",
    "on_call_channel_id": "on-call-channel-122",
    "on_call_escalation_policy_id": "on-call-policy-123",
    "on_call_rule_id": "on-call-rule-124",
    "on_call_schedule_id": "on-call-schedule-125",
    "on_call_user_id": "on-call-user-126",
    "role_id": "role-127",
    "service_name": "datalox-probe-service",
    "team_hierarchy_link_id": "team-link-129",
    "team_id": "team-130",
    "user_id": "user-131",
}


def test_probe_schema_and_helper_validation_agree_on_counts_and_auth() -> None:
    payload = _probe_payload()
    config = load_probe_config(PROBE)

    result = _run_helper("validate")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "get_only": True,
        "kind": "datadog_probe_validation_v0",
        "request_counts": {"base": 42, "fixture": 57},
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "datadog"
    assert payload["base_url"] == config.base_url == TEMPLATE_API_URL
    assert config.access_class == "approval_gated"
    assert len(config.probe_requests) == config.rate_budget.max_requests == 42
    assert payload["auth_profiles"]["datadog_keys"]["inject"] == [
        {"env": "DD_API_KEY", "in": "header", "name": "DD-API-KEY", "scheme": ""},
        {
            "env": "DD_APPLICATION_KEY",
            "in": "header",
            "name": "DD-APPLICATION-KEY",
            "scheme": "",
        },
    ]


def test_all_template_requests_are_get_only_and_cover_requested_families() -> None:
    payload = _probe_payload()
    requests = payload["probe_requests"] + payload["fixture_expansions"]["probe_requests"]

    assert {request["method"] for request in requests} == {"GET"}
    assert all(isinstance(request["query"], dict) for request in requests)
    paths = {request["path"] for request in requests}
    for family in (
        "/api/v1/monitor",
        "/api/v2/events",
        "/api/v2/incidents",
        "/api/v2/services",
        "/api/v2/teams",
        "/api/v2/downtime",
        "/api/v1/dashboard",
        "/api/v1/notebooks",
        "/api/v2/logs/events",
        "/api/v2/metrics",
        "/api/v1/query",
        "/api/v2/services/definitions",
        "/api/v2/catalog",
        "/api/v2/users",
        "/api/v2/roles",
        "/api/v2/team",
        "/api/v2/on-call",
    ):
        assert any(path.startswith(family) for path in paths), family


def test_render_base_is_concrete_exact_budget_mode_0600_and_secret_free(tmp_path: Path) -> None:
    out_path = tmp_path / "datadog-base.json"

    result = _run_helper("render", "--out", str(out_path), env=_valid_env())

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert json.loads(result.stdout)["probe_request_count"] == 42
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 42
    assert rendered["base_url"] == SITE_URLS["datadoghq.com"]
    assert "fixture_expansions" not in rendered
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secrets_absent(result, rendered_text)


def test_auth_preflight_checks_both_broker_requirements_without_secret_echo() -> None:
    result = _run_helper("auth-preflight", env=_valid_env())

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["provider_id"] == "datadog"
    assert receipt["auth_schema"] == "auth_broker_v0"
    assert receipt["auth_preflight"]["status"] == "passed"
    assert {requirement["env"] for requirement in receipt["auth_preflight"]["requirements"]} == {
        "DD_API_KEY",
        "DD_APPLICATION_KEY",
    }
    _assert_secrets_absent(result)


def test_render_full_fixture_uses_all_seed_ids_and_exact_budget(tmp_path: Path) -> None:
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps({"kind": "datadog_probe_seed_v0", "ids": FIXTURE_IDS}),
        encoding="utf-8",
    )
    out_path = tmp_path / "datadog-fixture.json"

    result = _run_helper(
        "render", "--out", str(out_path), "--seed-manifest", str(seed_path), env=_valid_env()
    )

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert json.loads(result.stdout)["probe_request_count"] == 99
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 99
    assert set(FIXTURE_IDS) == _fixture_placeholders()
    assert all(value in rendered_text for value in FIXTURE_IDS.values())
    _assert_no_placeholders(rendered)
    _assert_secrets_absent(result, rendered_text)


@pytest.mark.parametrize(("site", "api_url"), sorted(SITE_URLS.items()))
def test_official_sites_render_to_their_exact_api_hosts(
    tmp_path: Path, site: str, api_url: str
) -> None:
    env = _valid_env()
    env["DD_SITE"] = site
    out_path = tmp_path / f"{site}.json"

    result = _run_helper("render", "--out", str(out_path), env=env)

    assert result.returncode == 0, result.stderr
    assert json.loads(out_path.read_text(encoding="utf-8"))["base_url"] == api_url


@pytest.mark.parametrize("site", ["example.com", "api.datadoghq.com", "https://datadoghq.com", ""])
def test_unsupported_site_is_structured_and_secret_free(tmp_path: Path, site: str) -> None:
    env = _valid_env()
    env["DD_SITE"] = site

    result = _run_helper("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_structured_error(result, "unsupported_dd_site")
    _assert_secrets_absent(result)


@pytest.mark.parametrize("missing", ["DD_API_KEY", "DD_APPLICATION_KEY"])
def test_both_keys_are_required_without_secret_echo(tmp_path: Path, missing: str) -> None:
    env = _valid_env()
    env.pop(missing)

    result = _run_helper("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_structured_error(result, "missing_env")
    _assert_secrets_absent(result)


def test_unknown_seed_id_is_rejected_without_secret_echo(tmp_path: Path) -> None:
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps({"kind": "datadog_probe_seed_v0", "ids": {"guessed_id": "x"}}),
        encoding="utf-8",
    )

    result = _run_helper(
        "render",
        "--out",
        str(tmp_path / "blocked.json"),
        "--seed-manifest",
        str(seed_path),
        env=_valid_env(),
    )

    _assert_structured_error(result, "invalid_seed_manifest")
    _assert_secrets_absent(result)


def test_helper_routes_only_required_read_actions_through_datalox() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert 'if args.command in {"auth-preflight", "probe"}:' in source
    assert "return run_datalox(args.command, args)" in source
    assert '"datalox_gated_runtime.cli"' in source
    assert not re.search(r"['\"](?:POST|PUT|PATCH|DELETE)['\"]", source)
    assert "import httpx" not in source
    assert "import requests" not in source
    assert "from urllib" not in source


def test_helper_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(HELPER)], cwd=ROOT, text=True, capture_output=True, check=False
    )

    assert result.returncode == 0, result.stderr


def _probe_payload() -> dict[str, Any]:
    payload = json.loads(PROBE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _fixture_placeholders() -> set[str]:
    fixture = _probe_payload()["fixture_expansions"]["probe_requests"]
    return set(re.findall(r"\{([a-z][a-z0-9_]*)\}", json.dumps(fixture)))


def _valid_env() -> dict[str, str]:
    return {"DD_API_KEY": TEST_API_KEY, "DD_APPLICATION_KEY": TEST_APP_KEY}


def _assert_no_placeholders(value: Any) -> None:
    assert re.search(r"\{[a-z][a-z0-9_]*\}", json.dumps(value, sort_keys=True)) is None


def _assert_secrets_absent(
    result: subprocess.CompletedProcess[str], rendered_text: str = ""
) -> None:
    for secret in (TEST_API_KEY, TEST_APP_KEY):
        assert secret not in result.stdout
        assert secret not in result.stderr
        assert secret not in rendered_text


def _assert_structured_error(result: subprocess.CompletedProcess[str], expected_code: str) -> None:
    assert result.returncode == 1
    payload = json.loads(result.stderr)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == expected_code


def _run_helper(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    child_env = os.environ.copy()
    for name in ("DD_API_KEY", "DD_APPLICATION_KEY", "DD_SITE", "DATADOG_METRIC_QUERY"):
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
