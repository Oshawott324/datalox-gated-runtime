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
PROBE = ROOT / "probes" / "sentry.json"
HELPER = ROOT / "scripts" / "providers" / "sentry-sandbox.sh"
CANONICAL_API_URL = "https://sentry.io/api/0"
TEST_TOKEN = "sentry-test-token-that-must-not-be-echoed"
ORG_SLUG = "fixture-org"
PROJECT_SLUG = "fixture-project"
FIXTURE_IDS = {
    "team_slug": "fixture-team",
    "member_id": "member-101",
    "issue_id": "issue-202",
    "tag_key": "environment",
    "event_id": "event-303",
    "release_version": "release-404",
    "repo_id": "repo-505",
    "detector_id": "detector-606",
    "monitor_id": "monitor-707",
    "hook_id": "hook-808",
}


def test_probe_schema_and_helper_validation_agree_on_exact_counts() -> None:
    payload = _probe_payload()
    config = load_probe_config(PROBE)

    result = _run_helper("validate")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "get_only": True,
        "kind": "sentry_probe_validation_v0",
        "request_counts": {"base": 22, "fixture": 17},
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "sentry"
    assert payload["base_url"] == config.base_url == CANONICAL_API_URL
    assert len(config.probe_requests) == config.rate_budget.max_requests == 22


def test_all_requests_are_get_only_and_official_core_families_are_present() -> None:
    payload = _probe_payload()
    sections = {
        "base": payload["probe_requests"],
        "fixture": payload["fixture_expansions"]["probe_requests"],
    }

    assert {name: len(requests) for name, requests in sections.items()} == {
        "base": 22,
        "fixture": 17,
    }
    requests = [request for section in sections.values() for request in section]
    assert {request["method"] for request in requests} == {"GET"}
    assert all(isinstance(request["query"], dict) for request in requests)

    paths = {request["path"] for request in requests}
    assert all(path.startswith(("/organizations/", "/projects/", "/teams/")) for path in paths)
    for official_family in (
        "/organizations/",
        "/projects/{org_slug}/{project_slug}/",
        "/teams/{org_slug}/{team_slug}/",
        "/members/",
        "/issues/",
        "/events/",
        "/releases/",
        "/repos/",
        "/detectors/",
        "/monitors/",
        "/hooks/",
    ):
        assert any(official_family in path for path in paths), official_family


def test_render_base_has_exact_budget_mode_and_no_secrets_or_placeholders(
    tmp_path: Path,
) -> None:
    out_path = tmp_path / "sentry-base.json"

    result = _run_helper("render", "--out", str(out_path), env=_valid_env())

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    receipt = json.loads(result.stdout)
    assert receipt["probe_request_count"] == 22
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 22
    assert "fixture_expansions" not in rendered
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


def test_render_fixture_uses_exact_manifest_ids_with_budget_39_and_mode_0600(
    tmp_path: Path,
) -> None:
    seed_path = _write_seed_manifest(tmp_path / "seed.json")
    out_path = tmp_path / "sentry-fixture.json"

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
    assert receipt["probe_request_count"] == 39
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 39
    assert "fixture_expansions" not in rendered
    assert set(FIXTURE_IDS) == {
        "team_slug",
        "member_id",
        "issue_id",
        "tag_key",
        "event_id",
        "release_version",
        "repo_id",
        "detector_id",
        "monitor_id",
        "hook_id",
    }
    assert all(value in rendered_text for value in FIXTURE_IDS.values())
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


@pytest.mark.parametrize(
    ("env", "expected_code"),
    [
        ({"SENTRY_API_URL": ""}, "unsupported_sentry_api_url"),
        (
            {"SENTRY_API_URL": f"https://user:{TEST_TOKEN}@sentry.io/api/0"},
            "unsupported_sentry_api_url",
        ),
        ({"SENTRY_API_URL": "https://sentry.io:not-a-port/api/0"}, "invalid_sentry_api_url"),
        ({"SENTRY_AUTH_TOKEN": None}, "missing_env"),
        ({"SENTRY_ORG_SLUG": None}, "missing_env"),
        ({"SENTRY_PROJECT_SLUG": None}, "missing_env"),
    ],
)
def test_api_url_and_required_identity_failures_are_structured_without_token_echo(
    tmp_path: Path,
    env: dict[str, str | None],
    expected_code: str,
) -> None:
    out_path = tmp_path / "blocked.json"
    command_env = _valid_env()
    for name, value in env.items():
        if value is None:
            command_env.pop(name, None)
        else:
            command_env[name] = value

    result = _run_helper("render", "--out", str(out_path), env=command_env)

    _assert_structured_error(result, expected_code)
    _assert_secret_absent(result)
    assert not out_path.exists()


def test_partial_seed_manifest_renders_only_resolvable_requests_with_exact_budget(
    tmp_path: Path,
) -> None:
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps({"kind": "sentry_probe_seed_v0", "ids": {"issue_id": "only-one"}}),
        encoding="utf-8",
    )
    out_path = tmp_path / "sentry-partial-fixture.json"

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
    assert receipt["probe_request_count"] == 25
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 25
    assert "only-one" in rendered_text
    _assert_no_placeholders(rendered)
    _assert_secret_absent(result, rendered_text)


@pytest.mark.parametrize("manifest_case", ["missing", "malformed_json", "unknown_seed_id"])
def test_invalid_manifest_is_structured_without_token_echo(
    tmp_path: Path,
    manifest_case: str,
) -> None:
    seed_path = tmp_path / "seed.json"
    if manifest_case == "malformed_json":
        seed_path.write_text("{not-json", encoding="utf-8")
        expected_code = "invalid_json_file"
    elif manifest_case == "unknown_seed_id":
        seed_path.write_text(
            json.dumps({"kind": "sentry_probe_seed_v0", "ids": {"unknown_id": "x"}}),
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


@pytest.mark.parametrize("host", ["sentry.io", "us.sentry.io", "us2.sentry.io", "de.sentry.io"])
def test_official_region_hosts_are_accepted(tmp_path: Path, host: str) -> None:
    out_path = tmp_path / f"{host}.json"
    env = _valid_env()
    env["SENTRY_API_URL"] = f"https://{host}/api/0"

    result = _run_helper("render", "--out", str(out_path), env=env)

    assert result.returncode == 0, result.stderr
    assert json.loads(out_path.read_text(encoding="utf-8"))["base_url"] == env["SENTRY_API_URL"]


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/api/0",
        "https://sentry.io.example.com/api/0",
        "http://sentry.io/api/0",
    ],
)
def test_arbitrary_or_insecure_hosts_are_rejected(tmp_path: Path, url: str) -> None:
    env = _valid_env()
    env["SENTRY_API_URL"] = url

    result = _run_helper("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_structured_error(result, "unsupported_sentry_api_url")
    _assert_secret_absent(result)


def test_helper_only_routes_read_actions_through_datalox() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert 'if args.command in {"auth-preflight", "probe"}:' in source
    assert "return run_datalox(args.command, args)" in source
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


def _valid_env() -> dict[str, str]:
    return {
        "SENTRY_AUTH_TOKEN": TEST_TOKEN,
        "SENTRY_ORG_SLUG": ORG_SLUG,
        "SENTRY_PROJECT_SLUG": PROJECT_SLUG,
    }


def _write_seed_manifest(path: Path) -> Path:
    path.write_text(
        json.dumps({"kind": "sentry_probe_seed_v0", "ids": FIXTURE_IDS}),
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
        "SENTRY_API_URL",
        "SENTRY_AUTH_TOKEN",
        "SENTRY_ORG_SLUG",
        "SENTRY_PROJECT_SLUG",
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
