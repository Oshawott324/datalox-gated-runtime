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
PROBE = ROOT / "probes" / "microsoft_graph.json"
HELPER = ROOT / "scripts" / "providers" / "microsoft-graph-sandbox.sh"
CANONICAL_API_URL = "https://graph.microsoft.com/v1.0"
TEST_TOKEN = "microsoft-graph-test-token-that-must-not-be-echoed"
FIXTURE_IDS = {
    "calendar_id": "calendar fixture",
    "channel_id": "19:channel@thread.tacv2",
    "channel_message_id": "1712345678901",
    "chat_id": "19:chat fixture@unq.gbl.spaces",
    "chat_message_id": "1712345678902",
    "drive_item_id": "01ABC!drive item",
    "event_id": "event fixture",
    "group_id": "group fixture",
    "mail_folder_id": "mail folder fixture",
    "message_id": "AAMk!message fixture=",
    "planner_bucket_id": "bucket fixture",
    "planner_plan_id": "plan fixture",
    "planner_task_id": "task fixture",
    "site_drive_item_id": "01SITE!drive item",
    "site_id": "tenant.sharepoint.com,site fixture,web fixture",
    "team_id": "team fixture",
    "todo_list_id": "todo list fixture",
    "todo_task_id": "todo task fixture",
    "user_id": "fixture.user@example.test",
}


def test_probe_schema_and_helper_validation_agree_on_exact_counts() -> None:
    payload = _probe_payload()
    config = load_probe_config(PROBE)

    result = _run_helper("validate")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "get_only": True,
        "kind": "microsoft_graph_probe_validation_v0",
        "request_counts": {"base": 20, "fixture": 47},
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "microsoft_graph"
    assert payload["base_url"] == config.base_url == CANONICAL_API_URL
    assert len(config.probe_requests) == config.rate_budget.max_requests == 20


def test_all_requests_are_get_only_and_cover_microsoft_365_read_families() -> None:
    payload = _probe_payload()
    sections = {
        "base": payload["probe_requests"],
        "fixture": payload["fixture_expansions"]["probe_requests"],
    }

    assert {name: len(requests) for name, requests in sections.items()} == {
        "base": 20,
        "fixture": 47,
    }
    requests = [request for section in sections.values() for request in section]
    assert {request["method"] for request in requests} == {"GET"}
    assert all(isinstance(request["query"], dict) for request in requests)
    assert all(
        request["path"].startswith(tuple(payload["safe_read_prefixes"])) for request in requests
    )
    assert all("/beta/" not in request["path"] for request in requests)

    paths = {request["path"] for request in requests}
    for family in (
        "/me/messages",
        "/me/mailFolders",
        "/me/calendar",
        "/me/events",
        "/me/drive",
        "/sites",
        "/me/joinedTeams",
        "/me/chats",
        "/teams/",
        "/chats/",
        "/users",
        "/groups",
        "/me/todo/lists",
        "/me/planner",
        "/planner/",
    ):
        assert any(path.startswith(family) for path in paths), family


def test_render_base_has_exact_budget_mode_and_no_token_or_placeholders(
    tmp_path: Path,
) -> None:
    out_path = tmp_path / "microsoft-graph-base.json"

    result = _run_helper("render", "--out", str(out_path), env=_valid_env())

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert json.loads(result.stdout)["probe_request_count"] == 20
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 20
    assert "fixture_expansions" not in rendered
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    assert TEST_TOKEN not in result.stdout
    assert TEST_TOKEN not in result.stderr
    assert TEST_TOKEN not in rendered_text


def test_render_full_seed_resolves_all_ids_with_exact_budget_and_path_encoding(
    tmp_path: Path,
) -> None:
    seed_path = _write_seed_manifest(tmp_path / "seed.json", FIXTURE_IDS)
    out_path = tmp_path / "microsoft-graph-fixture.json"

    result = _run_helper(
        "render",
        "--seed-manifest",
        str(seed_path),
        "--out",
        str(out_path),
        env=_valid_env(),
    )

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    assert json.loads(result.stdout)["probe_request_count"] == 67
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 67
    assert set(FIXTURE_IDS) == _config_seed_id_keys()
    assert "/users/fixture.user%40example.test" in rendered_text
    assert "19%3Achannel%40thread.tacv2" in rendered_text
    assert "01ABC%21drive%20item" in rendered_text
    assert TEST_TOKEN not in rendered_text
    _assert_no_placeholders(rendered)


def test_partial_seed_only_adds_requests_with_satisfied_dependencies(tmp_path: Path) -> None:
    seed_path = _write_seed_manifest(
        tmp_path / "seed.json",
        {
            "channel_id": FIXTURE_IDS["channel_id"],
            "message_id": FIXTURE_IDS["message_id"],
            "team_id": FIXTURE_IDS["team_id"],
        },
    )
    out_path = tmp_path / "microsoft-graph-partial.json"

    result = _run_helper(
        "render",
        "--seed-manifest",
        str(seed_path),
        "--out",
        str(out_path),
        env=_valid_env(),
    )

    assert result.returncode == 0, result.stderr
    rendered = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 27
    paths = {request["path"] for request in rendered["probe_requests"]}
    assert any(path.endswith("/attachments") for path in paths)
    assert any(path.endswith("/channels") for path in paths)
    assert any(path.endswith("/members") and path.startswith("/teams/") for path in paths)
    assert not any("/messages/1712345678901" in path for path in paths)


def test_auth_preflight_uses_environment_token_without_provider_request(tmp_path: Path) -> None:
    out_path = tmp_path / "microsoft-graph.json"
    render = _run_helper("render", "--out", str(out_path), env=_valid_env())
    assert render.returncode == 0, render.stderr

    result = _run_helper(
        "auth-preflight",
        "--config",
        str(out_path),
        env=_valid_env(),
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["provider_id"] == "microsoft_graph"
    assert receipt["status"] == "completed"
    assert TEST_TOKEN not in result.stdout
    assert TEST_TOKEN not in result.stderr


@pytest.mark.parametrize(
    "url",
    [
        "https://graph.microsoft.com/beta",
        "https://example.com/v1.0",
        "http://graph.microsoft.com/v1.0",
        "https://graph.microsoft.com/v1.0/",
    ],
)
def test_noncanonical_graph_urls_are_rejected_without_token_echo(
    tmp_path: Path,
    url: str,
) -> None:
    env = _valid_env()
    env["MICROSOFT_GRAPH_API_URL"] = url

    result = _run_helper("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_structured_error(result, "unsupported_microsoft_graph_api_url")
    _assert_token_absent(result)


def test_missing_token_is_rejected_before_render(tmp_path: Path) -> None:
    result = _run_helper("render", "--out", str(tmp_path / "blocked.json"))

    _assert_structured_error(result, "missing_env")
    assert not (tmp_path / "blocked.json").exists()


@pytest.mark.parametrize("manifest_case", ["missing", "malformed_json", "unknown_id"])
def test_invalid_seed_manifest_is_structured_and_does_not_persist_token(
    tmp_path: Path,
    manifest_case: str,
) -> None:
    seed_path = tmp_path / "seed.json"
    if manifest_case == "malformed_json":
        seed_path.write_text("{not-json", encoding="utf-8")
        expected_code = "invalid_json_file"
    elif manifest_case == "unknown_id":
        _write_seed_manifest(seed_path, {"invented_id": "x"})
        expected_code = "invalid_seed_manifest"
    else:
        expected_code = "invalid_json_file"

    result = _run_helper(
        "render",
        "--seed-manifest",
        str(seed_path),
        "--out",
        str(tmp_path / "blocked.json"),
        env=_valid_env(),
    )

    _assert_structured_error(result, expected_code)
    _assert_token_absent(result)


def test_helper_exposes_only_read_probe_lifecycle() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert 'commands.add_parser("validate")' in source
    assert 'commands.add_parser("render")' in source
    assert 'commands.add_parser("auth-preflight")' in source
    assert 'commands.add_parser("probe")' in source
    assert 'commands.add_parser("author")' not in source
    assert not re.search(r"['\"](?:POST|PUT|PATCH|DELETE)['\"]", source)
    assert "urlopen" not in source
    assert not re.search(r"^\s*(?:import|from)\s+requests\b", source, re.MULTILINE)


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
    render_keys = {"calendar_end", "calendar_start", "site_search"}
    found = set(re.findall(r"\{([a-z][a-z0-9_]*)\}", json.dumps(_probe_payload())))
    return found - render_keys


def _valid_env() -> dict[str, str]:
    return {
        "MICROSOFT_GRAPH_ACCESS_TOKEN": TEST_TOKEN,
        "MICROSOFT_GRAPH_CALENDAR_START": "2026-07-01T00:00:00Z",
        "MICROSOFT_GRAPH_CALENDAR_END": "2026-08-01T00:00:00Z",
        "MICROSOFT_GRAPH_SITE_SEARCH": "datalox",
    }


def _write_seed_manifest(path: Path, ids: dict[str, str]) -> Path:
    path.write_text(
        json.dumps({"kind": "microsoft_graph_probe_seed_v0", "ids": ids}),
        encoding="utf-8",
    )
    return path


def _assert_no_placeholders(value: Any) -> None:
    assert re.search(r"\{[a-z][a-z0-9_]*\}", json.dumps(value, sort_keys=True)) is None


def _assert_token_absent(result: subprocess.CompletedProcess[str]) -> None:
    assert TEST_TOKEN not in result.stdout
    assert TEST_TOKEN not in result.stderr


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
        "MICROSOFT_GRAPH_ACCESS_TOKEN",
        "MICROSOFT_GRAPH_API_URL",
        "MICROSOFT_GRAPH_CALENDAR_END",
        "MICROSOFT_GRAPH_CALENDAR_START",
        "MICROSOFT_GRAPH_SITE_SEARCH",
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
