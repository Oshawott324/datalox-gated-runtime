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
PROBE = ROOT / "probes" / "hubspot_crm.json"
HELPER = ROOT / "scripts" / "providers" / "hubspot-crm-sandbox.sh"
CANONICAL_API_URL = "https://api.hubapi.com"
TEST_TOKEN = "pat-test-secret-do-not-persist"
FIXTURE_IDS = {
    "call_id": "1001",
    "communication_id": "1002",
    "company_id": "1003",
    "contact_id": "1004",
    "deal_id": "1005",
    "deal_line_item_id": "1006",
    "deal_pipeline_id": "default",
    "deal_stage_id": "appointmentscheduled",
    "email_id": "1007",
    "meeting_id": "1008",
    "note_id": "1009",
    "owner_id": "1010",
    "product_id": "1011",
    "quote_id": "1012",
    "quote_line_item_id": "1013",
    "task_id": "1014",
    "ticket_id": "1015",
    "ticket_pipeline_id": "0",
    "ticket_stage_id": "1",
}


def test_probe_json_and_helper_validation_agree() -> None:
    payload = _probe_payload()
    config = load_probe_config(PROBE)

    result = _run_helper("validate")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "get_only": True,
        "kind": "hubspot_crm_probe_validation_v0",
        "request_counts": {"base": 38, "fixture": 45},
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "hubspot_crm"
    assert payload["base_url"] == config.base_url == CANONICAL_API_URL
    assert len(config.probe_requests) == config.rate_budget.max_requests == 38


def test_all_probe_sections_are_get_only_current_official_route_families() -> None:
    payload = _probe_payload()
    sections = {
        "base": payload["probe_requests"],
        "fixture": payload["fixture_expansions"]["probe_requests"],
    }

    assert {name: len(requests) for name, requests in sections.items()} == {
        "base": 38,
        "fixture": 45,
    }
    for requests in sections.values():
        assert requests
        assert {request["method"] for request in requests} == {"GET"}
        assert all(isinstance(request["query"], dict) for request in requests)

    paths = {request["path"] for requests in sections.values() for request in requests}
    required_paths = {
        "/account-info/2026-03/details",
        "/crm/owners/2026-03",
        "/crm/objects/2026-03/contacts",
        "/crm/objects/2026-03/companies",
        "/crm/objects/2026-03/deals",
        "/crm/objects/2026-03/tickets",
        "/crm/objects/2026-03/calls",
        "/crm/objects/2026-03/emails",
        "/crm/objects/2026-03/meetings",
        "/crm/objects/2026-03/notes",
        "/crm/objects/2026-03/tasks",
        "/crm/objects/2026-03/communications",
        "/crm/objects/2026-03/products",
        "/crm/objects/2026-03/line_items",
        "/crm/objects/2026-03/quotes",
        "/crm/pipelines/2026-03/deals",
        "/crm/pipelines/2026-03/tickets",
        "/crm-object-schemas/2026-03/schemas",
        "/crm/associations/2026-03/contacts/companies/labels",
        "/crm/associations/2026-03/deals/line_items/labels",
        "/crm/associations/2026-03/quotes/line_items/labels",
        "/crm/objects/2026-03/tickets/{ticket_id}/associations/communications",
    }
    assert required_paths <= paths
    assert all(path == "/account-info/2026-03/details" or "/2026-03" in path for path in paths)
    assert not any("/search" in path or "/batch/" in path for path in paths)


def test_auth_profile_is_bearer_env_only() -> None:
    payload = _probe_payload()

    assert payload["auth_profile"] == "hubspot_access_token_bearer"
    assert payload["auth_profiles"] == {
        "hubspot_access_token_bearer": {
            "inject": [
                {
                    "env": "HUBSPOT_ACCESS_TOKEN",
                    "in": "header",
                    "name": "Authorization",
                    "scheme": "Bearer",
                }
            ],
            "kind": "env_static",
        }
    }
    assert "Authorization" not in payload["static_headers"]


def test_render_base_is_concrete_mode_0600_and_secret_free(tmp_path: Path) -> None:
    out_path = tmp_path / "hubspot-base.json"

    result = _run_helper("render", "--out", str(out_path), env=_valid_env())

    assert result.returncode == 0, result.stderr
    rendered_text = out_path.read_text(encoding="utf-8")
    rendered = json.loads(rendered_text)
    receipt = json.loads(result.stdout)
    assert receipt["probe_request_count"] == 38
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 38
    assert "fixture_expansions" not in rendered
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


def test_render_seeded_fixture_resolves_all_ids_with_budget_83(tmp_path: Path) -> None:
    seed_path = _write_seed_manifest(tmp_path / "seed.json")
    out_path = tmp_path / "hubspot-fixture.json"

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
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 83
    assert set(FIXTURE_IDS) == _template_fixture_id_keys()
    assert all(value in rendered_text for value in FIXTURE_IDS.values())
    _assert_no_placeholders(rendered)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600
    _assert_secret_absent(result, rendered_text)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.hubspot.com",
        "https://example.com",
        "https://api.hubapi.com.example.com",
        "http://api.hubapi.com",
        "https://api.hubapi.com/crm",
        f"https://user:{TEST_TOKEN}@api.hubapi.com",
    ],
)
def test_arbitrary_or_insecure_hosts_are_rejected_without_secret_echo(
    tmp_path: Path, url: str
) -> None:
    env = _valid_env()
    env["HUBSPOT_API_URL"] = url

    result = _run_helper("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_structured_error(result, "unsupported_hubspot_api_url")
    _assert_secret_absent(result)


def test_missing_access_token_is_rejected_without_output(tmp_path: Path) -> None:
    out_path = tmp_path / "blocked.json"

    result = _run_helper("render", "--out", str(out_path))

    _assert_structured_error(result, "missing_env")
    assert not out_path.exists()


@pytest.mark.parametrize("manifest_case", ["missing", "malformed_json", "malformed_schema"])
def test_invalid_seed_manifest_is_rejected_without_secret_echo(
    tmp_path: Path, manifest_case: str
) -> None:
    seed_path = tmp_path / "seed.json"
    if manifest_case == "malformed_json":
        seed_path.write_text("{not-json", encoding="utf-8")
        expected_code = "invalid_json_file"
    elif manifest_case == "malformed_schema":
        seed_path.write_text(
            json.dumps(
                {
                    "base_url": CANONICAL_API_URL,
                    "ids": {"contact_id": "1"},
                    "kind": "hubspot_crm_probe_seed_v0",
                }
            ),
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


def test_helper_routes_only_read_actions_and_has_no_authoring_path() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert 'if args.command in {"auth-preflight", "probe"}:' in source
    assert "return run_datalox(args.command, args)" in source
    assert "urllib.request" not in source
    assert "urlopen" not in source
    assert not re.search(r"^(?:from|import) requests\b", source, re.MULTILINE)
    assert 'commands.add_parser("seed")' not in source
    assert not re.search(r"run_datalox\(\s*['\"](?:post|put|patch|delete|write)", source, re.I)
    assert not re.search(r"['\"](?:POST|PUT|PATCH|DELETE)['\"]", source)


def test_helper_has_valid_bash_syntax_and_is_executable() -> None:
    result = subprocess.run(
        ["bash", "-n", str(HELPER)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert os.access(HELPER, os.X_OK)


def _probe_payload() -> dict[str, Any]:
    payload = json.loads(PROBE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _template_fixture_id_keys() -> set[str]:
    fixture = _probe_payload()["fixture_expansions"]
    return set(re.findall(r"\{([a-z][a-z0-9_]*)\}", json.dumps(fixture)))


def _valid_env() -> dict[str, str]:
    return {"HUBSPOT_ACCESS_TOKEN": TEST_TOKEN}


def _write_seed_manifest(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "base_url": CANONICAL_API_URL,
                "ids": FIXTURE_IDS,
                "kind": "hubspot_crm_probe_seed_v0",
            }
        ),
        encoding="utf-8",
    )
    return path


def _assert_no_placeholders(value: Any) -> None:
    assert re.search(r"\{[a-z][a-z0-9_]*\}", json.dumps(value, sort_keys=True)) is None


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


def _run_helper(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    child_env = os.environ.copy()
    child_env.pop("HUBSPOT_API_URL", None)
    child_env.pop("HUBSPOT_ACCESS_TOKEN", None)
    child_env.update(env or {})
    return subprocess.run(
        ["bash", str(HELPER), *args],
        cwd=ROOT,
        env=child_env,
        text=True,
        capture_output=True,
        check=False,
    )
