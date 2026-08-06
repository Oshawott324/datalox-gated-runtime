import json
import os
from pathlib import Path

from datalox_gated_runtime.provider_probe import load_probe_config


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_REQUEST_COUNTS = {
    "easypost": 13,
    "freshdesk": 24,
    "pagerduty": 37,
}


def test_authenticated_probe_configs_are_broker_backed_get_only() -> None:
    for provider_id, expected_count in EXPECTED_REQUEST_COUNTS.items():
        config = load_probe_config(ROOT / "probes" / f"{provider_id}.json")

        assert config.provider_id == provider_id
        assert config.auth_schema == "auth_broker_v0"
        assert config.auth_profile is not None
        assert len(config.probe_requests) == expected_count
        assert config.rate_budget.max_requests == expected_count
        assert {request.method for request in config.probe_requests} == {"GET"}


def test_authenticated_probe_helpers_are_executable() -> None:
    for provider_id in EXPECTED_REQUEST_COUNTS:
        helper = ROOT / "scripts" / "providers" / f"{provider_id}-sandbox.sh"

        assert helper.is_file()
        assert os.access(helper, os.X_OK)


def test_freshdesk_seed_expansions_are_explicit() -> None:
    payload = json.loads((ROOT / "probes" / "freshdesk.json").read_text(encoding="utf-8"))
    expansions = payload["fixture_expansions"]["probe_requests"]

    assert len(expansions) == 23
    assert {request["method"] for request in expansions} == {"GET"}


def test_easypost_artifacts_do_not_contain_a_test_key() -> None:
    paths = [
        ROOT / "probes" / "easypost.json",
        ROOT / "scripts" / "providers" / "easypost-sandbox.sh",
        ROOT / "docs" / "reports" / "2026-07-10-easypost-auth-probe-prep.md",
        *sorted((ROOT / "envs" / "probed_easypost_v0").glob("*")),
    ]

    for path in paths:
        if path.is_file():
            assert "EZTK" not in path.read_text(encoding="utf-8")
