import json

import pytest

from datalox_gated_runtime.auth import (
    AuthBrokerError,
    apply_auth_profile,
    parse_auth_broker_config,
    preflight_auth,
)


def test_applies_header_and_query_auth_without_mutating_inputs() -> None:
    config = parse_auth_broker_config(
        {
            "auth_profiles": {
                "provider_auth": {
                    "kind": "env_static",
                    "inject": [
                        {
                            "in": "header",
                            "name": "Authorization",
                            "env": "API_TOKEN",
                            "scheme": "Bearer",
                        },
                        {
                            "in": "header",
                            "name": "X-API-Key",
                            "env": "API_KEY",
                            "scheme": "",
                        },
                        {"in": "query", "name": "api_key", "env": "QUERY_KEY"},
                    ],
                }
            }
        }
    )
    headers = {"accept": "application/json"}
    query = {"limit": "1", "filter": ["active", "pending"]}

    applied_headers, applied_query = apply_auth_profile(
        config.require_profile("provider_auth"),
        headers=headers,
        query=query,
        environ={
            "API_TOKEN": "token-secret",
            "API_KEY": "key-secret",
            "QUERY_KEY": "query-secret",
        },
    )

    assert applied_headers == {
        "accept": "application/json",
        "Authorization": "Bearer token-secret",
        "X-API-Key": "key-secret",
    }
    assert applied_query == {
        "limit": "1",
        "filter": ("active", "pending"),
        "api_key": "query-secret",
    }
    assert headers == {"accept": "application/json"}
    assert query == {"limit": "1", "filter": ["active", "pending"]}


def test_rejects_duplicate_header_targets_case_insensitively() -> None:
    with pytest.raises(AuthBrokerError) as exc_info:
        parse_auth_broker_config(
            {
                "auth_profiles": {
                    "dupe_headers": {
                        "kind": "env_static",
                        "inject": [
                            {"in": "header", "name": "Authorization", "env": "TOKEN_A"},
                            {"in": "header", "name": "authorization", "env": "TOKEN_B"},
                        ],
                    }
                }
            }
        )

    assert exc_info.value.code == "invalid_auth_profile"
    assert "duplicate header target" in exc_info.value.message


def test_rejects_duplicate_query_targets_exactly() -> None:
    with pytest.raises(AuthBrokerError) as exc_info:
        parse_auth_broker_config(
            {
                "auth_profiles": {
                    "dupe_query": {
                        "kind": "env_static",
                        "inject": [
                            {"in": "query", "name": "api_key", "env": "TOKEN_A"},
                            {"in": "query", "name": "api_key", "env": "TOKEN_B"},
                        ],
                    }
                }
            }
        )

    assert exc_info.value.code == "invalid_auth_profile"
    assert "duplicate query target" in exc_info.value.message


def test_preflight_reports_missing_env_without_secret_values() -> None:
    config = parse_auth_broker_config(
        {
            "auth_profiles": {
                "provider_auth": {
                    "kind": "env_static",
                    "inject": [
                        {"in": "header", "name": "Authorization", "env": "API_TOKEN"},
                        {"in": "query", "name": "api_key", "env": "QUERY_KEY"},
                    ],
                }
            }
        }
    )

    proof = preflight_auth(
        config,
        ["provider_auth"],
        environ={"API_TOKEN": "token-secret"},
    )

    payload = proof.to_dict()
    assert payload["kind"] == "auth_preflight_v0"
    assert payload["profile_ids"] == ["provider_auth"]
    assert payload["status"] == "failed"
    assert payload["requirements"] == [
        {
            "profile_id": "provider_auth",
            "target": {"in": "header", "name": "Authorization"},
            "env": "API_TOKEN",
            "present": True,
        },
        {
            "profile_id": "provider_auth",
            "target": {"in": "query", "name": "api_key"},
            "env": "QUERY_KEY",
            "present": False,
        },
    ]
    assert "token-secret" not in json.dumps(payload)


def test_apply_auth_profile_rejects_query_collision_without_leaking_values() -> None:
    config = parse_auth_broker_config(
        {
            "auth_profiles": {
                "provider_auth": {
                    "kind": "env_static",
                    "inject": [{"in": "query", "name": "api_key", "env": "QUERY_KEY"}],
                }
            }
        }
    )

    with pytest.raises(AuthBrokerError) as exc_info:
        apply_auth_profile(
            config.require_profile("provider_auth"),
            query={"api_key": ["agent-secret", "second-agent-secret"]},
            environ={"QUERY_KEY": "query-secret"},
        )

    assert exc_info.value.code == "auth_query_collision"
    assert "api_key" in exc_info.value.message
    assert "agent-secret" not in str(exc_info.value)
    assert "second-agent-secret" not in str(exc_info.value)
    assert "query-secret" not in str(exc_info.value)
